"""The CLI adapter — the only transport binding for the wave-1 ``--alert`` path.

``run.py`` is an adapter, never the loop: it parses argv, loads ``.env``, builds
the leaf dependencies from the env contract (``OpenAICompatibleLLM`` over
``LLM_API_KEY`` / ``LLM_BASE_URL`` / ``LLM_MODEL``, the Fixture World source, the
interactive ``CLIGate``, and — wave 2 — a ``JsonlJournal`` writing
``runs/<run_id>/journal.jsonl``), reads the Alert JSON, calls the
transport-agnostic ``triage(alert, deps, run_id=run_id)``, prints a readable
Verdict summary, and persists the versioned run record alongside the journal at
``runs/<run_id>/result.json`` (gitignored). The adapter mints ``run_id`` once and
passes the *same* id to both the journal directory and ``triage`` so the journal
and the run record share one Run directory. Nothing in ``src/triage`` imports this
file (triage-conventions §Module map).

Wave 2 adds ``--resume <run_id> [--approve|--deny]`` (US-0002). ``triage`` never
crashes, so once a Run starts a Verdict always ships and the exit code is ``0``. A
configuration fault *before* the Run (e.g. a missing ``LLM_API_KEY`` when the LLM
transport is built) surfaces as a ``TriageError``; the adapter catches it, prints a
clean one-line message to stderr, and exits non-zero — the traceback path is
reserved for genuine bugs (non-``TriageError``), which stay loud.

**Resume artifact (wave 2).** The journal records only ``alert_id``, not the full
Alert, so the interrupted-investigation resume (which re-renders the Alert into the
reasoner prompt) needs it back. The Alert is persisted as a sibling artifact,
``runs/<run_id>/alert.json``, **at run start** (before ``triage``) — not at the end
like ``result.json``, because the resume scenario is a process *killed mid-run*
where ``result.json`` never landed. ``--resume`` reopens the journal (continuing
``seq``, truncating any torn line), rebuilds state, and dispatches on the journal
tail: no ``run_terminated`` -> continue the interrupted investigation (needs the
Alert); ``awaiting_approval`` -> ``--approve|--deny`` completes the gate (pure
journal, no Alert needed); any other terminal state, or ``--approve|--deny`` on a
non-pending Run -> a clean ``TriageError`` (no mutation). ``--watch`` is a later
adapter.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from triage.core import (
    TriageDeps,
    resume_approve,
    resume_deny,
    resume_investigation,
    summarize,
    triage,
)
from triage.errors import TriageError
from triage.gate import CLIGate, DeferredGate, RiskPolicy
from triage.journal import Journal, JsonlJournal, rebuild
from triage.llm import OpenAICompatibleLLM
from triage.memory import MemoryStore, PostureSynthesizer
from triage.memory.posture import synthesize_posture_if_due
from triage.models import Alert, RunResult
from triage.tools import FixtureDataSource, ToolRegistry

_RUNS_DIR = Path(__file__).resolve().parent / "runs"
_RESUME_BY = "cli-resume"


class _VerboseJournal:
    """A journal decorator: forwards every event, narrates the run to stderr.

    A CLI concern only — core stays silent (ADR-0003: the journal is the single
    instrumentation; this wrapper *reads* the same event stream the journal
    persists, it never adds events of its own).  stderr keeps stdout clean for
    the final summary, so piping stdout still yields just the verdict.
    """

    def __init__(self, inner: JsonlJournal) -> None:
        """Wrap ``inner``; all events are forwarded to it unchanged."""
        self._inner = inner

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        """Forward to the real journal, then narrate the interesting events."""
        self._inner.emit(event, payload, agent=agent)
        line = self._narrate(event, payload, agent)
        if line is not None:
            print(line, file=sys.stderr)  # noqa: T201 — CLI verbose narration: stderr is the point.

    @staticmethod
    def _narrate(event: str, payload: Mapping[str, Any], agent: str) -> str | None:
        """Render one journal event as a human line, or ``None`` to stay quiet."""
        renderer = _NARRATORS.get(event)
        if renderer is None:
            return None
        tag = "" if agent == "triage" else f"[{agent}] "
        return renderer(tag, payload)


def _narrate_plan(tag: str, payload: Mapping[str, Any]) -> str:
    steps = payload.get("steps") or []
    lines = [f"{tag}PLAN     {len(steps)} step(s)"]
    lines.extend(
        f"{tag}         - {s.get('tool')}({json.dumps(s.get('args', {}))})"
        for s in steps
        if isinstance(s, Mapping)
    )
    return "\n".join(lines)


def _narrate_revise(tag: str, payload: Mapping[str, Any]) -> str:
    steps = payload.get("steps") or []
    return f"{tag}REVISE   {len(steps)} replacement step(s): {json.dumps(steps)}"


def _narrate_tool_called(tag: str, payload: Mapping[str, Any]) -> str:
    return f"{tag}TOOL     {payload.get('tool')}({json.dumps(payload.get('args', {}))})"


_DATA_PREVIEW_CHARS = 200


def _narrate_tool_result(tag: str, payload: Mapping[str, Any]) -> str:
    err = payload.get("error")
    line = f"{tag}         -> ok={payload.get('ok')}" + (f" error={err}" if err else "")
    data = payload.get("data")
    if data:
        preview = json.dumps(data)
        if len(preview) > _DATA_PREVIEW_CHARS:
            preview = preview[:_DATA_PREVIEW_CHARS] + "…"
        line += f" {preview}"
    return line


def _narrate_llm(tag: str, payload: Mapping[str, Any]) -> str:
    return (
        f"{tag}LLM      {payload.get('purpose')} "
        f"({payload.get('tokens')} tok, {payload.get('latency_ms')} ms)"
    )


def _narrate_verdict(tag: str, payload: Mapping[str, Any]) -> str:
    verdict = payload.get("verdict")
    if isinstance(verdict, Mapping):
        n_findings = len(verdict.get("findings") or [])
        return (
            f"{tag}VERDICT  severity={verdict.get('severity')} "
            f"confidence={verdict.get('confidence')} findings={n_findings}"
        )
    return f"{tag}VERDICT  shipped"


def _narrate_verification(tag: str, payload: Mapping[str, Any]) -> str:
    line = f"{tag}VERIFY   {payload.get('action')}"
    if payload.get("failed"):
        line += f" failed={payload['failed']}"
    if payload.get("uncovered_entities"):
        line += f" uncovered={payload['uncovered_entities']}"
    return line


def _narrate_gate_requested(tag: str, payload: Mapping[str, Any]) -> str:
    actions = payload.get("actions") or []
    return f"{tag}GATE?    {len(actions)} high-risk action(s) pending approval"


_NARRATORS: dict[str, Any] = {
    "plan_created": _narrate_plan,
    "plan_revised": _narrate_revise,
    "tool_called": _narrate_tool_called,
    "tool_result": _narrate_tool_result,
    "llm_call": _narrate_llm,
    "verdict": _narrate_verdict,
    "verdict_verification": _narrate_verification,
    "gate_requested": _narrate_gate_requested,
    "gate_decision": lambda tag, p: f"{tag}GATE     {p.get('decision')}",
    "action_executed": lambda tag, p: f"{tag}ACTION   {p.get('action')} executed",
    "run_terminated": lambda tag, p: f"{tag}END      {p.get('reason')}",
}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse the CLI arguments — ``--alert``, ``--resume``, or ``--synthesize-posture``.

    ``--approve`` / ``--deny`` are mutually exclusive and only meaningful with
    ``--resume`` (a pending Run); argparse enforces the alert/resume/synthesize-posture
    choice and the approve/deny exclusivity so the adapter never reaches an ambiguous
    combination.

    ``--synthesize-posture``: regenerate the L3 posture brief immediately, regardless
    of the configured cadence (including when ``MEMORY_SYNTHESIZE_EVERY_N_RUNS=0``).
    This satisfies US-0004 AC "on-demand CLI trigger".
    """
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Triage one security alert JSON end-to-end, or resume a prior run.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--alert", type=Path, help="Path to the alert JSON file to investigate.")
    mode.add_argument("--resume", metavar="RUN_ID", help="Resume a prior run by its run id.")
    mode.add_argument(
        "--synthesize-posture",
        action="store_true",
        default=False,
        help=(
            "Regenerate the L3 org-level threat posture brief immediately, "
            "regardless of the configured cadence (including cadence=0)."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Narrate the run live to stderr (plan, tool calls, reasoning, verdict, gate).",
    )
    decision = parser.add_mutually_exclusive_group()
    decision.add_argument(
        "--approve",
        action="store_true",
        help="With --resume: approve the pending high-risk action batch.",
    )
    decision.add_argument(
        "--deny",
        action="store_true",
        help="With --resume: deny the pending high-risk action batch.",
    )
    return parser.parse_args(argv)


def _load_alert(path: Path) -> Alert:
    """Read and validate the Alert JSON at ``path`` (strict envelope)."""
    return Alert.model_validate_json(path.read_text(encoding="utf-8"))


def _persist_alert(alert: Alert, run_dir: Path) -> None:
    """Persist the Alert as ``<run_dir>/alert.json`` so ``--resume`` can re-read it.

    Written at run start (the run dir already exists — the journal created it), so
    an investigation killed mid-run still has its Alert to resume from.
    """
    (run_dir / "alert.json").write_text(alert.model_dump_json(indent=2), encoding="utf-8")


def _persist(result: RunResult, runs_dir: Path) -> Path:
    """Write the versioned run record to ``runs/<run_id>/result.json``."""
    run_dir = runs_dir / result.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    record_path = run_dir / "result.json"
    record_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return record_path


def _deps(llm: OpenAICompatibleLLM, journal: Journal, *, interactive: bool) -> TriageDeps:
    """Assemble the leaf dependency bundle from an already-built LLM + journal.

    The fresh ``--alert`` path uses the interactive ``CLIGate`` (the operator answers
    at the terminal); a resumed Run that may re-park (e.g. continuing an interrupted
    investigation that reaches a high-risk verdict) uses the ``DeferredGate`` so it
    exits ``awaiting_approval`` again rather than blocking on stdin in a headless
    resume.

    The Memory Store is env-driven (``MEMORY_DIR``, default ``.memory/``) and wired on
    BOTH paths: a fresh ``--alert`` Run recalls + persists, and a resumed interrupted
    investigation persists its concluded Verdict (the ``--approve|--deny`` decision
    paths never reach the persist tail, so a parked Run is never re-persisted).
    """
    gate = CLIGate(journal) if interactive else DeferredGate(journal)
    return TriageDeps(
        llm=llm,
        journal=journal,
        registry=ToolRegistry(),
        source=FixtureDataSource(),
        gate=gate,
        policy=RiskPolicy(),
        memory=MemoryStore(),
    )


def _run_fresh(alert_path: Path, runs_dir: Path, *, verbose: bool = False) -> RunResult:
    """Mint a Run, persist the Alert, and triage it end-to-end (the ``--alert`` path).

    The LLM is built FIRST: an unset ``LLM_API_KEY`` raises ``ConfigError`` here,
    before the journal creates the run directory — so a pre-Run config fault leaves
    no stray ``runs/<run_id>/`` behind.
    """
    alert = _load_alert(alert_path)
    llm = OpenAICompatibleLLM()
    run_id = str(uuid.uuid4())
    run_dir = runs_dir / run_id
    journal: Journal = JsonlJournal(run_dir)
    if verbose:
        journal = _VerboseJournal(journal)
    _persist_alert(alert, run_dir)
    deps = _deps(llm, journal, interactive=True)
    return triage(alert, deps, run_id=run_id)


def _run_resume(
    run_id: str,
    runs_dir: Path,
    *,
    approve: bool,
    deny: bool,
    verbose: bool = False,
) -> RunResult:
    """Reopen, rebuild, and continue a prior Run (the ``--resume`` path).

    Dispatches on the rebuilt journal tail: ``--approve`` / ``--deny`` complete a
    pending gate; otherwise an interrupted investigation continues (re-reading the
    persisted ``alert.json``). A mismatched flag/state raises ``TriageError`` from
    core, which ``main`` surfaces cleanly with no mutation. The LLM is built first so
    a config fault does not reopen (and re-flush) the journal.
    """
    llm = OpenAICompatibleLLM()
    run_dir = runs_dir / run_id
    reconstructed = rebuild(run_dir / "journal.jsonl")
    # Reopen: continues seq, truncates any torn line.
    journal: Journal = JsonlJournal(run_dir)
    if verbose:
        journal = _VerboseJournal(journal)
    deps = _deps(llm, journal, interactive=False)
    if approve:
        return resume_approve(deps, reconstructed, run_id=run_id, by=_RESUME_BY)
    if deny:
        return resume_deny(deps, reconstructed, run_id=run_id, by=_RESUME_BY)
    alert = _load_alert(run_dir / "alert.json")
    return resume_investigation(alert, deps, reconstructed, run_id=run_id)


def _maybe_synthesize_posture() -> None:
    """Increment the posture run counter and synthesize if the cadence is reached.

    Reads ``MEMORY_SYNTHESIZE_EVERY_N_RUNS`` from the environment (after
    :func:`load_dotenv` has already run in ``main``). Any failure is swallowed —
    a memory operation must never crash or delay a Run's exit.

    The broad ``except Exception`` below is intentional: the docstring promises "any
    failure is swallowed."  The callees (``PostureSynthesizer``, ``synthesize_posture_if_due``)
    are total by construction (each swallows its own IO), but a future edit to either could
    introduce a raise.  Catching here gives defensive depth so a memory-housekeeping step
    can never crash a Run that has already shipped its verdict.  No re-raise, no log —
    silence is correct: the run completed successfully and the memory miss is best-effort.
    """
    try:
        cadence = int(os.environ.get("MEMORY_SYNTHESIZE_EVERY_N_RUNS", "0"))
    except ValueError:
        cadence = 0
    try:
        synth = PostureSynthesizer()
        synthesize_posture_if_due(synth, cadence=cadence)
    except Exception:  # noqa: BLE001,S110 — intentional broad catch + silent pass; see docstring rationale above
        pass


def _run_synthesize_posture() -> int:
    """Regenerate the L3 posture brief immediately (the ``--synthesize-posture`` path).

    Uses the deterministic synthesis path — no LLM key required.  The brief is
    written to ``$MEMORY_DIR/posture.md`` (or ``.memory/posture.md`` when unset).
    An empty store yields an empty-but-valid brief (no crash).  Write failures are
    swallowed by :meth:`PostureSynthesizer.write` — a memory failure never crashes a
    Run.  Always returns ``0``: the caller decides whether to surface the path.
    """
    synth = PostureSynthesizer()
    brief = synth.synthesize_deterministic()
    synth.write(brief)
    posture_path = synth.base_dir / "posture.md"
    print(f"Posture brief written to: {posture_path}")  # noqa: T201 — CLI adapter output.
    return 0


def main(argv: list[str] | None = None, *, runs_dir: Path = _RUNS_DIR) -> int:
    """Run the adapter end-to-end (``--alert`` or ``--resume``) and return the exit code.

    Args:
        argv: The CLI arguments (defaults to ``sys.argv[1:]``); injectable so the
            adapter test drives it directly.
        runs_dir: Where run artifacts live; injectable so the test points it at a
            tmp dir instead of the repo's gitignored ``runs/``.

    Returns:
        ``0`` when a Verdict shipped (``triage`` never crashes once a Run starts);
        ``1`` when a ``TriageError`` (e.g. ``ConfigError`` from an unset
        ``LLM_API_KEY``, or a resume flag that does not match the Run's state)
        prevents the Run — a clean one-line message is printed to stderr. A
        non-``TriageError`` (a genuine bug) is not caught and propagates as a
        traceback.
    """
    load_dotenv()
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    # --synthesize-posture is key-free and never constructs an LLM, so it bypasses
    # the TriageError catch block (no ConfigError possible on that path).
    if args.synthesize_posture:
        return _run_synthesize_posture()

    try:
        # Each path builds the LLM first, so an unset LLM_API_KEY (ConfigError) is
        # raised before any journal directory is created or reopened.
        if args.resume is not None:
            result = _run_resume(
                args.resume,
                runs_dir,
                approve=args.approve,
                deny=args.deny,
                verbose=args.verbose,
            )
        else:
            result = _run_fresh(args.alert, runs_dir, verbose=args.verbose)
    except TriageError as exc:
        print(f"error: {exc}", file=sys.stderr)  # noqa: T201 — CLI adapter: stderr is the point.
        return 1

    record_path = _persist(result, runs_dir)
    print(summarize(result))  # noqa: T201 — CLI adapter: user-facing stdout is the point.
    print(f"\nRun record: {record_path}")  # noqa: T201 — CLI adapter output.
    # L3 cadence trigger: after a run persists, check if synthesis is due.
    # ``MEMORY_SYNTHESIZE_EVERY_N_RUNS=0`` (the default) disables this silently.
    # A write failure is swallowed by synthesize_posture_if_due; it never crashes.
    _maybe_synthesize_posture()
    return 0


if __name__ == "__main__":  # pragma: no cover  # CLI entrypoint guard — main() is tested directly.
    sys.exit(main())
