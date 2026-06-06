"""The eval runner — orchestrates load -> run -> assert -> report (US-0003).

``make eval`` runs this. It is the *orchestrator only*: every behavioral check
lives in the pure ``assertions`` engine, every LLM response comes through the
``LLM`` port, and the report is built from ``ScoreResult`` data. The runner adds no
assertion logic of its own — a foreign tool reuses ``assert_case`` without ever
importing this module (US-0003 AC).

Per case it:

1. loads the Golden Case + its Alert (``loader``);
2. runs the agent — **live** (any injected ``LLM``: ``OpenAICompatibleLLM`` in
   real ``make eval``, ``FakeLLM`` in the deterministic suite) or **replay**
   (``ReplayLLM`` serving the per-case cache, key-free) — capturing the Run's
   ``result.json``-shaped record and its journal events into a ``RunRecord``;
3. scores the Tier-1 Behavioral Assertions via the pure engine;
4. optionally runs the advisory Tier-2 Judge (never gates);
5. reports per-assertion results and the model + prompt hashes from the journal.

Exit code: **nonzero iff any Tier-1 assertion of a non-``pending`` case failed**
(the functional acceptance gate). A ``pending`` case (e.g. ``benign-after-flagged``
awaiting memory-recall wiring) reports its failures as informational and never
gates — the ``eval-authoring`` skill's handling for a case that passes only after
upstream wiring lands. A replay miss raises ``ReplayMiss`` and fails loudly with
which case missed — never a silent fall back to live.
"""

from __future__ import annotations

import json
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from triage.core import TriageDeps, triage
from triage.evals.assertions import assert_case
from triage.evals.loader import load_cases
from triage.evals.models import RunRecord
from triage.evals.replay import ReplayLLM, replay_path
from triage.gate import AutoGate, RiskPolicy
from triage.memory import MemoryStore
from triage.models import Alert, Verdict
from triage.tools import FixtureDataSource, ToolRegistry

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from triage.evals.judge import JudgeResult
    from triage.evals.models import GoldenCase, PriorRun, ScoreResult
    from triage.llm import LLM

_CASES_DIR = Path(__file__).resolve().parent / "cases"
_REPO_ROOT = Path(__file__).resolve().parents[3]


class _CapturingJournal:
    """A ``Journal`` that captures events in the exact on-disk flat-line shape.

    Mirrors ``JsonlJournal``: it owns ``seq`` (monotonic from 1), ``event_id``,
    and ``ts``, and merges the caller's ``event`` + flat ``payload`` — so the
    ``RunRecord`` it feeds the assertion engine is byte-for-byte the shape a
    persisted ``journal.jsonl`` would be parsed into.
    """

    def __init__(self) -> None:
        """Start the event buffer and the monotonic seq counter."""
        self.events: list[dict[str, object]] = []
        self._seq = 0

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        """Append one event as the flat ``{seq, event_id, ts, event, agent, **payload}``."""
        self._seq += 1
        self.events.append(
            {
                "seq": self._seq,
                "event_id": str(uuid.uuid4()),
                "ts": datetime.now(UTC).isoformat(),
                "event": event,
                "agent": agent,
                **payload,
            },
        )


@dataclass
class CaseReport:
    """The per-case eval outcome the runner prints and the gate reads."""

    name: str
    pending: bool
    tier1: list[ScoreResult] = field(default_factory=list)
    judge: JudgeResult | None = None
    judge_min: float | None = None
    model: str = ""
    prompt_hashes: list[str] = field(default_factory=list)

    @property
    def tier1_failures(self) -> list[ScoreResult]:
        """Return the failed Tier-1 assertions (the gate reads these)."""
        return [result for result in self.tier1 if not result.passed]

    @property
    def gating_failed(self) -> bool:
        """Return whether this case fails the Tier-1 gate (pending never gates)."""
        return bool(self.tier1_failures) and not self.pending

    @property
    def judge_failed(self) -> bool:
        """Return whether this case fails the soft Tier-2 judge gate.

        Conditions: ``judge_min`` is set AND the judge scored (``scored=True``)
        AND ``judge.score < judge_min``.  A not-scored judge (transport error,
        no key) NEVER fails the soft gate — degradation must not block CI.
        An absent ``judge_min`` is always False.  A pending case never triggers
        the soft gate.
        """
        if self.pending or self.judge_min is None or self.judge is None:
            return False
        if not self.judge.scored or self.judge.score is None:
            return False
        return self.judge.score < self.judge_min


def build_deps(
    llm: LLM,
    journal: _CapturingJournal,
    memory: MemoryStore | None = None,
    *,
    approve: bool = False,
    ti_enabled: bool = False,
) -> TriageDeps:
    """Wire the agent dependencies for an eval Run (Fixture World, configurable gate).

    ``approve`` controls whether ``AutoGate`` approves or denies the high-risk
    batch.  The default ``False`` is CI's default-deny posture (unchanged for every
    existing case).  Set ``approve=True`` for cases whose assertions require an
    approved action (e.g. gate-ordering cases that assert ``action_executed``
    follows ``gate_decision(approved)``).  Set ``approve=False`` (default) for
    cases that assert denial semantics — the ``denied_actions_not_executed``
    assertion requires ``gate_decision(denied)`` to be in the journal.

    ``memory`` is the optional entity-scoped Memory Store a case seeds via its
    ``prior_runs`` declaration; ``None`` (every case without a seed) keeps the loop
    memory-free — no recall block, no store writes — identical to before the seam.

    ``ti_enabled`` threads the per-case TI posture through to ``TriageDeps`` as an
    explicit override (never ``None`` from here — the runner resolves the case's
    declared posture before calling this).  The default ``False`` is byte-identical
    to every existing case (the implicit env-var fallback path in ``core`` would
    also read ``False`` in CI where ``TI_ENABLED`` is unset, but an explicit
    ``False`` in ``TriageDeps.ti_enabled`` bypasses the env read entirely, making
    parallel replay threads race-free regardless of the environment).
    """
    return TriageDeps(
        llm=llm,
        journal=journal,
        registry=ToolRegistry(),
        source=FixtureDataSource(),
        gate=AutoGate(journal, approve=approve),
        policy=RiskPolicy(),
        memory=memory,
        ti_enabled=ti_enabled,
    )


def _load_alert(path: str) -> Alert:
    """Load and validate an alert JSON resolved repo-root-relative."""
    return Alert.model_validate_json(
        (_REPO_ROOT / path).read_text(encoding="utf-8"),
    )


def _seed_memory(prior_runs: Sequence[PriorRun], base_dir: Path) -> MemoryStore:
    """Persist a case's declared prior Runs into a tmp-dir Memory Store.

    Each prior Run flows through the *real* ``MemoryStore.persist`` (never a
    hand-written atom file), so the seed path exercises the same code as production
    persist and the recalled content reaches the planner byte-identically. The store
    is rooted at ``base_dir`` (a per-case temporary directory) so it NEVER touches
    the developer's configured ``MEMORY_DIR`` — the seed is hermetic.
    """
    store = MemoryStore(base_dir)
    for prior in prior_runs:
        store.persist(
            prior.run_id,
            _load_alert(prior.alert),
            Verdict.model_validate(prior.verdict),
        )
    return store


def run_case(case: GoldenCase, llm: LLM) -> RunRecord:
    """Run one Golden Case's Alert through the agent, returning its ``RunRecord``.

    The Alert path in the case is resolved relative to the repo root. When the case
    declares ``prior_runs``, a throwaway tmp-dir Memory Store is seeded through the
    real ``persist`` API and wired via ``TriageDeps.memory`` so recall feeds the
    planner; the tmp dir is cleaned up after the Run, never touching ``MEMORY_DIR``.
    A case without a seed runs memory-free (``memory=None``). The captured journal
    and the ``result.json``-shaped run record are bundled into the same ``RunRecord``
    the on-disk loader would produce — so live and replay runs score through the
    identical seam.

    The per-case ``gate`` field (``"approve"`` or ``"deny"``) drives whether
    ``AutoGate`` approves or denies the high-risk batch.  The default ``"approve"``
    is byte-identical to all existing cases (no behaviour change).
    """
    alert = _load_alert(case.alert)
    journal = _CapturingJournal()
    approve = case.gate != "deny"
    if not case.prior_runs:
        return _run(
            alert,
            build_deps(llm, journal, approve=approve, ti_enabled=case.ti_enabled),
            journal,
        )
    with tempfile.TemporaryDirectory(prefix="triage-eval-memory-") as tmp:
        memory = _seed_memory(case.prior_runs, Path(tmp))
        return _run(
            alert,
            build_deps(llm, journal, memory, approve=approve, ti_enabled=case.ti_enabled),
            journal,
        )


def _run(alert: Alert, deps: TriageDeps, journal: _CapturingJournal) -> RunRecord:
    """Run the agent and bundle the result + captured journal into a ``RunRecord``."""
    result = triage(alert, deps)
    return RunRecord(
        result=json.loads(result.model_dump_json()),
        journal=journal.events,
    )


def _prompt_hashes(run_record: RunRecord) -> list[str]:
    """Return the ``prompt_hash`` of every ``llm_call`` event (report provenance)."""
    return [
        str(event["prompt_hash"])
        for event in run_record.journal
        if event.get("event") == "llm_call" and "prompt_hash" in event
    ]


def evaluate_case(
    case: GoldenCase,
    llm: LLM,
    *,
    judge: Any = None,  # noqa: ANN401 — a duck-typed Judge (score(run_record)->JudgeResult); avoids importing the LLM-bound judge unless used.
) -> CaseReport:
    """Run, score, and optionally judge one Golden Case into a ``CaseReport``."""
    run_record = run_case(case, llm)
    tier1 = assert_case(case, run_record)
    judge_result = judge.score(run_record) if judge is not None else None
    model = next(
        (str(e["model"]) for e in run_record.journal if e.get("event") == "llm_call"),
        "",
    )
    return CaseReport(
        name=case.name,
        pending=case.pending is not None,
        tier1=tier1,
        judge=judge_result,
        judge_min=case.judge_min,
        model=model,
        prompt_hashes=_prompt_hashes(run_record),
    )


def format_report(reports: Sequence[CaseReport]) -> str:
    """Render the human-readable eval report from the per-case results."""
    lines: list[str] = ["Eval report — Tier-1 (blocking) + Tier-2 (advisory)", ""]
    for report in reports:
        status = "PENDING" if report.pending else ("PASS" if not report.tier1_failures else "FAIL")
        lines.append(f"[{status}] {report.name}  (model={report.model or 'n/a'})")
        for result in report.tier1:
            mark = "ok  " if result.passed else "FAIL"
            suffix = f" — {result.detail}" if result.detail else ""
            lines.append(f"    {mark} {result.name}{suffix}")
        if report.judge is not None:
            lines.append(_format_judge(report.judge))
    lines.append("")
    gating = [r for r in reports if r.gating_failed]
    lines.append(
        "RESULT: all Tier-1 assertions passed"
        if not gating
        else f"RESULT: Tier-1 FAILURES in {[r.name for r in gating]}",
    )
    return "\n".join(lines)


def _format_judge(judge: JudgeResult) -> str:
    """Render one case's advisory Tier-2 line (never affects pass/fail)."""
    if not judge.scored:
        return "    judge: not scored (advisory)"
    return f"    judge: {judge.score}/100 (advisory) — {judge.rationale}"


def run_suite(
    llm: LLM,
    *,
    cases_dir: Path = _CASES_DIR,
    judge: Any = None,  # noqa: ANN401 — optional duck-typed Judge; see evaluate_case.
) -> list[CaseReport]:
    """Evaluate every Golden Case in ``cases_dir`` and return the per-case reports."""
    return [evaluate_case(case, llm, judge=judge) for case in load_cases(cases_dir)]


def _build_live_llm() -> LLM:
    """Build the real ``OpenAICompatibleLLM`` for a live ``make eval`` run.

    Imported lazily (PLC0415) so the deterministic suite never touches the openai
    client or needs a key — only the live ``make eval`` path constructs it.
    """
    # Deliberate lazy import (rationale in the docstring above).
    from triage.llm import OpenAICompatibleLLM  # noqa: PLC0415

    return OpenAICompatibleLLM()


def _build_judge(llm: LLM) -> Any:  # noqa: ANN401 — duck-typed Judge; see evaluate_case.
    """Build the live Tier-2 Judge (median-of-3, journal-free) for ``main``.

    Lazy import for the same reason as ``_build_live_llm``: the replay path and
    the deterministic suite never need the judge module's rubric load.
    """
    # Deliberate lazy import (rationale in the docstring above).
    from triage.evals.judge import Judge  # noqa: PLC0415
    from triage.journal import NoopJournal  # noqa: PLC0415

    return Judge(llm=llm, journal=NoopJournal(), samples=3)


def case_replay_path(case: GoldenCase, cases_dir: Path = _CASES_DIR) -> Path:
    """Return the replay-cache path that sits alongside ``case``'s YAML by name.

    ``cases/<name>.yaml`` -> ``cases/<name>.replay.json`` — the one-cache-per-case
    layout, resolved from the case *name* so a loaded ``GoldenCase`` (which does not
    carry its source path) still finds its cache.
    """
    return replay_path(cases_dir / f"{case.name}.yaml")


def main(argv: list[str] | None = None) -> int:
    """``make eval`` entry point — run the suite and exit nonzero on Tier-1 failure.

    Args:
        argv: CLI args; ``--replay`` re-serves each case from its recorded cache
            (key-free), otherwise a live ``OpenAICompatibleLLM`` is used.

    Returns:
        ``0`` when every gating (non-pending) case passed Tier-1, else ``1``.

    The live client is built only on the live path (and only once for every case);
    the replay path never constructs it, so ``make eval --replay`` needs no key.

    In replay mode, a case whose ``.replay.json`` does not exist yet is skipped
    with a loud ``[NO CACHE]`` note in the report — it is never a hard failure and
    never gates.  This allows new cases to land before their live recording runs.

    Live mode wires the Tier-2 Judge (median-of-3) for cases declaring
    ``judge_min`` — the soft gate's only consumers (US-0007).  Judging every case
    would triple live cost for advisory output nothing gates on; replay mode never
    judges (the judge is an LLM, and replay is the key-free path).
    """
    args = argv if argv is not None else sys.argv[1:]
    replay = "--replay" in args
    cases = load_cases(_CASES_DIR)
    live_llm = None if replay else _build_live_llm()
    judge = None if live_llm is None else _build_judge(live_llm)
    reports_and_skips: list[CaseReport | str] = []
    for case in cases:
        llm = _llm_for_case(case, live_llm)
        if llm is None:
            # No cache recorded yet — skip loudly, never gate.
            reports_and_skips.append(
                f"[NO CACHE] {case.name} — no replay cache recorded yet; "
                "run 'make eval' (live) to record one before replaying",
            )
        else:
            case_judge = judge if case.judge_min is not None else None
            reports_and_skips.append(evaluate_case(case, llm, judge=case_judge))
    reports = [r for r in reports_and_skips if isinstance(r, CaseReport)]
    lines = [format_report(reports)]
    skips = [s for s in reports_and_skips if isinstance(s, str)]
    if skips:
        lines.insert(0, "\n".join(skips))
    tier1_failed = any(report.gating_failed for report in reports)
    judge_soft_failed = any(report.judge_failed for report in reports)
    if judge_soft_failed and not tier1_failed:
        warn_lines = ["", "TIER-2 WARN — judge_min not met (soft gate, exit 2):"]
        warn_lines.extend(
            f"  {report.name}: score={report.judge.score} < judge_min={report.judge_min}"
            for report in reports
            if report.judge_failed and report.judge is not None
        )
        lines.append("\n".join(warn_lines))
    sys.stdout.write("\n".join(lines) + "\n")
    if tier1_failed:
        return 1
    if judge_soft_failed:
        return 2
    return 0


def _llm_for_case(case: GoldenCase, live_llm: LLM | None) -> LLM | None:
    """Pick the per-case LLM: that case's replay cache, or the shared live client.

    ``live_llm is None`` is the replay path — each case is served by its recorded
    cache via ``ReplayLLM``, never touching a live client.

    Returns ``None`` when in replay mode and the cache file is missing (new case,
    not yet recorded) — the caller must handle ``None`` as a loud skip, never a
    hard failure.  A cache file that exists but is malformed still raises
    ``ReplayCacheError`` loudly (a mis-recorded cache is different from "not yet
    recorded").
    """
    if live_llm is None:
        path = case_replay_path(case)
        if not path.exists():
            return None
        return ReplayLLM.from_path(path)
    return live_llm


if __name__ == "__main__":  # pragma: no cover  # CLI entry — exercised via main(argv) in tests.
    raise SystemExit(main())
