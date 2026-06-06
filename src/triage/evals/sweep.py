"""Multi-model eval sweep — run the golden suite on any model, compare results (US-0009).

Promoted from the wave-time workspace driver into shipped source.  Where
``runner.main`` runs the suite once on the configured model (the acceptance gate),
``sweep`` runs it on an *arbitrary* model loaded from an isolated env file, while
keeping the Tier-2 judge pinned to a baseline model so scores stay comparable
across models.  It proves the requirements-bonus claim — swap the model without
touching agent logic — and produces the per-model comparison table.

Design for the 100%-coverage gate: every non-LLM seam is a small pure function
(``load_env_file``, ``judge_overrides_present``, ``cache_destination``,
``throttle_remaining``, ``aggregate``), and ``run_sweep`` takes injectable
``llm_factory`` / ``judge_factory`` / ``case_runner`` so the deterministic suite
drives it with ``FakeLLM`` — no live client, no key.

CLI (``python -m triage.evals.sweep``):

    --env-file FILE         agent-model env (LLM_API_KEY/_BASE_URL/_MODEL); isolated per sweep
    --judge-env-file FILE   pin the judge to this model (its LLM_* load as JUDGE_*)
    --out DIR               per-case JSON + summary.json destination
    --scratch-caches        write replay caches into --out (never overwrite the baseline)
    --min-case-seconds N    floor each case's wall time (RPM throttle for serverless models)
    --workers N             concurrent cases (default: CPU count; use 1 for tight RPM)
    --no-judge              skip Tier-2 entirely
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from triage.evals.assertions import assert_case
from triage.evals.judge import Judge
from triage.evals.loader import load_cases
from triage.evals.replay import RecordingLLM, ReplayCache, replay_path
from triage.evals.runner import _build_live_llm, run_case
from triage.journal import NoopJournal

if TYPE_CHECKING:
    from collections.abc import Sequence

    from triage.evals.models import GoldenCase
    from triage.llm import LLM

_CASES_DIR = Path(__file__).resolve().parent / "cases"
_JUDGE_SAMPLES = 3
_JUDGE_PREFIX_MAP = {"LLM_": "JUDGE_"}

LLMFactory = Callable[[], "LLM"]
CaseRunner = Callable[["GoldenCase", "LLM"], Any]


# --------------------------------------------------------------------------- #
# Pure seams (unit-tested without any LLM)                                      #
# --------------------------------------------------------------------------- #


def load_env_file(path: Path, *, prefix_map: dict[str, str] | None = None) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines from ``path`` into ``os.environ`` and return them.

    ``prefix_map`` renames keys on the way in — ``{"LLM_": "JUDGE_"}`` turns a
    normal model env file into judge-pinning overrides, so one env file describes
    both an agent model (loaded as-is) and a pinned judge (loaded prefixed).
    Blank lines and ``#`` comments are skipped.  Each sweep process is fully
    isolated by its own env file; values overwrite the inherited environment.

    Returns the applied ``{key: value}`` map (the keys actually set), so callers
    and tests can assert what an env file contributed without reading os.environ.
    """
    applied: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if prefix_map:
            for old, new in prefix_map.items():
                if key.startswith(old):
                    key = new + key[len(old) :]
                    break
        value = value.strip()
        os.environ[key] = value
        applied[key] = value
    return applied


def judge_overrides_present() -> bool:
    """True iff a ``JUDGE_MODEL`` override is set — the judge is pinned to its own model."""
    return bool(os.environ.get("JUDGE_MODEL"))


def cache_destination(case_name: str, yaml_path: Path, out: Path, *, scratch: bool) -> Path:
    """Pick where a recorded replay cache is written.

    ``scratch=True`` (cross-model sweeps) writes into ``out`` so the committed
    baseline caches next to the YAMLs are never overwritten; otherwise it writes
    the canonical ``<case>.replay.json`` beside the YAML (a baseline re-record).
    """
    if scratch:
        return out / f"{case_name}.replay.json"
    return replay_path(yaml_path)


def throttle_remaining(elapsed: float, min_case_seconds: float) -> float:
    """Seconds still to sleep so a case consumes at least ``min_case_seconds``.

    Returns ``0.0`` when no throttle applies or the case already ran long enough —
    the RPM throttle for rate-limited serverless models (e.g. 20 RPM → 60s/case
    with ``--workers 1``).
    """
    if min_case_seconds <= 0:
        return 0.0
    return max(0.0, min_case_seconds - elapsed)


# --------------------------------------------------------------------------- #
# Result types + aggregation                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CaseOutcome:
    """One case's sweep outcome (the shape persisted per case and aggregated)."""

    name: str
    pending: bool
    crashed: bool
    tier1_passed: bool
    judge_score: int | None
    wall_s: float
    tokens: int


@dataclass(frozen=True)
class SweepSummary:
    """The per-model comparison row built from a run directory."""

    cases: int
    tier1_passed: int
    judge_mean: float | None
    judge_stdev: float | None
    judge_min: int | None
    wall_per_case: float
    tokens_per_case: int

    def as_row(self, model: str) -> str:
        """Render one Markdown table row for ``docs/evals/results.md``."""
        jm = f"{self.judge_mean:.1f}" if self.judge_mean is not None else "—"
        js = f"{self.judge_stdev:.1f}" if self.judge_stdev is not None else "—"
        jmin = str(self.judge_min) if self.judge_min is not None else "—"
        return (
            f"| {model} | {self.tier1_passed}/{self.cases} | {jm} | {js} | "
            f"{jmin} | {self.wall_per_case:.1f}s | {self.tokens_per_case} |"
        )


def aggregate(run_dir: Path) -> SweepSummary:
    """Reduce a sweep ``run_dir`` of per-case JSONs to one comparison row.

    Reads only ``<case>.json`` files (skips ``<case>.replay.json`` scratch caches).
    A crashed case counts toward ``cases`` but not ``tier1_passed`` and contributes
    no judge score.
    """
    scores: list[int] = []
    walls: list[float] = []
    toks: list[int] = []
    cases = 0
    tier1_passed = 0
    for f in sorted(run_dir.glob("*.json")):
        if f.name.endswith(".replay.json"):
            continue
        d = json.loads(f.read_text(encoding="utf-8"))
        cases += 1
        if d.get("crashed"):
            continue
        if all(a["passed"] for a in d.get("tier1", [])):
            tier1_passed += 1
        judge = d.get("judge") or {}
        if judge.get("scored") and judge.get("score") is not None:
            scores.append(int(judge["score"]))
        if d.get("wall_s") is not None:
            walls.append(float(d["wall_s"]))
        toks.append(sum(int(c.get("tokens") or 0) for c in (d.get("llm_calls") or [])))
    return SweepSummary(
        cases=cases,
        tier1_passed=tier1_passed,
        judge_mean=statistics.mean(scores) if scores else None,
        judge_stdev=statistics.stdev(scores) if len(scores) > 1 else None,
        judge_min=min(scores) if scores else None,
        wall_per_case=statistics.mean(walls) if walls else 0.0,
        tokens_per_case=int(statistics.mean(toks)) if toks else 0,
    )


# --------------------------------------------------------------------------- #
# Sweep configuration (factories + per-case options, injectable in tests)      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SweepConfig:
    """The factories and per-case options threaded through one sweep.

    Factories are injectable so the deterministic suite drives a sweep with
    ``FakeLLM`` and the real ``run_case`` — no live client, no key.  ``None``
    sentinels resolve at use time (``llm_factory`` → ``_build_live_llm``,
    ``case_runner`` → ``run_case``) so module-level monkeypatching works;
    ``judge_factory=None`` skips Tier-2.
    """

    llm_factory: LLMFactory | None = None
    judge_factory: LLMFactory | None = None
    case_runner: CaseRunner | None = None
    scratch_caches: bool = False
    min_case_seconds: float = 0.0

    def make_llm(self) -> LLM:
        """Build the agent LLM (resolves the default at call time)."""
        return (self.llm_factory or _build_live_llm)()

    def run(self, case: GoldenCase, llm: LLM) -> Any:  # noqa: ANN401 — RunRecord, kept loose
        """Run one case (resolves the default ``run_case`` at call time)."""
        return (self.case_runner or run_case)(case, llm)


def build_judge_llm() -> LLM:
    """Build the judge's LLM — pinned via ``JUDGE_*`` overrides when present.

    Cross-model sweeps run the agent on an alternative model but keep the judge on
    the baseline model for score comparability.  Without overrides the judge shares
    the agent's env-built client (single-model behavior, unchanged).
    """
    if not judge_overrides_present():
        return _build_live_llm()
    from openai import OpenAI  # noqa: PLC0415 — only needed on the pinned-judge path

    from triage.llm import OpenAICompatibleLLM  # noqa: PLC0415

    client = OpenAI(
        api_key=os.environ.get("JUDGE_API_KEY") or os.environ.get("LLM_API_KEY"),
        base_url=os.environ.get("JUDGE_BASE_URL") or os.environ.get("LLM_BASE_URL") or None,
    )
    return OpenAICompatibleLLM(client=client, model=os.environ["JUDGE_MODEL"])


# --------------------------------------------------------------------------- #
# Per-case execution                                                           #
# --------------------------------------------------------------------------- #


def _atomic_write(dest: Path, text: str) -> None:
    """Write ``text`` to ``dest`` atomically via a temp file in the same directory."""
    fd, tmp = tempfile.mkstemp(dir=dest.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        Path(tmp).replace(dest)
    except OSError:
        Path(tmp).unlink(missing_ok=True)
        raise


def run_case_to_disk(
    case: GoldenCase,
    yaml_path: Path,
    out: Path,
    config: SweepConfig,
) -> CaseOutcome:
    """Run one case, persist its result JSON + replay cache, return its outcome.

    A crashing case is itself a finding: the crash is recorded and the sweep
    continues (the same never-let-one-case-kill-the-run posture as the workspace
    driver).  Factories come from ``config`` so tests drive this with ``FakeLLM``.
    """
    dest = out / f"{case.name}.json"
    live = config.make_llm()
    judge = (
        Judge(llm=config.judge_factory(), journal=NoopJournal(), samples=_JUDGE_SAMPLES)
        if config.judge_factory is not None
        else None
    )
    cache = ReplayCache(entries={}, model=getattr(live, "model", "unknown"))
    recorder = RecordingLLM(live, cache)

    t0 = time.monotonic()
    try:
        record = config.run(case, recorder)
    except Exception as exc:  # noqa: BLE001 — a crashing case is a finding, not a sweep abort
        _atomic_write(dest, json.dumps({"name": case.name, "crashed": repr(exc)}))
        _sleep(throttle_remaining(time.monotonic() - t0, config.min_case_seconds))
        return CaseOutcome(case.name, False, True, False, None, 0.0, 0)  # noqa: FBT003

    wall = time.monotonic() - t0
    cache.dump(cache_destination(case.name, yaml_path, out, scratch=config.scratch_caches))
    tier1 = assert_case(case, record)
    judge_result = judge.score(record) if judge is not None else None
    judge_data = judge_result.model_dump() if judge_result is not None else None
    calls = [e for e in record.journal if e.get("event") == "llm_call"]
    tokens = sum(int(e.get("tokens") or 0) for e in calls)
    _atomic_write(
        dest,
        json.dumps(
            {
                "name": case.name,
                "pending": case.pending is not None,
                "wall_s": round(wall, 2),
                "tier1": [{"name": r.name, "passed": r.passed, "detail": r.detail} for r in tier1],
                "judge": judge_data,
                "judge_min": case.judge_min,
                "verdict": record.result.get("verdict"),
                "terminated_reason": record.result.get("terminated_reason"),
                "llm_calls": [
                    {"purpose": e.get("purpose"), "tokens": e.get("tokens")} for e in calls
                ],
                "tools_called": [
                    e.get("tool") for e in record.journal if e.get("event") == "tool_called"
                ],
            },
            indent=1,
        ),
    )
    _sleep(throttle_remaining(wall, config.min_case_seconds))
    return CaseOutcome(
        name=case.name,
        pending=case.pending is not None,
        crashed=False,
        tier1_passed=all(r.passed for r in tier1),
        judge_score=(judge_data or {}).get("score"),
        wall_s=wall,
        tokens=tokens,
    )


def _sleep(seconds: float) -> None:
    """Sleep wrapper (one indirection so the throttle path is trivially patchable)."""
    if seconds > 0:
        time.sleep(seconds)


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class SweepResult:
    """What ``run_sweep`` returns: per-case outcomes + the aggregated summary."""

    summary: SweepSummary
    outcomes: list[CaseOutcome] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        """True iff every non-pending case passed Tier-1 (the sweep exit gate)."""
        non_pending = [o for o in self.outcomes if not o.pending]
        return all(o.tier1_passed for o in non_pending)


def run_sweep(
    pairs: Sequence[tuple[GoldenCase, Path]],
    out: Path,
    config: SweepConfig | None = None,
    *,
    workers: int = 1,
) -> SweepResult:
    """Run every ``(case, yaml_path)`` pair, persist results, return outcomes + summary.

    Already-completed cases (a ``<case>.json`` already in ``out``) are skipped, so a
    sweep interrupted by a spent quota resumes cleanly.  Concurrency is bounded by
    ``workers``; with a rate-limited model use ``workers=1`` + a throttle in
    ``config.min_case_seconds``.  ``config`` defaults to a live-model sweep with the
    pinned-or-shared judge.
    """
    config = config or SweepConfig(judge_factory=build_judge_llm)
    out.mkdir(parents=True, exist_ok=True)
    outcomes: list[CaseOutcome] = []
    to_run = [(c, p) for c, p in pairs if not (out / f"{c.name}.json").exists()]

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(run_case_to_disk, case, path, out, config): case.name
            for case, path in to_run
        }
        for fut in as_completed(futures):
            outcome = fut.result()
            mark = "CRASH" if outcome.crashed else ("PASS" if outcome.tier1_passed else "FAIL")
            sys.stdout.write(f"  {mark} {outcome.name}  wall={outcome.wall_s:.1f}s\n")
            sys.stdout.flush()
            outcomes.append(outcome)

    return SweepResult(summary=aggregate(out), outcomes=outcomes)


def _pairs_from_dirs(dirs: Sequence[str]) -> list[tuple[GoldenCase, Path]]:
    """Load all cases under ``dirs`` paired with their YAML paths, sorted by name."""
    pairs: list[tuple[GoldenCase, Path]] = []
    for d in dirs:
        directory = Path(d)
        pairs.extend((case, directory / f"{case.name}.yaml") for case in load_cases(directory))
    pairs.sort(key=lambda p: p[0].name)
    return pairs


def main(argv: list[str] | None = None) -> int:
    """CLI entry point — run one model's sweep and exit nonzero on any Tier-1 failure."""
    parser = argparse.ArgumentParser(prog="triage.evals.sweep")
    parser.add_argument("--out", default="_workspace/evalrun", type=Path)
    parser.add_argument("--dirs", nargs="*", default=[str(_CASES_DIR)])
    parser.add_argument("--env-file", default=None)
    parser.add_argument("--judge-env-file", default=None)
    parser.add_argument("--scratch-caches", action="store_true")
    parser.add_argument("--no-judge", action="store_true")
    parser.add_argument("--min-case-seconds", type=float, default=0.0)
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if args.env_file:
        load_env_file(Path(args.env_file))
    if args.judge_env_file:
        load_env_file(Path(args.judge_env_file), prefix_map=_JUDGE_PREFIX_MAP)
    agent_model = os.environ.get("LLM_MODEL", "?")
    judge_model = os.environ.get("JUDGE_MODEL") or agent_model
    sys.stdout.write(f"agent model: {agent_model}  judge model: {judge_model}\n")

    config = SweepConfig(
        judge_factory=None if args.no_judge else build_judge_llm,
        scratch_caches=args.scratch_caches,
        min_case_seconds=args.min_case_seconds,
    )
    result = run_sweep(_pairs_from_dirs(args.dirs), args.out, config, workers=args.workers)
    sys.stdout.write(result.summary.as_row(agent_model) + "\n")
    return 0 if result.all_passed else 1


if __name__ == "__main__":  # pragma: no cover — CLI entry; main(argv) is tested directly.
    raise SystemExit(main())
