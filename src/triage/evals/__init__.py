"""The eval harness — the mandatory functional acceptance gate (RFC-0001 §Eval).

This package ``__init__`` re-exports ONLY the pure, dependency-light surface — the
eval data contracts and the pure Tier-1 assertion engine — so that

    from triage.evals.assertions import assert_case

(or ``from triage.evals import assert_case``) does NOT drag in the runner, the
agent core, or the LLM client (US-0003 AC: a foreign tool reuses the checks
without importing the runner). The heavier collaborators are imported from their
own submodules by the consumers that need them, never eagerly here:

* ``RecordingLLM`` / ``ReplayLLM`` / ``ReplayCache`` / ``ReplayMiss`` — Replay Mode
  (``from triage.evals.replay import ...``);
* ``Judge`` — the advisory Tier-2 reviewer (``from triage.evals.judge import Judge``);
* ``run_suite`` / ``main`` — the orchestrator ``make eval`` invokes
  (``from triage.evals.runner import ...``);
* ``load_case`` / ``load_run_record`` — the on-disk seams (``...loader``).

Vendor bindings (deepeval, promptfoo, LangSmith) live behind ``evals.adapters`` —
optional consumers of ``RunRecord`` + the case ``reference`` block, never a
dependency of the harness (the ``eval-authoring`` skill: tool-neutral evaluability).

NOTE (AC-vs-landed-code): importing any ``triage.evals`` submodule still triggers
the *parent* ``triage`` package ``__init__`` (``src/triage/__init__.py``, owned by
another wave), which eagerly imports ``triage.core`` et al. That eager parent
import is outside this package's control; this ``__init__`` is slimmed so the
*evals* layer adds no runner/core coupling of its own.
"""

from triage.evals.assertions import assert_case
from triage.evals.models import (
    GoldenCase,
    Reference,
    RunRecord,
    ScoreResult,
    TrajectoryExpect,
    VerdictExpect,
)

__all__ = [
    "GoldenCase",
    "Reference",
    "RunRecord",
    "ScoreResult",
    "TrajectoryExpect",
    "VerdictExpect",
    "assert_case",
]
