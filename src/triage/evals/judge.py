"""Tier-2 Judge — advisory LLM scoring from the Trajectory (US-0003, never blocks).

The Tier-2 lane (``eval-authoring`` skill): an LLM grades the *reasoning quality*
of a Run from its Trajectory and returns a 0-to-100 score tracked as a trend. It
is strictly advisory — it never gates submission and never overrides the
deterministic Tier-1 checks. A judge failure (no key, transport error, malformed
score) degrades to "not scored", never an exception that could block the gate.

ADR-0005: ``prompts/judge.md`` separates the rubric (instructions) from the
labeled ``<trajectory>`` block (untrusted data the judge evaluates). The Run
record and journal are dumped into that block via ``str.replace`` over the labeled
sentinel — never ``str.format`` (the artifacts are JSON full of literal braces).

Like every other LLM consumer, the judge talks only through the ``LLM`` port, so
it runs against ``FakeLLM`` / ``ReplayLLM`` in tests and a real model in live mode.
It emits ``llm_call`` (``purpose="judge"``) on success — the Tier-2 lane's only
journal footprint (ADR-0001: the journal is the only instrumentation).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from triage.errors import TriageError
from triage.llm import Message

if TYPE_CHECKING:
    from triage.evals.models import RunRecord
    from triage.journal import Journal
    from triage.llm import LLM

_PROMPT_PATH = Path(__file__).resolve().parents[3] / "prompts" / "judge.md"

_JUDGE_SCORE_MIN = 0
_JUDGE_SCORE_MAX = 100


class JudgeScore(BaseModel):
    """The advisory Tier-2 score the judge LLM returns (lax — it is LLM output)."""

    model_config = ConfigDict(extra="ignore")

    score: int = Field(ge=_JUDGE_SCORE_MIN, le=_JUDGE_SCORE_MAX)
    rationale: str = Field(min_length=1)


class JudgeResult(BaseModel):
    """The outcome of one Tier-2 judging — always produced, never blocking.

    ``scored`` is ``False`` when the judge could not run (no key, transport error,
    malformed reply); the runner reports it as "not scored" and moves on.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    scored: bool
    score: int | None = None
    rationale: str = ""


class Judge:
    """Advisory Tier-2 reviewer — scores reasoning from a Run's Trajectory."""

    def __init__(self, *, llm: LLM, journal: Journal) -> None:
        """Bind the LLM port and the journal; the rubric loads once."""
        self._llm = llm
        self._journal = journal
        self._template = _PROMPT_PATH.read_text(encoding="utf-8")

    def score(self, run_record: RunRecord) -> JudgeResult:
        """Score a Run's reasoning quality — advisory, never raising.

        Any failure (LLM error, malformed score) degrades to ``scored=False`` so a
        judge problem can never block a run or fail an eval. On success it emits
        the single ``llm_call`` (``purpose="judge"``) the Tier-2 lane records.
        """
        messages = self._render(run_record)
        try:
            completion = self._llm.complete(messages, JudgeScore)
        except TriageError:
            # Advisory lane: a missing key, transport failure, or malformed reply
            # (every triage error) degrades to "not scored", never blocks.
            return JudgeResult(scored=False, rationale="judge unavailable")
        self._journal.emit(
            "llm_call",
            {
                "purpose": "judge",
                "model": completion.model,
                "prompt_hash": completion.prompt_hash,
                "tokens": completion.tokens,
                "latency_ms": completion.latency_ms,
            },
        )
        return JudgeResult(
            scored=True,
            score=completion.value.score,
            rationale=completion.value.rationale,
        )

    def _render(self, run_record: RunRecord) -> list[Message]:
        """Render the rubric with the Run's trajectory in the labeled untrusted block."""
        trajectory = json.dumps(
            {"result": run_record.result, "journal": run_record.journal},
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        content = self._template.replace("{{TRAJECTORY}}", trajectory)
        return [Message(role="user", content=content)]
