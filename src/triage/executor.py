"""The executor — the ReAct loop (RFC-0001 §Core loop / ADR-0005).

The executor consumes an ``InvestigationPlan`` and walks it as a sequence of
executor **Steps** (distinct from **Plan Steps** — UBIQUITOUS_LANGUAGE.md): each
Step picks one Plan Step, runs its Tool against the ``DataSource`` (read-only,
mid-loop mutation is impossible by construction), turns the result into an
**Observation** (``ToolResult``), then asks the **Reasoner** (one structured LLM
call, ``purpose="reason"``) what to do next:

* ``continue`` — the remaining plan is still sound; proceed to its next Plan Step.
  ``next_step`` is ignored on this verb.
* ``revise_plan`` — the evidence changes the agenda; ``next_step`` *replaces* the
  remaining plan and is the only Plan Step executed next. Emits ``plan_revised``.
  This is the one verb that carries a ``next_step`` — keeping ``revise_plan``
  distinct from ``continue`` (a ``continue`` that carried a step would collapse
  the two and make ``plan_revised`` meaningless).
* ``conclude`` — stop; ``terminated_reason="completed"``.

The loop never crashes (RFC-0001 §Retry visibility / triage-conventions):

* Tool errors arrive as ``ToolResult(ok=False)`` Observations via ``execute_tool``
  — the Reasoner adapts, the run does not raise.
* A hallucinated tool name (``registry.get`` raises ``KeyError``) is converted to
  an ``ok=False`` Observation the same way — a real path on the ``revise_plan``
  branch.
* The **repeat-call guard**: an identical tool+args pair proposed twice is never
  executed; a guard note is surfaced to the Reasoner (forcing a course change)
  but is kept out of the evidence ``observations`` — it is not evidence. The Step
  still counts against ``MAX_STEPS`` so a Reasoner that keeps re-proposing the
  duplicate still terminates.
* ``MAX_STEPS`` breach (env ``MAX_STEPS``, default 15; constructor override for
  tests): stop with ``terminated_reason="max_steps"``. Synthesizing the partial
  Verdict is the verdict/core module's job — the executor only signals.
* An ``LLMError`` from the Reasoner mid-loop: stop with
  ``terminated_reason="error"`` and return what was gathered. Mirroring the
  planner, nothing is emitted on that path (no ``Completion`` means no
  ``llm_call`` metadata to journal). The executor does **not** emit
  ``run_terminated`` — that, and the degraded partial Verdict, are core's job;
  the executor signals via ``terminated_reason``. This is the single boundary
  crossing the ``LLMError`` makes (no exception crosses two module boundaries).

The return seam is local to this module: ``models.py`` is owned by the core wave,
so ``ExecutionResult`` / ``ObservationEntry`` are defined here and the core wave
may promote them. ``ExecutionResult`` carries the gathered Observation trajectory
(what ``verdict.py`` cites Findings from), the ``terminated_reason``, and the
final Reasoner rationale.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from triage.errors import LLMError
from triage.llm import Message
from triage.models import (
    Alert,
    InvestigationPlan,
    PlanStep,
    ReasonerDecision,
    TerminatedReason,
    ToolResult,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from triage.journal import Journal
    from triage.llm import LLM
    from triage.tools.base import DataSource, Tool
    from triage.tools.registry import ToolRegistry

from triage.tools.base import execute_tool

_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "reasoner.md"

_DEFAULT_MAX_STEPS = 15


def _max_steps_from_env() -> int:
    """Read ``MAX_STEPS`` from the env, falling back to the default of 15.

    A non-integer value is treated as unset — the env is operator-controlled
    config, not untrusted input, so a malformed value falls back rather than
    failing the run at construction time.
    """
    raw = os.environ.get("MAX_STEPS")
    if raw is None:
        return _DEFAULT_MAX_STEPS
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_MAX_STEPS


class ObservationEntry(BaseModel):
    """One executed Step's evidence: the Tool, its args, and the Observation.

    The unit ``verdict.py`` cites Findings from — it carries the executor Step
    number (the ``MAX_STEPS``-counted iteration, *not* the Plan Step index) so the
    trajectory is reconstructable without positional inference, mirroring the
    journal's shared ``step`` discipline. Closed/strict: it is an internal record
    the LLM never produces.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    step: int = Field(ge=1)
    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    result: ToolResult


class ExecutionResult(BaseModel):
    """The executor's local return seam — what verdict/core consume.

    Carries the gathered Observation trajectory (the evidence Findings cite), the
    ``terminated_reason`` the executor only ever sets to ``completed``,
    ``max_steps``, or ``error`` (``awaiting_approval`` is the gate's, never the
    executor's), and the final Reasoner rationale when one was reached.

    Defined locally because ``models.py`` is owned by the core wave; promote there
    if a second consumer appears.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    observations: list[ObservationEntry] = Field(default_factory=list)
    terminated_reason: TerminatedReason
    final_rationale: str | None = None


@dataclass
class _Dispatch:
    """The internal result of applying one Reasoner decision in the loop.

    Either ``terminated`` is set (the decision ended the Run — conclude or a
    degenerate revision) or it is ``None`` and ``pending`` is the plan to walk next
    (``continue`` keeps the current pending; ``revise_plan`` replaces it). Never
    both — a private helper for the shared loop, not a public seam.
    """

    terminated: ExecutionResult | None = None
    pending: list[PlanStep] = field(default_factory=list)


@dataclass
class _LoopState:
    """The mutable bookkeeping the ReAct walk carries across Steps.

    Bundled into one object so ``run`` and ``resume`` seed the shared ``_loop``
    without a long keyword-argument list: ``pending`` is the plan still to walk,
    ``observations`` the gathered trajectory, ``attempted`` the repeat-call-guard
    set, ``guard_notes`` the off-trajectory nudges, and ``step`` the
    ``MAX_STEPS``-counted iteration count (seeded to the rebuilt count on resume).
    """

    pending: list[PlanStep]
    observations: list[ObservationEntry]
    attempted: set[tuple[str, str]]
    guard_notes: list[str]
    step: int


class Executor:
    """Walks an Investigation Plan as the ReAct loop, gathering Observations."""

    def __init__(
        self,
        *,
        llm: LLM,
        journal: Journal,
        registry: ToolRegistry,
        source: DataSource,
        max_steps: int | None = None,
    ) -> None:
        """Bind the explicit dependencies; the reasoner prompt loads once.

        Args:
            llm: The structured-output port the ``reason`` call goes through.
            journal: The port ``llm_call`` / ``plan_revised`` / ``tool_called`` /
                ``tool_result`` events emit to.
            registry: The read-only investigation tools — the only callable set
                mid-loop, by construction.
            source: The ``DataSource`` tools read from (the Fixture World ships in
                wave 1; swappable behind the Protocol).
            max_steps: Override for the ``MAX_STEPS`` guard; falls back to the env
                var, then the default of 15. The override keeps the breach test
                small instead of scripting 15 replies.
        """
        self._llm = llm
        self._journal = journal
        self._registry = registry
        self._source = source
        self._max_steps = max_steps if max_steps is not None else _max_steps_from_env()
        self._template = _PROMPT_PATH.read_text(encoding="utf-8")

    def run(self, alert: Alert, plan: InvestigationPlan) -> ExecutionResult:
        """Execute ``plan`` for ``alert`` and return the gathered Observations.

        Args:
            alert: The validated Alert under investigation (rendered untrusted).
            plan: The ``InvestigationPlan`` whose Plan Steps seed the loop.

        Returns:
            An ``ExecutionResult`` with the Observation trajectory and the
            ``terminated_reason`` — never raising on a tool or LLM failure.
        """
        return self._loop(
            alert,
            _LoopState(
                pending=list(plan.steps),
                observations=[],
                attempted=set(),
                guard_notes=[],
                step=0,
            ),
        )

    def resume(
        self,
        alert: Alert,
        plan: InvestigationPlan,
        *,
        pre_observations: Sequence[ObservationEntry],
        next_step_index: int,
    ) -> ExecutionResult:
        """Continue an interrupted investigation from its rebuilt Observations.

        The single re-entry point for ``--resume`` on an interrupted Run (US-0002
        AC3). Completed Tool Steps are **reused from the record, never re-executed**
        — their ``ObservationEntry`` trajectory is rebuilt from the journal and
        seeded here, so no recorded ``tool_called`` / ``tool_result`` pair repeats.

        The executor loop is *execute-then-reason*: each fresh Step executes a tool
        and only then reasons about whether to proceed. The reasoner's verb is
        **not** in the journal (``llm_call`` records only metadata), so it is not
        reconstructable and must be re-run. Resume therefore **reasons first** over
        the rebuilt Observations — the deferred "what next?" decision over the last
        recorded Step — and dispatches it (conclude -> done; revise -> the new Plan
        Step is the only pending one; continue -> walk the remaining plan), *then*
        drops into the same loop. This avoids the causality bug of executing the
        next Step before the reason call that authorizes it.

        Args:
            alert: The Alert under investigation (re-validated by the adapter).
            plan: The original ``InvestigationPlan`` (its Plan Steps index the
                remaining work; rebuilt from the journal's ``plan_created``).
            pre_observations: The Observation trajectory rebuilt from the journal,
                **one entry per executor Step** (the caller collapses a retried
                Step's multiple recorded results to its last attempt) — seeded as
                already-gathered evidence (reused, not re-run). ``step`` seeds the
                ``MAX_STEPS`` counter from this length.
            next_step_index: The index into ``plan.steps`` of the first *unexecuted*
                Plan Step (the count of completed executor Steps — not recorded
                result rows, which a retry would inflate). ``continue`` walks from
                here; ``revise`` discards it for the new step.

        Returns:
            An ``ExecutionResult`` whose trajectory includes the reused Observations
            plus any new ones — never raising on a tool or LLM failure.
        """
        observations = list(pre_observations)
        state = _LoopState(
            pending=list(plan.steps[next_step_index:]),
            observations=observations,
            attempted={(o.tool, _args_key(o.args)) for o in observations},
            guard_notes=[],
            step=len(observations),
        )

        # Reason first over the rebuilt Observations — the deferred decision the
        # killed Run never recorded. No fresh tool ran yet, so its first journal
        # line is ``llm_call(reason)``, never ``tool_called`` (the causality fix).
        try:
            decision = self._reason(
                alert=alert,
                observations=state.observations,
                guard_notes=state.guard_notes,
            )
        except LLMError:
            return ExecutionResult(observations=state.observations, terminated_reason="error")
        outcome = self._dispatch(decision, state.observations, pending=state.pending)
        if outcome.terminated is not None:
            return outcome.terminated
        state.pending = outcome.pending
        return self._loop(alert, state)

    def _loop(self, alert: Alert, state: _LoopState) -> ExecutionResult:
        """The shared ReAct walk — execute a Step, reason, dispatch, repeat.

        Shared by ``run`` (fresh, ``step=0``) and ``resume`` (seeded with the rebuilt
        Observations and the post-reason ``pending``). Each iteration executes the
        next Plan Step, then reasons and dispatches the decision.
        """
        while state.pending:
            if state.step >= self._max_steps:
                return ExecutionResult(
                    observations=state.observations,
                    terminated_reason="max_steps",
                )
            state.step += 1
            plan_step = state.pending.pop(0)
            self._execute_step(
                step=state.step,
                plan_step=plan_step,
                attempted=state.attempted,
                observations=state.observations,
                guard_notes=state.guard_notes,
            )
            try:
                decision = self._reason(
                    alert=alert,
                    observations=state.observations,
                    guard_notes=state.guard_notes,
                )
            except LLMError:
                return ExecutionResult(observations=state.observations, terminated_reason="error")
            outcome = self._dispatch(decision, state.observations, pending=state.pending)
            if outcome.terminated is not None:
                return outcome.terminated
            state.pending = outcome.pending

        # The plan (and every revision) was exhausted without a ``conclude``: the
        # gathered Observations stand as a completed trajectory for the verdict.
        return ExecutionResult(observations=state.observations, terminated_reason="completed")

    def _dispatch(
        self,
        decision: ReasonerDecision,
        observations: list[ObservationEntry],
        *,
        pending: list[PlanStep],
    ) -> _Dispatch:
        """Apply one Reasoner decision, returning either a terminal result or the next pending plan.

        * ``conclude`` -> terminal ``completed`` with the rationale.
        * ``revise_plan`` with a ``next_step`` -> that step replaces the remaining
          plan (emits ``plan_revised``); without one it is a degenerate revision
          (nothing to run next) and ends like a conclude.
        * ``continue`` -> the current ``pending`` is walked as-is.
        """
        if decision.decision == "conclude":
            return _Dispatch(
                terminated=ExecutionResult(
                    observations=observations,
                    terminated_reason="completed",
                    final_rationale=decision.rationale,
                ),
            )
        if decision.decision == "revise_plan" and decision.next_step is not None:
            self._journal.emit("plan_revised", {"steps": [decision.next_step.model_dump()]})
            return _Dispatch(pending=[decision.next_step])
        if decision.decision == "revise_plan":
            # ``revise_plan`` with no ``next_step`` is a degenerate revision —
            # there is nothing to run next, so the loop ends like a conclude.
            return _Dispatch(
                terminated=ExecutionResult(
                    observations=observations,
                    terminated_reason="completed",
                    final_rationale=decision.rationale,
                ),
            )
        return _Dispatch(pending=pending)  # ``continue`` — walk pending as-is.

    def _execute_step(
        self,
        *,
        step: int,
        plan_step: PlanStep,
        attempted: set[tuple[str, str]],
        observations: list[ObservationEntry],
        guard_notes: list[str],
    ) -> None:
        """Run one Plan Step, honouring the repeat-call guard.

        A duplicate tool+args pair is never executed: a guard note is recorded for
        the Reasoner (off the evidence trajectory) and no ``tool_called`` /
        ``tool_result`` is emitted for it. Otherwise the Tool runs via
        ``execute_tool``, whose callbacks emit the journal pair with a shared
        ``step`` + ``attempt``; an unknown tool name is converted to an ``ok=False``
        Observation rather than crashing.
        """
        key = (plan_step.tool, _args_key(plan_step.args))
        if key in attempted:
            guard_notes.append(
                f"Step {step}: refused to repeat the identical call "
                f"{plan_step.tool}({_args_key(plan_step.args)}) — choose a different "
                "tool or arguments, or conclude.",
            )
            return
        attempted.add(key)

        tool = self._resolve_tool(plan_step.tool)
        if tool is None:
            result = ToolResult(
                tool=plan_step.tool,
                ok=False,
                error=f"unknown tool '{plan_step.tool}' — not a registered investigation tool",
            )
            self._journal.emit(
                "tool_called",
                {"step": step, "tool": plan_step.tool, "args": dict(plan_step.args), "attempt": 1},
            )
            self._journal.emit(
                "tool_result",
                {"step": step, "attempt": 1, "ok": False, "error": result.error},
            )
        else:
            result = execute_tool(
                tool,
                plan_step.args,
                self._source,
                before_attempt=lambda attempt: self._journal.emit(
                    "tool_called",
                    {
                        "step": step,
                        "tool": plan_step.tool,
                        "args": dict(plan_step.args),
                        "attempt": attempt,
                    },
                ),
                after_attempt=lambda attempt, r: self._journal.emit(
                    "tool_result",
                    {"step": step, "attempt": attempt, "ok": r.ok}
                    | ({"data": r.data} if r.ok else {"error": r.error}),
                ),
            )
        observations.append(
            ObservationEntry(
                step=step,
                tool=plan_step.tool,
                args=dict(plan_step.args),
                result=result,
            ),
        )

    def _resolve_tool(self, name: str) -> Tool | None:
        """Return the registered Tool, or ``None`` for a hallucinated tool name."""
        try:
            return self._registry.get(name)
        except KeyError:
            return None

    def _reason(
        self,
        *,
        alert: Alert,
        observations: list[ObservationEntry],
        guard_notes: list[str],
    ) -> ReasonerDecision:
        """Ask the Reasoner what to do next; emit ``llm_call`` (purpose reason).

        Raises:
            LLMError: The reason call failed after retries + the repair attempt —
                propagated for ``run`` to convert to ``terminated_reason="error"``;
                nothing is emitted on that path (no ``Completion`` to journal).
        """
        messages = self._render(alert, observations, guard_notes)
        completion = self._llm.complete(messages, ReasonerDecision)
        self._journal.emit(
            "llm_call",
            {
                "purpose": "reason",
                "model": completion.model,
                "prompt_hash": completion.prompt_hash,
                "tokens": completion.tokens,
                "latency_ms": completion.latency_ms,
            },
        )
        return completion.value

    def _render(
        self,
        alert: Alert,
        observations: list[ObservationEntry],
        guard_notes: list[str],
    ) -> list[Message]:
        """Render the reasoner prompt into the single user message the LLM seam consumes.

        ``str.replace`` over labeled sentinels (never ``str.format``) because the
        alert payload and the Observations are JSON full of literal braces. Both
        the alert payload and the Observations land inside labeled untrusted blocks
        (ADR-0005): a tool Observation influences the next Step but is data, not an
        instruction.
        """
        content = (
            self._template.replace("{{TOOLS}}", self._render_tools())
            .replace("{{ALERT_PAYLOAD}}", self._render_alert(alert))
            .replace("{{OBSERVATIONS}}", self._render_observations(observations, guard_notes))
        )
        return [Message(role="user", content=content)]

    def _render_tools(self) -> str:
        """Render each tool spec as a stable, human-readable block."""
        return "\n\n".join(
            json.dumps(spec, sort_keys=True, ensure_ascii=False) for spec in self._registry.specs()
        )

    @staticmethod
    def _render_alert(alert: Alert) -> str:
        """Dump the whole alert (envelope + payload) as one untrusted JSON blob."""
        return json.dumps(alert.model_dump(), sort_keys=True, ensure_ascii=False, indent=2)

    @staticmethod
    def _render_observations(
        observations: list[ObservationEntry],
        guard_notes: list[str],
    ) -> str:
        """Render the Observation trajectory plus any guard notes for the Reasoner.

        The guard notes ride along here (so the Reasoner is forced to change course)
        but are deliberately absent from the persisted evidence trajectory — a
        refused duplicate is not an Observation.
        """
        blocks = [
            json.dumps(entry.model_dump(), sort_keys=True, ensure_ascii=False, indent=2)
            for entry in observations
        ]
        blocks.extend(guard_notes)
        return "\n\n".join(blocks)


def _args_key(args: Sequence[Any] | dict[str, Any]) -> str:
    """Return a stable string key for tool args, for the repeat-call guard.

    Canonical (``sort_keys``) so ``{"a": 1, "b": 2}`` and ``{"b": 2, "a": 1}``
    collide as the same call.
    """
    return json.dumps(args, sort_keys=True, ensure_ascii=False)
