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

from triage.constants import (
    COMPLETED,
    ERROR,
    EVT_LLM_CALL,
    EVT_PLAN_REVISED,
    EVT_TOOL_CALLED,
    EVT_TOOL_RESULT,
    MAX_STEPS,
    NO_PROGRESS,
    REVISE_EXHAUSTED,
)
from triage.errors import LLMError
from triage.models import (
    Alert,
    InvestigationPlan,
    PlanStep,
    ReasonerDecision,
    TerminatedReason,
    ToolResult,
)
from triage.rendering import (
    dump_alert,
    dump_compact,
    journal_llm_callbacks,
    observation_tag,
    render_guard_note,
    split_stable_dynamic,
    truncate,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from triage.journal import Journal
    from triage.llm import LLM, Message
    from triage.tools.base import DataSource, Tool
    from triage.tools.registry import ToolRegistry

from triage.tools.base import execute_tool

_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "reasoner.md"

_DEFAULT_MAX_STEPS = 15
_OBSERVATION_DATA_MAX_CHARS = 4000
_NO_PROGRESS_THRESHOLD = 6
"""K=6 consecutive ok=False observations trigger the no-progress backstop (RFC-0003 §Parameters).

A conservative fixed safety constant: the recorded all-miss trajectories run
3-4 failed steps before self-concluding, so K sits comfortably above that
while staying well below MAX_STEPS=15.  Counter is reset on any ok=True
observation; repeat-guard refusals do NOT advance it.
"""


def _truncate_data(serialized: str) -> str:
    """Truncate an oversized serialized observation data field for LLM rendering.

    Delegates to ``rendering.truncate`` — the single implementation shared with
    verdict.  The journal retains the full data; this helper affects only the
    LLM-facing render.
    """
    return truncate(serialized, _OBSERVATION_DATA_MAX_CHARS)


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
    without a long keyword-argument list:

    * ``pending`` — the plan steps still to walk.
    * ``observations`` — the gathered trajectory (pre-observations are already here
      on entry from ``run``).
    * ``attempted`` — the repeat-call-guard set (pre-observation tools already in
      here so the executor never re-executes them).
    * ``guard_notes`` — off-trajectory Reasoner nudges (not evidence).
    * ``step`` — the *step number* used for the next executor ``ObservationEntry``;
      starts at ``initial_step`` (the number of pre-observations so executor steps
      are numbered past the TI range) and increments before each tool call.  This
      counter is for **numbering only** and does NOT govern the ``MAX_STEPS`` guard.
    * ``budget_used`` — the executor loop's own step budget; always starts at 0 for
      a fresh ``run`` call (TI pre-observations do not consume ``MAX_STEPS`` —
      RFC-0002 §pre-step-0).  Seeded from ``len(pre_observations)`` on ``resume``
      (resumed steps do consume prior budget — the standard resume semantics).
    * ``consecutive_miss_count`` — the A2 fail-streak counter (reset on ok=True).
    """

    pending: list[PlanStep]
    observations: list[ObservationEntry]
    attempted: set[tuple[str, str]]
    guard_notes: list[str]
    step: int
    budget_used: int = 0
    consecutive_miss_count: int = 0


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

    def run(
        self,
        alert: Alert,
        plan: InvestigationPlan,
        *,
        initial_step: int = 0,
        pre_observations: list[ObservationEntry] | None = None,
    ) -> ExecutionResult:
        """Execute ``plan`` for ``alert`` and return the gathered Observations.

        Args:
            alert: The validated Alert under investigation (rendered untrusted).
            plan: The ``InvestigationPlan`` whose Plan Steps seed the loop.
            initial_step: The step counter offset when the loop starts.  Defaults
                to 0 (the fresh-run case where the loop increments to 1 before the
                first tool call).  The TI integration uses this to seed the counter
                past the TI pre-observations so executor steps do not collide with
                TI step numbers (RFC-0002 §pre-step-0 convention).
            pre_observations: Observations gathered before the plan loop (TI
                pre-observations).  These are prepended to the result trajectory and
                their tools are recorded in the repeat-call guard set so the executor
                never re-executes them.  Defaults to an empty list.

        Returns:
            An ``ExecutionResult`` with the Observation trajectory and the
            ``terminated_reason`` — never raising on a tool or LLM failure.
        """
        pre = pre_observations or []
        return self._loop(
            alert,
            _LoopState(
                pending=list(plan.steps),
                observations=list(pre),
                attempted={(o.tool, _args_key(o.args)) for o in pre},
                guard_notes=[],
                step=initial_step,  # step NUMBER starts past the TI range
                budget_used=0,  # TI pre-observations do not consume MAX_STEPS
            ),
        )

    def resume(
        self,
        alert: Alert,
        plan: InvestigationPlan,
        *,
        pre_observations: Sequence[ObservationEntry],
        next_step_index: int,
        executor_pre_count: int | None = None,
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
                step-numbering counter from this length.
            next_step_index: The index into ``plan.steps`` of the first *unexecuted*
                Plan Step (the count of completed executor Steps — not recorded
                result rows, which a retry would inflate). ``continue`` walks from
                here; ``revise`` discards it for the new step.
            executor_pre_count: The number of ``pre_observations`` entries that
                consumed the ``MAX_STEPS`` budget (i.e. executor-issued steps only,
                excluding TI pre-observations).  Defaults to ``len(pre_observations)``
                for a pure-executor resume; callers that mix TI + executor
                observations pass only the executor count so the resumed budget
                matches the fresh-run contract (TI never consumes ``MAX_STEPS``,
                RFC-0002 §pre-step-0).

        Returns:
            An ``ExecutionResult`` whose trajectory includes the reused Observations
            plus any new ones — never raising on a tool or LLM failure.
        """
        observations = list(pre_observations)
        n = len(observations)
        # Budget is executor steps only.  TI pre-observations are budget-free in
        # fresh runs (RFC-0002 §pre-step-0); the resumed contract must be symmetric.
        budget = executor_pre_count if executor_pre_count is not None else n
        state = _LoopState(
            pending=list(plan.steps[next_step_index:]),
            observations=observations,
            attempted={(o.tool, _args_key(o.args)) for o in observations},
            guard_notes=[],
            step=n,  # step NUMBER: next executor step is n+1
            budget_used=budget,  # resume: only executor steps consumed budget
        )

        # Reason first over the rebuilt Observations — the deferred decision the
        # killed Run never recorded. No fresh tool ran yet, so its first journal
        # line is ``llm_call(reason)``, never ``tool_called`` (the causality fix).
        try:
            decision = self._reason(
                alert=alert,
                observations=state.observations,
                guard_notes=state.guard_notes,
                pending=state.pending,
            )
        except LLMError:
            return ExecutionResult(observations=state.observations, terminated_reason=ERROR)
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
            if state.budget_used >= self._max_steps:
                return ExecutionResult(
                    observations=state.observations,
                    terminated_reason=MAX_STEPS,
                )
            state.budget_used += 1
            state.step += 1
            plan_step = state.pending.pop(0)
            self._execute_step(
                step=state.step,
                plan_step=plan_step,
                attempted=state.attempted,
                observations=state.observations,
                guard_notes=state.guard_notes,
            )
            # A2: track consecutive ok=False results and surface adapt notes.
            # Repeat-guard refusals do NOT advance this counter (RFC-0003 §Decision):
            # a refused step produces no Observation, so state.observations is unchanged
            # and the last entry's ok flag is whatever it was before the guard fired.
            # We detect a "new" observation by comparing against the step we just ran:
            # if the latest observation's step equals the current step, a tool ran.
            last_obs = state.observations[-1] if state.observations else None
            new_obs_this_step = last_obs is not None and last_obs.step == state.step
            if new_obs_this_step and not last_obs.result.ok:  # type: ignore[union-attr]
                state.consecutive_miss_count += 1
                obs = last_obs
                if state.consecutive_miss_count == 1:
                    detail = (
                        f"{obs.tool} failed for entity "
                        f"'{obs.args.get('entity', '?')}' ({obs.result.error}). "
                        "Adapt: try a different entity from the alert or a different tool."
                    )
                else:
                    detail = (
                        f"{obs.tool} failed for entity "
                        f"'{obs.args.get('entity', '?')}' ({obs.result.error}). "
                        f"This is the {state.consecutive_miss_count}th consecutive "
                        "failure. Do not retry similar lookups — pivot to an entity or "
                        "tool you have NOT tried yet (especially an unverified entity "
                        "type such as user identity). Conclude only when no relevant "
                        "untried tool/entity remains."
                    )
                note_kind = "miss_1" if state.consecutive_miss_count == 1 else "miss_n"
                state.guard_notes.append(render_guard_note(note_kind, state.step, detail))
                # No-progress backstop: K=6 consecutive ok=False observations
                # (RFC-0003 §Decision).  This fires AFTER emitting the adapt note so
                # the last note is still in the trajectory — but BEFORE the reason call
                # so no LLM token is spent on a provably-unrecoverable situation.
                if state.consecutive_miss_count >= _NO_PROGRESS_THRESHOLD:
                    return ExecutionResult(
                        observations=state.observations,
                        terminated_reason=NO_PROGRESS,
                    )
            elif new_obs_this_step:
                state.consecutive_miss_count = 0
            try:
                decision = self._reason(
                    alert=alert,
                    observations=state.observations,
                    guard_notes=state.guard_notes,
                    pending=state.pending,
                )
            except LLMError:
                return ExecutionResult(observations=state.observations, terminated_reason=ERROR)
            outcome = self._dispatch(decision, state.observations, pending=state.pending)
            if outcome.terminated is not None:
                return outcome.terminated
            state.pending = outcome.pending

        # The plan (and every revision) was exhausted without a ``conclude``: the
        # gathered Observations stand as a completed trajectory for the verdict.
        return ExecutionResult(observations=state.observations, terminated_reason=COMPLETED)

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
                    terminated_reason=COMPLETED,
                    final_rationale=decision.rationale,
                ),
            )
        if decision.decision == "revise_plan" and decision.next_step is not None:
            # 1-STEP REVISION INVARIANT: every ``plan_revised`` event carries exactly
            # one step (the single ``next_step`` the Reasoner proposed).  Resume
            # depends on this: ``journal.rebuild`` counts ``tool_result`` events after
            # the last ``plan_revised`` to compute ``steps_after_last_revision``, then
            # ``core.resume_investigation`` indexes into the revision's step list by
            # that count.  A multi-step revision would mean the count is no longer a
            # valid index — do not change this without updating the rebuild and resume
            # logic together.
            self._journal.emit(EVT_PLAN_REVISED, {"steps": [decision.next_step.model_dump()]})
            return _Dispatch(pending=[decision.next_step])
        if decision.decision == "revise_plan":
            # ``revise_plan`` with no ``next_step`` is a degenerate revision —
            # there is nothing to run next.  This terminates with ``revise_exhausted``
            # (RFC-0003 §Decision) instead of laundering into ``completed``, so
            # callers can distinguish "investigation concluded" from "planner gave up".
            return _Dispatch(
                terminated=ExecutionResult(
                    observations=observations,
                    terminated_reason=REVISE_EXHAUSTED,
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
            detail = (
                f"refused to repeat the identical call "
                f"{plan_step.tool}({_args_key(plan_step.args)}) — choose a different "
                "tool or arguments, or conclude."
            )
            guard_notes.append(render_guard_note("repeat_guard", step, detail))
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
                EVT_TOOL_CALLED,
                {"step": step, "tool": plan_step.tool, "args": dict(plan_step.args), "attempt": 1},
            )
            self._journal.emit(
                EVT_TOOL_RESULT,
                {"step": step, "attempt": 1, "ok": False, "error": result.error},
            )
        else:
            result = execute_tool(
                tool,
                plan_step.args,
                self._source,
                before_attempt=lambda attempt: self._journal.emit(
                    EVT_TOOL_CALLED,
                    {
                        "step": step,
                        "tool": plan_step.tool,
                        "args": dict(plan_step.args),
                        "attempt": attempt,
                    },
                ),
                after_attempt=lambda attempt, r: self._journal.emit(
                    EVT_TOOL_RESULT,
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
        pending: list[PlanStep],
    ) -> ReasonerDecision:
        """Ask the Reasoner what to do next; emit ``llm_call`` (purpose reason).

        Raises:
            LLMError: The reason call failed after retries + the repair attempt —
                propagated for ``run`` to convert to ``terminated_reason="error"``;
                nothing is emitted on that path (no ``Completion`` to journal).
        """
        messages = self._render(alert, observations, guard_notes, pending)
        purpose = "reason"
        on_transport_retry, on_repair = journal_llm_callbacks(self._journal, purpose)
        completion = self._llm.complete(
            messages,
            ReasonerDecision,
            on_transport_retry=on_transport_retry,
            on_repair=on_repair,
        )
        self._journal.emit(
            EVT_LLM_CALL,
            {
                "purpose": purpose,
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
        pending: list[PlanStep],
    ) -> list[Message]:
        """Render the reasoner prompt as two messages: stable prefix + dynamic data.

        The stable message (instructions + tools) is identical across all reason
        calls within the session, allowing the API to cache it. The dynamic message
        carries the per-call alert, observations, remaining steps, and task
        instruction. ``{{END_OF_STABLE}}`` in the template marks the split point.
        ``str.replace`` over labeled sentinels (never ``str.format``) because the
        alert payload and the Observations are JSON full of literal braces.
        """
        rendered = (
            self._template.replace("{{TOOLS}}", self._render_tools())
            .replace("{{ALERT_PAYLOAD}}", self._render_alert(alert))
            .replace("{{OBSERVATIONS}}", self._render_observations(observations, guard_notes))
            .replace("{{REMAINING_STEPS}}", self._render_pending(pending))
        )
        return split_stable_dynamic(rendered)

    def _render_tools(self) -> str:
        """Render each tool spec as a stable, human-readable block."""
        return "\n\n".join(
            json.dumps(spec, sort_keys=True, ensure_ascii=False) for spec in self._registry.specs()
        )

    @staticmethod
    def _render_alert(alert: Alert) -> str:
        """Dump the whole alert (envelope + payload) as one untrusted JSON blob."""
        return dump_alert(alert)

    @staticmethod
    def _render_pending(pending: list[PlanStep]) -> str:
        """Render the queued-but-not-yet-executed Plan Steps for the Reasoner."""
        if not pending:
            return "(no further steps are planned — all planned steps have been executed)"
        return "\n\n".join(dump_compact(step.model_dump()) for step in pending)

    @staticmethod
    def _render_observations(
        observations: list[ObservationEntry],
        guard_notes: list[str],
    ) -> str:
        """Render the Observation trajectory plus any guard/adapt notes for the Reasoner.

        Each observation is emitted as a single ``<observation>`` XML tag carrying
        step, tool, and ok as attributes; the rest of the data is compact JSON
        inside the tag body, with oversized data fields truncated at
        ``_OBSERVATION_DATA_MAX_CHARS``. Guard and adapt notes (wrapped in
        ``<guard_note>`` tags by the caller) ride along here but are deliberately
        absent from the persisted evidence trajectory — a refused duplicate or a
        tool-miss note is not an Observation.
        """
        blocks: list[str] = []
        for entry in observations:
            data = entry.model_dump()
            result = data.pop("result", {})
            ok_val = result.get("ok", False)
            inner: dict[str, object] = {"step": entry.step, "args": entry.args}
            if ok_val:
                raw = dump_compact(result.get("data"))
                inner["data"] = _truncate_data(raw)
            else:
                inner["error"] = result.get("error")
            body = dump_compact(inner)
            blocks.append(observation_tag(entry.step, entry.tool, ok_val, body))
        blocks.extend(guard_notes)
        return "\n\n".join(blocks)


def _args_key(args: Sequence[Any] | dict[str, Any]) -> str:
    """Return a stable string key for tool args, for the repeat-call guard.

    Canonical (``sort_keys``) so ``{"a": 1, "b": 2}`` and ``{"b": 2, "a": 1}``
    collide as the same call.
    """
    return json.dumps(args, sort_keys=True, ensure_ascii=False)
