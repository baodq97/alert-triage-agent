"""The transport-agnostic core entrypoint — ``triage(alert, deps)`` (RFC-0001 §Core loop).

One Run, start to finish, with no transport assumptions: ``triage`` plans the
investigation, executes it, synthesizes a Verdict, enforces the deterministic
verdict-safety checks in code, runs the single Approval Gate, executes any
approved High-risk Action batch, and returns the versioned ``RunResult``. Nothing
imports ``run.py``; the adapters (``--alert`` CLI, later ``--watch`` /
``--resume``) live there and call this. ``triage`` never crashes (US-0001): every
failure mode either degrades deterministically or is converted to a
``terminated_reason``.

Flow (RFC-0001 §Core loop / triage-conventions):

1. ``run_started`` — ``alert_id`` + the run ``config`` + ``schema_version``.
2. **Plan.** A planner ``LLMError`` means the plan never happened: execution is
   skipped and the Run takes the degraded path — synthesize from no material with
   ``terminated_reason="error"`` (``VerdictSynthesizer`` cannot raise). Otherwise
   the executor walks the plan and returns its Observation trajectory +
   ``terminated_reason`` (``completed`` | ``max_steps`` | ``error``).
3. **Synthesize.** The executor's ``ObservationEntry`` list is adapted to the
   verdict seam (``[entry.result for entry in observations]``) and the upstream
   ``terminated_reason`` is passed through — it is a code-owned fact, never an LLM
   judgment.
4. **Target-entity invariant (deterministic, in code).** The invariant applies
   only to *targeted* Response Actions: a targeted Action whose target is absent
   (malformed) or is not an Alert Entity value is *rejected before the gate*, each
   with its true reason. An *untargeted* advisory action has no target to validate
   and passes through to the gate untouched. Rejections are recorded observably
   (``action_rejected`` event — strictly pre-gate) and never reach the gate. The
   shipped Verdict keeps its full ``recommended_actions`` (the invariant is
   downstream enforcement, not a verdict mutation); only the *accepted* actions are
   offered to the gate.
5. **Gate.** ONE gate per Run over the accepted actions. ``None`` (Zero-touch — no
   High-risk Action) ships the Verdict untouched; a decision is recorded.
6. **Execute.** On ``approved``, the High-risk batch executes (mock Response
   Actions) and each emits ``action_executed``; an approved Action with no executor
   (a capability gap, not a denial) emits ``action_skipped`` instead — strictly
   post-gate, never ``action_rejected``. On ``denied``, nothing executes; the
   Verdict still ships.
7. ``run_terminated`` — the single ``reason`` derived in step 2.

``awaiting_approval`` (wave 2): when the Run's gate cannot resolve in-process (a
``DeferredGate`` — the asynchronous-HITL seam the watch adapter wires), ``request``
returns the ``HOLD`` sentinel. ``triage`` then parks the Run: ``gate_requested`` was
emitted, NO ``gate_decision`` follows, ``run_terminated(reason="awaiting_approval")``
is emitted, and the ``RunResult`` carries ``terminated_reason="awaiting_approval"``
with empty ``gate_decisions`` / ``executed_actions`` — the pending state ``--resume
--approve|--deny`` completes. The Verdict's own ``terminated_reason`` stays the
*investigation* reason (``completed``), not the run-level park — so the post-approve
``RunResult`` rebuilt from the ``verdict`` event is naturally consistent.

**Resume (wave 2, US-0002):** three reader-side entrypoints rebuild state from
``runs/<run_id>/journal.jsonl`` (via ``journal.rebuild``) and continue the Run —
*never* re-emitting ``run_started`` (the reopened journal already has it and just
continues ``seq``):

* ``resume_investigation`` — an interrupted Run (no ``run_terminated`` recorded):
  the rebuilt Observations seed ``Executor.resume`` (completed Tool Steps reused
  from the record, never re-executed; the reasoner is re-run because its verb was
  never journaled), then the shared run *tail* synthesizes the Verdict, gates, and
  terminates.
* ``resume_approve`` / ``resume_deny`` — a pending Run (``awaiting_approval``):
  emit the deferred ``gate_decision`` and, on approve, execute the High-risk batch
  **idempotently** — per Action, execute only if no ``action_executed`` already
  exists for it (check -> execute -> record), so a kill between execute and record
  reuses the recorded result and never double-executes (US-0002 AC6). The Verdict
  still ships on deny.

**JournalError containment (wave 2):** ``emit`` can raise ``JournalError`` mid-Run
and no inner caller catches it — colliding with "a Run never crashes / always ships
a Verdict". ``triage`` catches it at this single boundary, degrades to a partial
Verdict with ``terminated_reason="error"``, and makes a best-effort final
``run_terminated`` emit (swallowing a secondary journal failure there). The CLI is
already safe via its ``TriageError`` catch; this closes the in-``triage`` gap.
"""

from __future__ import annotations

import contextlib
import json
import os
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from triage.errors import GateError, JournalError, LLMError
from triage.executor import Executor, ObservationEntry
from triage.gate import is_hold
from triage.models import (
    Action,
    GateDecision,
    InvestigationPlan,
    PlanStep,
    RunResult,
    ToolResult,
    Verdict,
)
from triage.planner import Planner
from triage.threat_intel import TIToolRegistry, classify_ioc, enrich
from triage.tools.actions import block_user, block_user_target, is_targeted
from triage.verdict import DEGRADED_CONFIDENCE, DEGRADED_SEVERITY, VerdictSynthesizer

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from triage.gate import ApprovalGate, GateOutcome, RiskPolicy
    from triage.journal import Journal, ReconstructedRun, StepObservation
    from triage.llm import LLM
    from triage.memory import MemoryStore
    from triage.models import (
        Alert,
        TerminatedReason,
    )
    from triage.tools.base import DataSource
    from triage.tools.registry import ToolRegistry

SCHEMA_VERSION = 1
"""The run-record schema version stamped on ``run_started`` (lives only in the event)."""

# The wave-1 Response Action dispatch table: the only executable action is
# ``block_user`` (the single shipped Response Action). The post-gate flow only
# ever executes an approved High-risk batch, and a Verdict's actions are
# target-checked first, so an unmapped name cannot reach here in wave 1.
_ACTION_EXECUTORS: dict[str, Callable[[Action], dict[str, object]]] = {
    "block_user": block_user,
}

# Maximum number of TI enrichments per run — bounds the mini-loop token cost
# (RFC-0002 §Open questions: "fixed small step cap").  Two covers the common
# case of one public IP + one domain in an alert without runaway cost.
_TI_MAX_ENRICHMENTS = 2


def _ti_enabled_from_env() -> bool:
    """Read ``TI_ENABLED`` from the env; default is ``False`` (absent-by-default).

    Truthy values: ``"1"``, ``"true"``, ``"yes"`` (case-insensitive).  Any other
    non-empty string or an absent var is treated as disabled — matching the
    ``MAX_STEPS`` / ``MEMORY_SYNTHESIZE_EVERY_N_RUNS`` parse pattern of falling
    back rather than crashing the run at construction time.
    """
    raw = os.environ.get("TI_ENABLED", "").strip().lower()
    return raw in {"1", "true", "yes"}


@dataclass(frozen=True)
class TriageDeps:
    """The explicit, frozen dependency bundle one Run is wired from.

    Leaf collaborators only (``models``-level seams): ``triage`` constructs the
    ``Planner`` / ``Executor`` / ``VerdictSynthesizer`` itself, so the adapter in
    ``run.py`` builds only the leaves and never reaches into the loop. ``max_steps``
    overrides the executor's ``MAX_STEPS`` guard (env / default 15 otherwise) —
    the seam the breach test drives cheaply.

    ``memory`` is the entity-scoped Memory Store (RFC-0001 §Memory) — an optional
    leaf collaborator. When present it is recalled into the planner context (recall
    is untrusted, informs-never-dictates) and atoms are persisted at verdict time.
    ``None`` (the deterministic-suite default) keeps the loop memory-free: no recall
    block, no store writes — behavior identical to before the seam was wired. A
    memory failure never crashes a Run (the store swallows its own IO faults), so no
    new ``try/except`` is needed at this boundary.

    ``ti_enabled`` is an explicit per-deps override for the TI enrichment flag
    (RFC-0002 §per-case TI wiring).  ``None`` (the default) falls back to the
    ``TI_ENABLED`` env var (current behavior; default off).  ``True`` or ``False``
    overrides the env var for that Run — the seam that eval cases use so parallel
    replay runs do not race on a process-global env mutation.  All existing callers
    that pass no ``ti_enabled`` are byte-identical: ``None`` → env read → same path.
    """

    llm: LLM
    journal: Journal
    registry: ToolRegistry
    source: DataSource
    gate: ApprovalGate
    policy: RiskPolicy
    max_steps: int | None = field(default=None)
    memory: MemoryStore | None = field(default=None)
    ti_enabled: bool | None = field(default=None)


def triage(alert: Alert, deps: TriageDeps, *, run_id: str | None = None) -> RunResult:
    """Run one Alert through the full triage loop and return its ``RunResult``.

    Args:
        alert: The validated Alert envelope+payload under investigation.
        deps: The frozen dependency bundle (LLM, journal, registry, source, gate,
            policy, optional ``max_steps``).
        run_id: The Run's identity. The adapter (``run.py``) mints it once and uses
            the *same* id for the ``JsonlJournal`` directory (``runs/<run_id>``) and
            this call, so ``journal.jsonl`` and ``result.json`` land together; a
            ``JsonlJournal`` needs the run dir *before* ``triage`` runs (to emit
            ``run_started``), so the id cannot originate inside ``triage`` once the
            journal is real. Defaults to an internally-minted ``uuid4`` so existing
            callers (and the deterministic suite) are untouched — run_id is Run
            *identity*, not a collaborator, so it is a keyword param, not a
            ``TriageDeps`` field.

    Returns:
        The versioned ``RunResult`` — verdict, gate decisions, executed actions,
        run id, terminated reason. Never raises: a planner failure degrades to a
        partial verdict, tool/LLM failures convert to a ``terminated_reason``, and
        the gate decision either way still ships the verdict.
    """
    if run_id is None:
        run_id = str(uuid.uuid4())
    try:
        deps.journal.emit(
            "run_started",
            {
                "alert_id": alert.alert_id,
                "config": {"max_steps": deps.max_steps},
                "schema_version": SCHEMA_VERSION,
            },
        )
        observation_entries, terminated_reason = _investigate(alert, deps)
        return _conclude_run(alert, deps, observation_entries, terminated_reason, run_id=run_id)
    except JournalError:
        return _degraded_on_journal_error(deps, run_id)


def _degraded_on_journal_error(deps: TriageDeps, run_id: str) -> RunResult:
    """Contain a mid-Run ``JournalError`` into a partial Verdict (US-0001).

    ``emit`` is the only inner call that raises ``JournalError`` and no inner caller
    catches it; ``triage`` is the single boundary that does (triage-conventions
    typed-errors seam). A failure can land *before* any Verdict exists (e.g. on
    ``run_started``), so a degraded Verdict is built directly here — never routed
    through the synthesizer, whose own ``verdict`` emit could re-raise. A Verdict
    always ships regardless of where the journal broke.
    """
    verdict = Verdict(
        severity=DEGRADED_SEVERITY,
        findings=[],
        recommended_actions=[],
        confidence=DEGRADED_CONFIDENCE,
        terminated_reason="error",
    )
    _best_effort_terminate(deps.journal, "error")
    return RunResult(
        run_id=run_id,
        verdict=verdict,
        gate_decisions=[],
        executed_actions=[],
        terminated_reason="error",
    )


def _best_effort_terminate(journal: Journal, reason: TerminatedReason) -> None:
    """Emit a final ``run_terminated`` on the degraded path, swallowing a re-failure.

    The journal is already known-broken here (the containment branch), so a second
    ``JournalError`` from this emit is expected and ignored — the in-memory
    ``RunResult`` still ships (a Run never crashes).
    """
    # The journal is already known-broken; a secondary JournalError here has no
    # recovery left and is deliberately suppressed (the in-memory RunResult ships).
    with contextlib.suppress(JournalError):
        journal.emit("run_terminated", {"reason": reason})


def _conclude_run(
    alert: Alert,
    deps: TriageDeps,
    observation_entries: list[ObservationEntry],
    terminated_reason: TerminatedReason,
    *,
    run_id: str,
) -> RunResult:
    """The shared run *tail*: synthesize the Verdict, gate, and terminate.

    Reused by ``triage`` (fresh) and ``resume_investigation`` (interrupted Run) — it
    never emits ``run_started`` (the reopened journal already has it). On a ``HOLD``
    gate outcome the Run parks as ``awaiting_approval``: ``gate_requested`` was
    emitted by the gate, no ``gate_decision`` follows, and the run-level
    ``terminated_reason`` becomes ``awaiting_approval`` while the Verdict keeps its
    investigation reason.

    ``observation_entries`` carries the full ``ObservationEntry`` list so the verdict
    renderer can use real executor step numbers (``entry.step``) instead of
    re-deriving them from position — preserving step fidelity when guard-refused
    steps create numbering gaps in the journal.
    """
    synthesizer = VerdictSynthesizer(llm=deps.llm, journal=deps.journal)
    verdict = synthesizer.synthesize(
        alert,
        observations=[entry.result for entry in observation_entries],
        observation_steps=[entry.step for entry in observation_entries],
        terminated_reason=terminated_reason,
    )
    # Persist L1 atoms at verdict time (RFC-0001 §Memory: "finding atoms persisted at
    # verdict time"). The guard is presence-only — any synthesized Verdict persists,
    # degraded or not: atoms are per-(entity, finding), so a degraded-but-with-findings
    # Verdict (e.g. a ``max_steps`` partial that still carried Findings through) writes
    # its atoms, while an empty-findings Verdict no-ops in the store. This is the single
    # persist point shared by ``triage`` (fresh) and ``resume_investigation`` (both
    # funnel here); ``resume_approve`` / ``resume_deny`` never reach this tail, so a
    # parked Run's Verdict (persisted here before it parked) is never re-persisted. The
    # store is best-effort (swallows its own IO faults) — it cannot crash the Run.
    if deps.memory is not None:
        deps.memory.persist(run_id, alert, verdict)
    accepted = _accept_actions(alert, verdict.recommended_actions, deps.journal)
    outcome = deps.gate.request(accepted, deps.policy)
    if is_hold(outcome):
        deps.journal.emit("run_terminated", {"reason": "awaiting_approval"})
        return RunResult(
            run_id=run_id,
            verdict=verdict,
            gate_decisions=[],
            executed_actions=[],
            terminated_reason="awaiting_approval",
        )
    decision = _as_decision(outcome)
    gate_decisions, executed = _resolve_gate(decision, accepted, deps)
    deps.journal.emit("run_terminated", {"reason": terminated_reason})
    return RunResult(
        run_id=run_id,
        verdict=verdict,
        gate_decisions=gate_decisions,
        executed_actions=executed,
        terminated_reason=terminated_reason,
    )


def _enrich_iocs(alert: Alert, deps: TriageDeps) -> list[ObservationEntry]:
    """Run TI enrichment for external IOCs in the alert entities (RFC-0002).

    Iterates ``alert.entities``, classifies each value with the deterministic
    ``classify_ioc`` function, and calls ``enrich()`` for up to
    ``_TI_MAX_ENRICHMENTS`` external IOCs (deduped by value).  Each enrichment
    result is wrapped as one ``ObservationEntry`` with ``tool="threat_intel.enrich"``,
    ``args={"ioc": value, "type": ioc_type}``, and a ``ToolResult`` whose ``data``
    is the serialised ``TIReport`` (or ``ok=False`` when ``enrich`` returns ``None``).

    Journal discipline (RFC-0002 §Journal):
    * The TI mini-loop's own events (``tool_called`` / ``tool_result`` /
      ``llm_call`` for TI tools) carry ``agent="threat-intel"`` — emitted inside
      ``enrich()``.
    * The wrapping ``tool_called`` / ``tool_result`` pair that records each
      enrichment as an executor Observation carries ``agent="triage"`` — the
      primary loop consumed the result.  This is what gives the "hierarchical
      trace in one stream" property (US-0005 AC3).

    Step numbers start at 1 and are assigned in enrichment order.  The executor
    is later started with ``initial_step=len(result)`` so its steps begin past
    the TI range and never collide.

    TI enrichment is best-effort: ``enrich()`` never propagates an exception
    (it swallows ``LLMError`` internally); a fixture miss degrades to an
    ``ok=False`` observation.  A TI fault never crashes the primary Run.
    """
    registry = TIToolRegistry()
    seen: set[str] = set()
    entries: list[ObservationEntry] = []

    for _entity_type, entity_value in alert.entities.items():
        if not isinstance(entity_value, str):
            continue
        if entity_value in seen:
            continue
        ioc_type = classify_ioc(_entity_type, entity_value)
        if ioc_type is None:
            continue
        seen.add(entity_value)
        step = len(entries) + 1
        args: dict[str, object] = {"ioc": entity_value, "type": ioc_type}

        # Emit the primary-loop wrapper pair (agent="triage") before delegation.
        deps.journal.emit(
            "tool_called",
            {"step": step, "tool": "threat_intel.enrich", "args": args, "attempt": 1},
        )
        report = enrich(
            ioc_type, entity_value, llm=deps.llm, journal=deps.journal, registry=registry
        )
        if report is not None:
            result = ToolResult(
                tool="threat_intel.enrich",
                ok=True,
                data=report.model_dump(),
            )
            deps.journal.emit(
                "tool_result",
                {"step": step, "attempt": 1, "ok": True, "data": result.data},
            )
        else:
            result = ToolResult(
                tool="threat_intel.enrich",
                ok=False,
                error="TI enrichment failed",
            )
            deps.journal.emit(
                "tool_result",
                {"step": step, "attempt": 1, "ok": False, "error": result.error},
            )
        entries.append(
            ObservationEntry(step=step, tool="threat_intel.enrich", args=dict(args), result=result)
        )
        if len(entries) >= _TI_MAX_ENRICHMENTS:
            break

    return entries


def _investigate(alert: Alert, deps: TriageDeps) -> tuple[list[ObservationEntry], TerminatedReason]:
    """Plan and execute, returning the ObservationEntry list and the terminated reason.

    A planner ``LLMError`` means the plan never happened: execution is skipped and
    the reason is ``"error"`` with no gathered material. Otherwise the executor's
    ``ObservationEntry`` trajectory carries through — including each entry's real
    ``step`` number — so the verdict renderer can use the journal-faithful step
    attributes rather than re-deriving them from position.

    When ``TI_ENABLED`` is truthy (env) OR ``deps.ti_enabled`` is ``True``,
    external IOCs in the alert entities are enriched **before** the plan loop runs
    (RFC-0002 §pre-step-0).  ``deps.ti_enabled`` takes precedence over the env var
    so parallel eval threads can set per-Run TI posture without racing on a
    process-global env mutation.  The TI observations use steps 1..K; the executor
    loop starts at step K+1 via ``initial_step``.  TI enrichment does NOT consume
    the ``MAX_STEPS`` budget.
    """
    # TI enrichment — pre-step-0, before planning and outside the MAX_STEPS budget
    # (RFC-0002 §pre-step-0).  Runs first so the planner can see TI observations in
    # the FakeLLM script order and so the executor pre-seeds its trajectory.
    # ``deps.ti_enabled`` is the explicit override (not None → use it directly);
    # None → fall back to the env var (byte-identical for all existing callers).
    ti_on = deps.ti_enabled if deps.ti_enabled is not None else _ti_enabled_from_env()
    ti_observations: list[ObservationEntry] = _enrich_iocs(alert, deps) if ti_on else []

    planner = Planner(llm=deps.llm, journal=deps.journal, tool_specs=deps.registry.specs())
    # Recall is entity-scoped and best-effort (the store never raises); ``None`` when
    # no Memory Store is wired keeps the planner prompt memory-free. Recall feeds the
    # plan call ONLY — ``resume_investigation`` reuses the journaled plan and never
    # re-plans, so there is no recall to wire there.
    recall = deps.memory.recall(alert) if deps.memory is not None else None
    try:
        plan = planner.plan(alert, recall=recall)
    except LLMError:
        return ti_observations, "error"

    executor = Executor(
        llm=deps.llm,
        journal=deps.journal,
        registry=deps.registry,
        source=deps.source,
        max_steps=deps.max_steps,
    )
    execution = executor.run(
        alert,
        plan,
        initial_step=len(ti_observations),
        pre_observations=ti_observations,
    )
    return execution.observations, execution.terminated_reason


def _accept_actions(
    alert: Alert,
    actions: Sequence[Action],
    journal: Journal,
) -> list[Action]:
    """Return the actions that satisfy the target-entity invariant; reject the rest.

    The target-entity invariant applies *only to targeted* Response Actions
    (triage-conventions §Target invariant) — "no target" and "invalid target" are
    distinct, never conflated:

    * **Untargeted** action (``is_targeted`` is ``False``, e.g. an advisory
      ``notify_soc``) — no target to validate; it passes through to the Risk Policy
      / gate untouched.
    * **Targeted, target absent** (a *malformed* ``block_user`` with no ``user``
      param) — its target cannot be validated, so it is rejected with reason
      ``"missing required target"``.
    * **Targeted, target present but not an Alert Entity value** — rejected with
      reason ``"target is not an alert entity"``.
    * **Targeted, target is an Alert Entity value** — accepted.

    Each rejection is recorded observably via an ``action_rejected`` event (true
    reason per case) so a dropped action is never silent. Membership uses ``==``
    over ``alert.entities.values()`` (never a ``set`` — a payload value may be
    unhashable, and the Run must never crash).
    """
    entity_values = list(alert.entities.values())
    accepted: list[Action] = []
    for action in actions:
        if not is_targeted(action):
            accepted.append(action)  # no target to validate — straight to the gate
            continue
        target = block_user_target(action)
        if target is None:
            reason = "missing required target"
        elif target not in entity_values:
            reason = "target is not an alert entity"
        else:
            accepted.append(action)
            continue
        journal.emit(
            "action_rejected",
            {"action": action.model_dump(), "reason": reason},
        )
    return accepted


def _as_decision(outcome: GateOutcome) -> GateDecision | None:
    """Narrow a non-``HOLD`` gate outcome to ``GateDecision | None`` for the resolver.

    ``_conclude_run`` handles ``HOLD`` before calling this, so the outcome here is
    only a resolved ``GateDecision`` (approved / denied) or ``None`` (Zero-touch).
    Returning ``None`` for anything else keeps the resolver's type honest without a
    cast; a ``_Hold`` reaching here would be a caller bug.
    """
    return outcome if isinstance(outcome, GateDecision) else None


def _dispatch_action(action: Action, deps: TriageDeps) -> Action | None:
    """Execute one approved Action and emit its journal event; return it or ``None``.

    The single post-gate dispatch helper shared by ``_resolve_gate`` and
    ``_execute_one``: an action with a registered executor runs and emits
    ``action_executed``; one without emits ``action_skipped`` (a capability gap, not
    a denial) and returns ``None``.  This is the single source of truth for the
    post-gate emit pattern — neither ``_resolve_gate`` nor ``_execute_one`` duplicate
    it.
    """
    executor = _ACTION_EXECUTORS.get(action.name)
    if executor is None:
        deps.journal.emit(
            "action_skipped",
            {"action": action.model_dump(), "reason": "no executor for action"},
        )
        return None
    result = executor(action)
    deps.journal.emit("action_executed", {"action": action.model_dump(), "result": result})
    return action


def _resolve_gate(
    decision: GateDecision | None,
    accepted: Sequence[Action],
    deps: TriageDeps,
) -> tuple[list[GateDecision], list[Action]]:
    """Record the gate decision and execute the approved High-risk batch.

    ``None`` is a Zero-touch Run (no High-risk Action): no decision, nothing
    executed. ``denied`` records the decision; the Verdict still ships. ``approved``
    executes the High-risk Actions (the gate already batched only those), each
    emitting ``action_executed``.

    An *approved* High-risk Action with no Response-Action executor (an untargeted
    advisory action that reached the gate, then was approved) is recorded via
    ``action_skipped`` — a distinct, post-gate event — and *not* executed. This is
    deliberately NOT ``action_rejected``: ``action_rejected`` is strictly the
    *pre-gate* target-entity invariant (a denied-by-code action a human never saw),
    whereas ``action_skipped`` is an *approved* action the code cannot carry out (a
    capability gap a human did see and approve). Keeping them distinct lets a
    consumer tell "denied" from "approved-but-unexecutable" by event name, not by
    string-matching a free-text reason — so ``action_rejected`` can never follow a
    ``gate_decision``, and an approved action is always either ``action_executed``
    XOR ``action_skipped``. The dispatch table holds only the shipped executable
    Response Actions, so the Run never crashes on a missing executor (US-0001:
    ``triage`` never crashes). When advisory actions become executable, add them to
    ``_ACTION_EXECUTORS``.
    """
    if decision is None:
        return [], []
    if decision.decision == "denied":
        return [decision], []
    executed: list[Action] = []
    for action in deps.policy.high_risk(accepted):
        dispatched = _dispatch_action(action, deps)
        if dispatched is not None:
            executed.append(dispatched)
    return [decision], executed


def resume_investigation(
    alert: Alert,
    deps: TriageDeps,
    reconstructed: ReconstructedRun,
    *,
    run_id: str,
) -> RunResult:
    """Continue an interrupted Run from its rebuilt state (US-0002 AC3).

    Precondition: the Run was killed mid-investigation — ``reconstructed`` has no
    ``run_terminated`` (``is_interrupted()``). The reopened journal (passed in via
    ``deps.journal``) already holds ``run_started`` and the recorded Tool Steps, so
    this NEVER re-emits ``run_started`` and continues ``seq``.

    What is **reused from the record vs re-run** (the resume contract):

    * **Tool Steps — reused.** Each recorded ``tool_result`` rebuilt into an
      ``ObservationEntry`` is seeded into ``Executor.resume`` as already-gathered
      evidence, so no recorded ``tool_called`` / ``tool_result`` pair repeats — the
      completed work is never re-executed.
    * **Reasoner — re-run.** The reasoner's verb (``continue`` / ``revise`` /
      ``conclude``) is *not* in the journal (``llm_call`` records only metadata), so
      it is not reconstructable; ``Executor.resume`` re-fires the deferred reason
      call over the rebuilt Observations with fresh LLM reasoning.
    * **Plan revisions — honoured.** When ``plan_revisions`` is non-empty, the
      remaining work is rebuilt from the *last revision's* steps indexed by the
      steps executed after that revision — so a kill-after-revision resumes on the
      revised step, not on the original plan's next step.  The original plan is used
      only when no revision was recorded (the common linear case).

    The investigation then continues into the shared run tail (synthesize -> gate ->
    terminate), so a resumed Run reaches a Verdict exactly as a fresh one does.

    Raises:
        GateError: The Run is not interrupted (it already terminated or is pending)
            — resuming an investigation that is not mid-flight is a misuse.
    """
    if not reconstructed.is_interrupted():
        msg = (
            f"cannot resume investigation of run {run_id}: it is not interrupted "
            f"(terminated_reason={reconstructed.terminated_reason!r})"
        )
        raise GateError(msg)
    # Collapse the rebuilt Observations to ONE per executor Step: a transient tool
    # retry records two ``tool_result`` events (two ``StepObservation`` rows) for a
    # single Step (cf. AC2 retry visibility), and the executor keeps one Observation
    # per Step. Last attempt wins (the recovered result, never the failed attempt),
    # and ``next_step_index`` is the count of *Steps* consumed — never the row count,
    # which a retry would inflate, silently dropping a remaining Plan Step.
    #
    # F1/F2 fix (US-0005 QA): the journal rebuild now filters by agent="triage", so
    # ``reconstructed.observations`` contains both TI wrapper observations
    # (tool="threat_intel.enrich", agent="triage") and executor step observations.
    # We must separate them so (a) ``next_step_index`` counts only executor steps
    # (not TI wrappers) and (b) ``budget_used`` in the executor mirrors the fresh-run
    # contract where TI observations are budget-free (RFC-0002 §pre-step-0).
    by_step = {obs.step: obs for obs in reconstructed.observations}
    pre_observations = [_rebuild_observation(by_step[step]) for step in sorted(by_step)]
    # Count observations that are TI wrapper entries vs executor-issued steps.
    # TI wrappers are identified by tool name ("threat_intel.enrich") — the only
    # tool the primary loop emits before the executor runs (pre-step-0 contract).
    executor_pre_count = sum(1 for obs in pre_observations if obs.tool != "threat_intel.enrich")
    # Resume-after-revision: when the executor revised the plan mid-run, the last
    # recorded ``plan_revised`` steps replace the original plan for the remaining
    # work.  The executor's ``revise_plan`` dispatch replaces pending with exactly
    # one step, so each revision record in ``plan_revisions`` carries a one-element
    # list (the single next_step).  To find which of the last revision's steps have
    # already executed, we look at ``reconstructed.steps_after_last_revision`` — the
    # count of tool_result events recorded *strictly after* the last ``plan_revised``
    # event (computed by the journal rebuild from event ordering, not arithmetic).
    # This is correct regardless of when in the run the revision fired: revision at
    # step 1 or step 5 both yield the right 0-or-1 index into the (1-element)
    # revised step list.
    # If no revisions were recorded, fall back to the original plan (linear case).
    if reconstructed.plan_revisions:
        last_revision_steps = reconstructed.plan_revisions[-1]
        plan = InvestigationPlan(steps=[PlanStep.model_validate(s) for s in last_revision_steps])
        # Clamp next_step_index to the length of the revision's step list for
        # forward-compatibility: today every revision records exactly one step
        # (the 1-step invariant; see executor._dispatch), so
        # ``steps_after_last_revision`` is 0 or 1 and the index is always valid.
        # If a future revision ever records multiple steps, the count is still a
        # step-count, not a position guarantee, and clamping prevents an
        # out-of-bounds index from crashing a resume.
        next_step_index = min(reconstructed.steps_after_last_revision, len(last_revision_steps))
    else:
        plan = InvestigationPlan(
            steps=[PlanStep.model_validate(s) for s in reconstructed.plan_steps]
        )
        # Linear case: next step is the count of completed executor steps (not TI).
        next_step_index = executor_pre_count
    executor = Executor(
        llm=deps.llm,
        journal=deps.journal,
        registry=deps.registry,
        source=deps.source,
        max_steps=deps.max_steps,
    )
    execution = executor.resume(
        alert,
        plan,
        pre_observations=pre_observations,
        next_step_index=next_step_index,
        executor_pre_count=executor_pre_count,
    )
    return _conclude_run(
        alert, deps, execution.observations, execution.terminated_reason, run_id=run_id
    )


def resume_approve(
    deps: TriageDeps,
    reconstructed: ReconstructedRun,
    *,
    run_id: str,
    by: str,
) -> RunResult:
    """Complete a pending Run by approving its parked High-risk batch (US-0002 AC6).

    Precondition: the Run is ``awaiting_approval`` (``gate_requested`` recorded, no
    ``gate_decision``). Emits the deferred ``gate_decision(approved, by=...)``, then
    executes the batch **idempotently**: per Action, execute only if no
    ``action_executed`` already exists for it (check -> execute -> record), so a kill
    between execute and record reuses the recorded result on the next resume and
    never double-executes. Needs no Alert — actions come from the recorded
    ``gate_requested`` batch and the Verdict from the ``verdict`` event.

    A ``JournalError`` here deliberately fail-stops (no containment): with a broken
    journal the check -> execute -> record idempotency cannot be honored, so no
    high-risk action may execute; the CLI converts it to a clean nonzero exit.

    Raises:
        GateError: The Run is not pending approval (no mutation occurs).
    """
    batch = _pending_batch(reconstructed, run_id)
    deps.journal.emit("gate_decision", {"decision": "approved", "by": by})
    decision = GateDecision(decision="approved", by=by)
    already = _executed_targets(reconstructed)
    executed: list[Action] = []
    for action in batch:
        if action.name in _ACTION_EXECUTORS and _action_key(action) in already:
            # Recorded result reused (idempotency): the executor already ran for this
            # action on a prior resume that was killed before recording completion.
            executed.append(action)
            continue
        executed.extend(_execute_one(action, deps))
    deps.journal.emit("run_terminated", {"reason": "completed"})
    return _resumed_result(reconstructed, run_id, [decision], executed)


def resume_deny(
    deps: TriageDeps,
    reconstructed: ReconstructedRun,
    *,
    run_id: str,
    by: str,
) -> RunResult:
    """Complete a pending Run by denying its parked batch — the Verdict still ships.

    Emits ``gate_decision(denied, by=...)`` then ``run_terminated(completed)``;
    nothing executes. Needs no Alert (pure journal). A ``JournalError`` here
    deliberately fail-stops (same posture as ``resume_approve``): the denial must be
    durably recorded; the CLI converts it to a clean nonzero exit.

    Raises:
        GateError: The Run is not pending approval (no mutation occurs).
    """
    _pending_batch(reconstructed, run_id)
    deps.journal.emit("gate_decision", {"decision": "denied", "by": by})
    decision = GateDecision(decision="denied", by=by)
    deps.journal.emit("run_terminated", {"reason": "completed"})
    return _resumed_result(reconstructed, run_id, [decision], [])


def _pending_batch(reconstructed: ReconstructedRun, run_id: str) -> list[Action]:
    """Return the parked High-risk batch, or raise if the Run is not pending.

    A pending Run is exactly ``awaiting_approval`` (``gate_requested`` recorded, no
    ``gate_decision``); ``--approve|--deny`` on anything else is a misuse that must
    mutate nothing.
    """
    if not reconstructed.is_awaiting_approval() or reconstructed.gate_requested is None:
        msg = (
            f"cannot approve/deny run {run_id}: it is not awaiting approval "
            f"(terminated_reason={reconstructed.terminated_reason!r})"
        )
        raise GateError(msg)
    raw_actions = reconstructed.gate_requested.get("actions", [])
    return [Action.model_validate(a) for a in raw_actions]


def _execute_one(action: Action, deps: TriageDeps) -> list[Action]:
    """Execute one approved Action (or record ``action_skipped`` when unexecutable).

    Delegates to ``_dispatch_action`` — the shared post-gate dispatch helper — so
    the emit ordering and event shapes are byte-identical to ``_resolve_gate``.
    """
    dispatched = _dispatch_action(action, deps)
    return [dispatched] if dispatched is not None else []


def _executed_targets(reconstructed: ReconstructedRun) -> set[str]:
    """Return the keys of Actions already recorded as ``action_executed``.

    The idempotency ledger: an Action whose key is here was executed and recorded on
    a prior resume, so it is reused (its recorded result stands), never re-applied.
    """
    executed = reconstructed.executed_actions()
    return {_action_key(Action.model_validate(rec.action)) for rec in executed}


def _action_key(action: Action) -> str:
    """A stable identity for an Action for the idempotency check (name + params)."""
    return json.dumps(
        {"name": action.name, "params": action.params},
        sort_keys=True,
        ensure_ascii=False,
    )


def _resumed_result(
    reconstructed: ReconstructedRun,
    run_id: str,
    gate_decisions: list[GateDecision],
    executed: list[Action],
) -> RunResult:
    """Build the ``RunResult`` for a completed resume from the recorded Verdict.

    The Verdict is reconstructed from the ``verdict`` event (a pending Run always
    shipped one before parking); ``terminated_reason`` is ``completed`` — the
    resumed Run reached its conclusion.
    """
    verdict = Verdict.model_validate(reconstructed.verdict)
    return RunResult(
        run_id=run_id,
        verdict=verdict,
        gate_decisions=gate_decisions,
        executed_actions=executed,
        terminated_reason="completed",
    )


def _rebuild_observation(obs: StepObservation) -> ObservationEntry:
    """Rebuild a recorded ``StepObservation`` into the executor's ``ObservationEntry``.

    Reconstructs the ``ToolResult`` from the recorded ``ok`` + ``data``/``error`` so
    the resumed executor reuses the exact recorded Observation — never re-running the
    tool.
    """
    return ObservationEntry(
        step=obs.step,
        tool=obs.tool,
        args=obs.args,
        result=ToolResult(tool=obs.tool, ok=obs.ok, data=obs.data, error=obs.error),
    )


def summarize(result: RunResult) -> str:
    """Render a human-readable one-screen summary of a finished Run (CLI output).

    Lives in ``core`` (not ``run.py``) so it is covered by the deterministic suite
    and reused by any future adapter — it reads only ``models`` types.
    """
    verdict: Verdict = result.verdict
    lines = [
        f"Run {result.run_id} — terminated: {result.terminated_reason}",
        f"Severity: {verdict.severity}   Confidence: {verdict.confidence:.2f}",
        f"Findings ({len(verdict.findings)}):",
    ]
    lines.extend(f"  - {finding.statement} [{finding.evidence}]" for finding in verdict.findings)
    lines.append(f"Recommended actions ({len(verdict.recommended_actions)}):")
    lines.extend(f"  - {action.name}" for action in verdict.recommended_actions)
    lines.append(f"Gate decisions: {[d.decision for d in result.gate_decisions]}")
    lines.append(f"Executed actions: {[a.name for a in result.executed_actions]}")
    return "\n".join(lines)
