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

``awaiting_approval`` cannot occur in wave 1: the CLI adapter is synchronous, so
the gate resolves in-process and the Run never parks. The reason is reserved for
the later async ``--watch`` / ``--resume`` adapters; ``triage`` never sets it.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from triage.errors import LLMError
from triage.executor import Executor
from triage.models import RunResult
from triage.planner import Planner
from triage.tools.actions import block_user, block_user_target, is_targeted
from triage.verdict import VerdictSynthesizer

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from triage.gate import ApprovalGate, RiskPolicy
    from triage.journal import Journal
    from triage.llm import LLM
    from triage.models import (
        Action,
        Alert,
        GateDecision,
        TerminatedReason,
        ToolResult,
        Verdict,
    )
    from triage.tools.base import DataSource
    from triage.tools.registry import ToolRegistry

from dataclasses import dataclass, field

SCHEMA_VERSION = 1
"""The run-record schema version stamped on ``run_started`` (lives only in the event)."""

# The wave-1 Response Action dispatch table: the only executable action is
# ``block_user`` (the single shipped Response Action). The post-gate flow only
# ever executes an approved High-risk batch, and a Verdict's actions are
# target-checked first, so an unmapped name cannot reach here in wave 1.
_ACTION_EXECUTORS: dict[str, Callable[[Action], dict[str, object]]] = {
    "block_user": block_user,
}


@dataclass(frozen=True)
class TriageDeps:
    """The explicit, frozen dependency bundle one Run is wired from.

    Leaf collaborators only (``models``-level seams): ``triage`` constructs the
    ``Planner`` / ``Executor`` / ``VerdictSynthesizer`` itself, so the adapter in
    ``run.py`` builds only the leaves and never reaches into the loop. ``max_steps``
    overrides the executor's ``MAX_STEPS`` guard (env / default 15 otherwise) —
    the seam the breach test drives cheaply.
    """

    llm: LLM
    journal: Journal
    registry: ToolRegistry
    source: DataSource
    gate: ApprovalGate
    policy: RiskPolicy
    max_steps: int | None = field(default=None)


def triage(alert: Alert, deps: TriageDeps) -> RunResult:
    """Run one Alert through the full triage loop and return its ``RunResult``.

    Args:
        alert: The validated Alert envelope+payload under investigation.
        deps: The frozen dependency bundle (LLM, journal, registry, source, gate,
            policy, optional ``max_steps``).

    Returns:
        The versioned ``RunResult`` — verdict, gate decisions, executed actions,
        run id, terminated reason. Never raises: a planner failure degrades to a
        partial verdict, tool/LLM failures convert to a ``terminated_reason``, and
        the gate decision either way still ships the verdict.
    """
    run_id = str(uuid.uuid4())
    deps.journal.emit(
        "run_started",
        {
            "alert_id": alert.alert_id,
            "config": {"max_steps": deps.max_steps},
            "schema_version": SCHEMA_VERSION,
        },
    )

    observations, terminated_reason = _investigate(alert, deps)
    synthesizer = VerdictSynthesizer(llm=deps.llm, journal=deps.journal)
    verdict = synthesizer.synthesize(
        alert,
        observations=observations,
        terminated_reason=terminated_reason,
    )

    accepted = _accept_actions(alert, verdict.recommended_actions, deps.journal)
    decision = deps.gate.request(accepted, deps.policy)
    gate_decisions, executed = _resolve_gate(decision, accepted, deps)

    deps.journal.emit("run_terminated", {"reason": terminated_reason})
    return RunResult(
        run_id=run_id,
        verdict=verdict,
        gate_decisions=gate_decisions,
        executed_actions=executed,
        terminated_reason=terminated_reason,
    )


def _investigate(alert: Alert, deps: TriageDeps) -> tuple[list[ToolResult], TerminatedReason]:
    """Plan and execute, returning the Observations and the terminated reason.

    A planner ``LLMError`` means the plan never happened: execution is skipped and
    the reason is ``"error"`` with no gathered material. Otherwise the executor's
    ``ObservationEntry`` trajectory is adapted to the verdict seam (the bare
    ``ToolResult`` list Findings cite) and its ``terminated_reason`` carries
    through.
    """
    planner = Planner(llm=deps.llm, journal=deps.journal, tool_specs=deps.registry.specs())
    try:
        plan = planner.plan(alert)
    except LLMError:
        return [], "error"
    executor = Executor(
        llm=deps.llm,
        journal=deps.journal,
        registry=deps.registry,
        source=deps.source,
        max_steps=deps.max_steps,
    )
    execution = executor.run(alert, plan)
    observations = [entry.result for entry in execution.observations]
    return observations, execution.terminated_reason


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
        executor = _ACTION_EXECUTORS.get(action.name)
        if executor is None:
            deps.journal.emit(
                "action_skipped",
                {"action": action.model_dump(), "reason": "no executor for action"},
            )
            continue
        result = executor(action)
        deps.journal.emit("action_executed", {"action": action.model_dump(), "result": result})
        executed.append(action)
    return [decision], executed


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
