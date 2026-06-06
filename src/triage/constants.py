"""Centralized constants for the triage agent (RFC-0003 §Structured termination).

``TerminatedReason`` string constants and journal event-name constants live here
so every emitter references the same string, eliminating the risk of a bare
literal diverging silently.  The values are intentionally identical to the
strings already serialized in ``result.json`` records and replay caches —
introducing these constants is a **value-preserving refactor**: existing test
literals and YAML fixtures remain valid without modification.

TypedDicts for each journal event's payload give emitters a lightweight static
contract without a runtime schema gate (RFC-0003 §Alternatives: "runtime journal
event schema enforcement" was rejected; TypedDicts give emitter coherence only).
The journal remains free-form and additive — unknown events fold into no view on
resume rebuild (forward compatibility preserved).
"""

from __future__ import annotations

from typing import TypedDict

# --------------------------------------------------------------------------- #
# Terminated-reason constants                                                   #
# --------------------------------------------------------------------------- #

COMPLETED = "completed"
"""Run ended normally — the executor concluded or the plan was exhausted."""

MAX_STEPS = "max_steps"
"""Run ended because the executor reached the ``MAX_STEPS`` budget limit."""

ERROR = "error"
"""Run ended due to an unrecoverable LLM or journal error."""

AWAITING_APPROVAL = "awaiting_approval"
"""Run parked at the HITL gate — a ``DeferredGate`` emitted ``HOLD``."""

NO_PROGRESS = "no_progress"
"""Run ended because K consecutive ok=False observations made no progress."""

REVISE_EXHAUSTED = "revise_exhausted"
"""Run ended because ``revise_plan`` was issued with no ``next_step`` to run."""


# --------------------------------------------------------------------------- #
# Journal event-name constants                                                  #
# --------------------------------------------------------------------------- #

EVT_RUN_STARTED = "run_started"
EVT_LLM_CALL = "llm_call"
EVT_LLM_TRANSPORT_RETRY = "llm_transport_retry"
EVT_LLM_REPAIR = "llm_repair"
EVT_PLAN_CREATED = "plan_created"
EVT_PLAN_REVISED = "plan_revised"
EVT_TOOL_CALLED = "tool_called"
EVT_TOOL_RESULT = "tool_result"
EVT_ACTION_REJECTED = "action_rejected"
EVT_GATE_REQUESTED = "gate_requested"
EVT_GATE_DECISION = "gate_decision"
EVT_ACTION_EXECUTED = "action_executed"
EVT_ACTION_SKIPPED = "action_skipped"
EVT_ACTION_DROPPED_UNTRACEABLE = "action_dropped_untraceable"
EVT_VERDICT = "verdict"
EVT_VERDICT_VERIFICATION = "verdict_verification"
EVT_RUN_TERMINATED = "run_terminated"
EVT_FINDING_UNATTRIBUTED = "finding_unattributed"
"""Emitted when a finding cannot be attributed to any alert entity (ADR-0006).

Payload: ``{statement: str (truncated to 200 chars), reason: str}``.
Never emitted when a finding is attributed via declared, validated entities or
the text-scan detection fallback.  Serves as the audit trail for memory loss
that would otherwise be silent (ADR-0006 §Consequences: "no silent path").
"""


# --------------------------------------------------------------------------- #
# Payload TypedDicts — emitter-side coherence, NOT a runtime gate               #
# --------------------------------------------------------------------------- #


class RunStartedPayload(TypedDict):
    """Payload for the ``run_started`` journal event."""

    alert_id: str
    config: dict  # type: ignore[type-arg]
    schema_version: int


class LLMCallPayload(TypedDict):
    """Payload for the ``llm_call`` journal event."""

    purpose: str
    model: str
    prompt_hash: str
    tokens: int
    latency_ms: float


class LLMTransportRetryPayload(TypedDict):
    """Payload for the ``llm_transport_retry`` journal event."""

    purpose: str
    attempt: int
    error: str


class LLMRepairPayload(TypedDict):
    """Payload for the ``llm_repair`` journal event."""

    purpose: str
    error: str


class PlanCreatedPayload(TypedDict):
    """Payload for the ``plan_created`` journal event."""

    steps: list  # type: ignore[type-arg]


class PlanRevisedPayload(TypedDict):
    """Payload for the ``plan_revised`` journal event."""

    steps: list  # type: ignore[type-arg]


class ToolCalledPayload(TypedDict):
    """Payload for the ``tool_called`` journal event."""

    step: int
    tool: str
    args: dict  # type: ignore[type-arg]
    attempt: int


class ToolResultPayload(TypedDict, total=False):
    """Payload for the ``tool_result`` journal event (``data`` and ``error`` are exclusive)."""

    step: int
    attempt: int
    ok: bool
    data: dict  # type: ignore[type-arg]
    error: str


class ActionRejectedPayload(TypedDict):
    """Payload for the ``action_rejected`` journal event."""

    action: dict  # type: ignore[type-arg]
    reason: str


class GateRequestedPayload(TypedDict):
    """Payload for the ``gate_requested`` journal event."""

    actions: list  # type: ignore[type-arg]
    risk: str


class GateDecisionPayload(TypedDict):
    """Payload for the ``gate_decision`` journal event."""

    decision: str
    by: str


class ActionExecutedPayload(TypedDict):
    """Payload for the ``action_executed`` journal event."""

    action: dict  # type: ignore[type-arg]
    result: dict  # type: ignore[type-arg]


class ActionSkippedPayload(TypedDict):
    """Payload for the ``action_skipped`` journal event."""

    action: dict  # type: ignore[type-arg]
    reason: str


class ActionDroppedUntraceablePayload(TypedDict):
    """Payload for the ``action_dropped_untraceable`` journal event."""

    action: dict  # type: ignore[type-arg]
    reason: str


class VerdictPayload(TypedDict):
    """Payload for the ``verdict`` journal event."""

    verdict: dict  # type: ignore[type-arg]


class RunTerminatedPayload(TypedDict):
    """Payload for the ``run_terminated`` journal event."""

    reason: str


class FindingUnattributedPayload(TypedDict):
    """Payload for the ``finding_unattributed`` journal event (ADR-0006).

    Emitted by ``memory/store.persist`` when neither the declared
    ``related_entities`` nor the text-scan detection fallback yields an alert
    entity for a finding.  The statement is truncated to 200 chars to bound the
    journal event size; the full statement is in the finding in the verdict event.
    """

    statement: str
    reason: str


class VerdictVerificationPayload(TypedDict):
    """Payload for the ``verdict_verification`` journal event (RFC-0003 §Verify hook)."""

    checks: list  # type: ignore[type-arg]  # list of {name: str, passed: bool}
    failed: list  # type: ignore[type-arg]  # names of failed checks
    uncovered_entities: list  # type: ignore[type-arg]  # entity values not covered
    failed_findings: list  # type: ignore[type-arg]  # finding indices that failed citation
    action: str  # "pass" | "degrade"
