"""Pydantic data contracts shared across the triage agent (RFC-0001 §Data contracts).

Three validation postures coexist here (ADR-0004 item 2):

* The **Alert envelope** is strict — the six typed fields reject coercion so a
  malformed upstream alert fails at the door, never silently. ``severity_hint``
  is a free non-empty ``str`` (upstream severities vary; only the agent's own
  ``Verdict.severity`` is the strict enum). ``timestamp`` is kept as the raw
  ISO-8601 ``str`` rather than a ``datetime`` so strict mode does not reject the
  string form the alerts ship with (no coercion).
* The **Payload** (``entities`` / ``context``) stays flexible: arbitrary dicts
  passed to the LLM untouched. Code never branches on ``event_type`` and never
  defines per-event-type schemas — unknown event types must parse unchanged.
* The **LLM-output models** (``InvestigationPlan``/``PlanStep``,
  ``ReasonerDecision``, ``Verdict``/``Finding``/``Action``) are **lax**: they
  tolerate hallucinated extra keys (``extra="ignore"``) and benign coercions
  (e.g. a quoted ``"0.9"`` confidence from a small local model) so that such
  drift does not count as "malformed" and burn the single repair attempt on the
  no-``response_format`` path (Ollama/vLLM). Semantic constraints still bite:
  the severity enum, the ``confidence`` 0-to-1 range, and required fields all
  reject. Because validation recurses with each child model's *own* config,
  every model reachable from a ``response_model`` must be lax — a strict child
  nested in a lax parent would re-admit the bug. The internal/result models
  (``ToolResult``, ``GateDecision``, ``RunResult``) the LLM never produces stay
  strict for internal-contract integrity (a lax ``Verdict`` nested inside a
  strict ``RunResult`` is fine — the child's config wins).
"""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]
"""The agent's concluded rating — the strict enum (distinct from Severity Hint)."""

ReasonerVerb = Literal["continue", "revise_plan", "conclude"]
"""The Reasoner's decision after each Observation."""

TerminatedReason = Literal[
    "completed",
    "max_steps",
    "awaiting_approval",
    "error",
    "no_progress",
    "revise_exhausted",
]
"""Why a Run ended — shared by Verdict, RunResult, and the ``run_terminated`` event."""


class _Strict(BaseModel):
    """Base for strict, closed models: no coercion, no unexpected fields.

    Scoped to the Alert envelope and the internal/result records the LLM never
    produces — NOT the LLM-output models (see module docstring / ADR-0004).
    """

    model_config = ConfigDict(strict=True, extra="forbid")


class _Lax(BaseModel):
    """Base for LLM-output models: tolerate hallucinated keys + benign coercion.

    ``extra="ignore"`` drops unexpected fields rather than retaining them; lax
    (non-strict) validation coerces a quoted number into its field type. Field
    constraints (enums, ranges, required) still reject — only the *malformed*
    bar is relaxed, so benign drift parses instead of burning the repair attempt.
    """

    model_config = ConfigDict(extra="ignore")


class Alert(_Strict):
    """A JSON-described suspicious event submitted for investigation.

    Six typed Envelope fields plus the flexible Payload dicts. The Envelope is
    strict; the Payload is pass-through.
    """

    alert_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    source: str = Field(min_length=1)
    severity_hint: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    entities: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class PlanStep(_Lax):
    """One intended tool action within an Investigation Plan."""

    tool: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(min_length=1)


class InvestigationPlan(_Lax):
    """The LLM-generated, structured sequence of intended Plan Steps for a Run."""

    steps: list[PlanStep]


class Finding(_Lax):
    """One evidence-backed fact derived from Observations, citing its source.

    ``related_entities`` is the LLM-declared attribution field (ADR-0006 §Resolution
    order step 1 — "Declared"): a list of entity values from the alert's known
    entity values (``entities`` dict union scalar string values of ``context``) that
    this finding is about.  Values are validated in code against the known entity
    values — hallucinated names are dropped before any atom is persisted.  ``None``
    (the default) triggers the detection fallback in ``attribution.py``; an empty
    list signals "nothing attributed" and goes straight to the unattributed path
    without scanning the text.
    """

    statement: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    related_entities: list[str] | None = None


class Action(_Lax):
    """A response the Verdict proposes; the Risk Policy classifies on ``name``.

    Lax: it arrives inside ``Verdict`` straight from the LLM, so it must tolerate
    the same benign drift as its parent.
    """

    name: str = Field(min_length=1)
    params: dict[str, Any] | None = None
    description: str | None = None


class ToolResult(_Strict):
    """The result of one tool call as seen by the agent — the Observation.

    Tool failures never crash the Run: a permanent error returns as
    ``ok=False`` with ``error`` set, so the agent can adapt.
    """

    tool: str = Field(min_length=1)
    ok: bool
    data: dict[str, Any] | None = None
    error: str | None = None


class ReasonerDecision(_Lax):
    """The Reasoner's decision after an Observation, with optional next Plan Step."""

    decision: ReasonerVerb
    rationale: str = Field(min_length=1)
    next_step: PlanStep | None = None


class Verdict(_Lax):
    """The structured conclusion of a Run (partial on early termination)."""

    severity: Severity
    findings: list[Finding]
    recommended_actions: list[Action]
    confidence: float = Field(ge=0.0, le=1.0)
    terminated_reason: TerminatedReason | None = None


class GateDecision(_Strict):
    """The human outcome at the Approval Gate for the batched High-risk Actions."""

    decision: Literal["approved", "denied"]
    by: str = Field(min_length=1)


class RunResult(_Strict):
    """The versioned run record: what ``run.py`` prints and evals read.

    Persisted as ``runs/<run_id>/result.json`` so external eval adapters read it
    instead of importing ``src/triage``.
    """

    run_id: str = Field(min_length=1)
    verdict: Verdict
    gate_decisions: list[GateDecision] = Field(default_factory=list)
    executed_actions: list[Action] = Field(default_factory=list)
    terminated_reason: TerminatedReason
