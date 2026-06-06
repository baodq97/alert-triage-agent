"""Eval data contracts — Golden Case, run record, and ScoreResult (US-0003).

These are the eval harness's own Pydantic contracts, kept deliberately apart from
``triage.models``:

* ``GoldenCase`` / ``TrajectoryExpect`` / ``VerdictExpect`` mirror the
  ``evals/cases/*.yaml`` schema documented in the ``eval-authoring`` skill — the
  declarative Behavioral Assertions (ranges and sets, never exact matches) plus
  the tool-neutral ``reference`` block adapters read.
* ``RunRecord`` is the frozen experiment a Tier-1 assertion scores: the
  versioned ``result.json`` run record plus the flat ``journal.jsonl`` lines. It
  is the *only* artifact the pure assertion engine consumes, so a foreign tool
  re-scores a run with these two files and nothing from ``src/triage`` beyond
  ``triage.models`` (US-0003 AC: assertion purity).
* ``ScoreResult`` is one Behavioral Assertion's outcome — the unit the runner
  reports and the gate (Tier-1 must all pass) reads.

The case models are lax (``extra="ignore"``) so a YAML key the engine does not
yet understand never fails the load — a new assertion is additive. ``RunRecord``
holds the raw artifacts as plain dicts/lists: it never re-validates them into
``triage`` models, because an external adapter must be able to hand the harness a
``result.json`` that a *future* schema version produced.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _CaseModel(BaseModel):
    """Base for the Golden Case models — tolerant of forward-compatible keys."""

    model_config = ConfigDict(extra="ignore")


class TrajectoryExpect(_CaseModel):
    """Declarative Tier-1 assertions over the Run's Trajectory (journal events).

    Every field is optional: a case asserts only the behaviors it guards. The
    assertion engine emits one ``ScoreResult`` per *populated* field, so an absent
    field is silent, never a vacuous pass.
    """

    must_call_tools: list[str] | None = None
    """Tool names that MUST appear among the Run's ``tool_called`` events (a set)."""

    gate_before_high_risk: bool | None = None
    """If ``True``: no ``action_executed`` may precede a ``gate_decision(approved)``."""

    no_action_without_gate: bool | None = None
    """If ``True``: every ``action_executed`` is preceded by a ``gate_decision(approved)``."""

    max_steps_respected: bool | None = None
    """If ``True``: the Run did not terminate with ``reason="max_steps"`` (it finished)."""

    no_repeated_identical_calls: bool | None = None
    """If ``True``: no identical ``tool``+``args`` pair was *executed* twice."""

    must_observe_tool_failure: bool | None = None
    """If ``True``: at least one ``tool_result`` with ``ok=false`` MUST appear — the
    Run observed a tool failure (the resilience cases assert the OUTCOME instead of
    pinning which tool fails, so a reasonable-but-different route still counts)."""

    terminated_reason_in: list[str] | None = None
    """The Run's ``terminated_reason`` MUST be one of these (a set)."""

    denied_actions_not_executed: bool | None = None
    """If ``True``: for every ``gate_decision(denied)`` event, no ``action_executed``
    event follows for any action in that denied batch (matched by action name+params).
    Guards that a denial is actually honoured — an action that was explicitly denied
    must never appear in the ``action_executed`` stream."""


class VerdictExpect(_CaseModel):
    """Declarative Tier-1 assertions over the synthesized Verdict.

    Ranges and sets only — the LLM's exact severity/confidence varies run to run,
    so an exact match would flap. Every field is optional.
    """

    severity_in: list[str] | None = None
    """The Verdict ``severity`` MUST be one of these (a RANGE, never exact)."""

    must_reference_entities: list[str] | None = None
    """Each string MUST appear (case-insensitive) in some finding statement/evidence."""

    confidence_min: float | None = None
    """The Verdict ``confidence`` MUST be at least this floor."""

    confidence_max: float | None = None
    """The Verdict ``confidence`` MUST be at most this ceiling."""

    verdict_has_findings_with_citations: bool | None = None
    """If ``True``: the Verdict has >=1 finding and every finding cites its evidence."""


class ReferenceTool(_CaseModel):
    """One entry in the tool-neutral ``reference.expected_tools`` ordered list."""

    name: str = Field(min_length=1)
    input_parameters: dict[str, object] | None = None


class Reference(_CaseModel):
    """The tool-neutral expected block — read by ``evals/adapters/``, never gated.

    The ``expect`` assertions remain the only Tier-1 gate; ``reference`` is the
    vendor-neutral shape a deepeval/promptfoo adapter projects from (ordered tool
    list, expected severity/actions, and the adapter knobs ``ordered`` / ``exact``).
    """

    expected_tools: list[ReferenceTool] = Field(default_factory=list)
    expected_severity: str | None = None
    expected_actions: list[str] = Field(default_factory=list)
    ordered: bool = False
    exact: bool = False


class PriorRun(_CaseModel):
    """One prior Run a case declaratively seeds into its tmp Memory Store.

    The seed exercises the *real* ``MemoryStore.persist`` API (never a hand-written
    atom file): the runner replays this prior ``(run_id, alert, verdict)`` through
    ``persist`` before the case Run, so the recalled content reaches the planner via
    the exact production code path. All three fields are fixed in the YAML — no
    wall clock, no minted ``run_id`` — so the seeded recall is byte-identical run to
    run and the plan ``prompt_hash`` stays replay-stable (RFC-0001 §Memory: ``ts``
    keys off the alert timestamp, never the wall clock).
    """

    run_id: str = Field(min_length=1)
    """The prior Run's identity — fixed in YAML; it renders into the recall item."""

    alert: str = Field(min_length=1)
    """Path (repo-root-relative) to the prior Run's alert JSON — the entity source."""

    verdict: dict[str, object]
    """The prior Run's verdict as an inline dict — validated by ``persist`` into atoms."""


class GoldenCase(_CaseModel):
    """One Golden Case loaded from ``evals/cases/*.yaml`` (the eval contract).

    ``alert`` is the path to the alert JSON (relative to the repo root) the Run
    investigates; ``expect`` holds the blocking Tier-1 Behavioral Assertions;
    ``reference`` is the optional tool-neutral block for adapters; ``guards`` is the
    one-line regression note the skill requires (free text, never asserted).

    ``prior_runs`` is the optional declarative Memory seed: when present, the runner
    builds a throwaway tmp-dir Memory Store, persists each prior Run through the real
    ``MemoryStore.persist``, and wires it via ``TriageDeps.memory`` so recall feeds
    the planner. A case without it keeps ``memory=None`` — the loop runs memory-free,
    byte-for-byte as before the seam was wired.
    """

    name: str = Field(min_length=1)
    alert: str = Field(min_length=1)
    gate: str = "approve"
    """Per-case gate posture for ``AutoGate``: ``"approve"`` (default) or ``"deny"``.

    Drives whether ``build_deps`` wires ``AutoGate(approve=True/False)`` for this
    Run.  The default ``"approve"`` preserves byte-identical behaviour for every
    existing case.  Set to ``"deny"`` for cases that assert denial semantics
    (e.g. ``high-gate-denied`` verifies that a denied batch is never executed).
    """
    ti_enabled: bool = False
    """Whether the TI enrichment mini-loop is enabled for this case (RFC-0002).

    Mirrors the ``TI_ENABLED`` env var but per-case and race-free: the runner
    sets ``TriageDeps.ti_enabled`` from this field rather than mutating the
    process-global env, so parallel replay threads do not interfere with each
    other.  The default ``False`` keeps every existing case byte-identical —
    TI code paths are off unless a case explicitly sets ``ti_enabled: true``.
    """
    judge_min: float | None = None
    """Per-case minimum Tier-2 judge score (median-of-3, 0-100 scale).

    When set, a case whose judge score falls below this threshold fails the
    soft gate (exit 2, ``TIER-2 WARN`` section) — but ONLY when a judge is
    actually wired.  If no judge is passed to ``evaluate_case`` this field is
    silently ignored and the gate behaviour is identical to a case without it.
    A judge that returns ``scored=False`` (transport error, no key) also never
    triggers the soft gate regardless of this value — degradation must not
    block CI.  Only set on sentinel cases with demonstrably stable median
    scores (≥ 60 band across 3+ sweeps); leave ``None`` on the known-hard
    tail (tool-failure\\*, edge-\\*) whose scores vary run to run.
    """
    prior_runs: list[PriorRun] | None = None
    expect_trajectory: TrajectoryExpect = Field(
        default_factory=TrajectoryExpect,
        alias="trajectory",
    )
    expect_verdict: VerdictExpect = Field(default_factory=VerdictExpect, alias="verdict")
    reference: Reference = Field(default_factory=Reference)
    guards: str | None = None
    pending: str | None = None
    """When set, a human-readable note that this case passes only after pending wiring.

    The ``benign-after-flagged`` case sets it (memory recall wiring is in flight);
    the runner reports a pending case's failures as informational, never gating —
    see the ``eval-authoring`` skill's note on cases awaiting upstream wiring.
    """


class ScoreResult(BaseModel):
    """One Behavioral Assertion's outcome — the unit the runner reports.

    ``passed`` drives the Tier-1 gate; ``score`` is a 0-to-1 numeric the Tier-2
    judge and trend reports share the shape of; ``detail`` explains a failure.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    name: str = Field(min_length=1)
    passed: bool
    score: float = Field(ge=0.0, le=1.0)
    detail: str = ""


class RunRecord(BaseModel):
    """The frozen experiment a Tier-1 assertion scores (US-0003 AC: purity).

    The two on-disk artifacts of one Run: the versioned ``result.json`` run record
    and the flat ``journal.jsonl`` lines. Held as raw ``dict``/``list`` so the
    assertion engine never re-validates them into ``triage`` models — an external
    adapter hands these in from a possibly-future schema version.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    result: dict[str, object]
    journal: list[dict[str, object]]
