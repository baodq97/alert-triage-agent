"""Verdict verify hook — deterministic grounding checks (RFC-0003 §Verify hook).

A leaf module: imports only ``models``, ``attribution``, and the stdlib.  No LLM
calls, no journal calls, no imports of other triage modules.

The hook verifies a Verdict against the run's own evidence trajectory — grounding
and internal consistency that code can check without ground-truth access.  It does
NOT verify correctness (the eval suite's job).

Four calibrated checks (all others were excluded by the adversarial review —
see RFC-0003 §Calibration findings):

1. **Citation validity** — every ``finding.evidence`` either (a) contains the name
   of a tool the run actually called, (b) contains a data value present in the
   run's observation set, (c) is an alert-correlation citation (references alert
   fields — sanctioned by verdict.md for zero-evidence runs), or (d) is a
   failure citation (references ``ok:false`` when the run actually has failed
   observations — Phase-1 calibration: summary findings over all-failed
   trajectories legitimately cite the failure shape, not a single tool).
   Fails only when evidence matches none of the four.

2. **Confidence-evidence consistency** — ``ok_count == 0`` → confidence must be in
   ``[0.30, 0.40]`` (the existing clamp band); ``confidence >= 0.8`` requires
   ``>= 1`` ok observation (Phase-1 calibration: one decisive ok observation
   legitimately supports high confidence; the hazard is high confidence with
   ZERO successful evidence).  (Does not re-enforce the clamp — just detects if
   the shipped verdict violates the invariant the clamp should have enforced.)

3. **Action traceability** — every targeted action's entity param appears as a
   case-insensitive substring in at least one finding's statement + evidence.
   Re-homed here from ``verdict._filter_traceable_actions`` as the canonical
   enforcement point (RFC-0003 §Decision).

4. **Coverage** — an alert envelope entity value (``alert.entities`` dict,
   matchable scalars + list items) is *covered* when it (a) appears in ≥1 tool
   call's args (the run targeted it — per RFC-0003 "targeting it (by args)"),
   (b) appears in ≥1 observation's data, or (c) appears in ≥1 finding text.
   The check FAILS only when **zero** envelope entities are covered (a blind
   verdict — Phase-1 calibration: correct triage routinely leaves noise
   entities uninvestigated; 10/35 recorded-correct verdicts have partial
   coverage).  The full ``uncovered_entities`` list is always reported for the
   journal and the Phase-2 gap note regardless of pass/fail.  TI enrichment
   observations count as coverage for their IOC.

``verify()`` runs all four checks and returns a ``VerificationResult`` — a
bounded, prose-free record.  The caller (``core._conclude_run``) journals the
``verdict_verification`` event and decides whether to degrade or re-enter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from triage.attribution import entities_in_text
from triage.tools.actions import is_targeted

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from triage.models import Alert, ToolResult, Verdict

# ---------------------------------------------------------------------------
# Constants mirroring the existing clamp band (must stay in sync with verdict.py)
# ---------------------------------------------------------------------------

_ZERO_EVIDENCE_CONF_MIN = 0.30
_ZERO_EVIDENCE_CONF_MAX = 0.40


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    """The bounded, prose-free outcome of the verify hook (RFC-0003 §Open questions).

    Attributes:
        passed: True iff all four checks passed.
        checks: Ordered list of ``{name: str, passed: bool}`` records for each
            check.
        uncovered_entities: Entity values from ``alert.entities`` that have no
            observation targeting them and no mention in any finding.
        failed_findings: Indices (0-based) of findings whose citation failed
            the validity check.
        failed_checks: Names of the checks that did not pass.
    """

    passed: bool
    checks: list[dict[str, Any]] = field(default_factory=list)
    uncovered_entities: list[str] = field(default_factory=list)
    failed_findings: list[int] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_citation_validity(
    verdict: Verdict,
    observations: Sequence[ToolResult],
    alert: Alert,
) -> tuple[bool, list[int]]:
    """Check 1: every finding's evidence is grounded in the run's trajectory.

    A finding's evidence passes if it:
    (a) contains the name of a tool the run actually called,
    (b) contains a data value present in the observation set (scanned as strings),
    (c) references an alert field value (alert-correlation exemption —
       sanctioned for zero-evidence runs where evidence cites the alert itself),
    or (d) cites the failure trajectory (``ok:false`` appears in the evidence
       and the run actually has ≥1 failed observation — summary findings over
       failed trajectories are grounded in the run, not hallucinated).

    Returns:
        (passed, failed_indices) — passed is True iff every finding passes;
        failed_indices is the 0-based list of failing finding positions.
    """
    called_tools: set[str] = {obs.tool for obs in observations}

    # Collect all string values from successful observation data (recursively flatten
    # dict/list values into strings for the substring scan).
    obs_data_values: set[str] = set()
    for obs in observations:
        if obs.ok and obs.data:
            _collect_string_values(obs.data, obs_data_values)

    # Collect all alert field values for the alert-correlation exemption.
    alert_values: set[str] = set()
    _collect_string_values(alert.model_dump(), alert_values)

    has_failed_observation = any(not obs.ok for obs in observations)

    failed: list[int] = []
    for idx, finding in enumerate(verdict.findings):
        evidence_lower = finding.evidence.lower()
        # (a) tool name appears in evidence
        if any(tool.lower() in evidence_lower for tool in called_tools if tool):
            continue
        # (b) some observation data value appears in evidence
        if any(val.lower() in evidence_lower for val in obs_data_values if val):
            continue
        # (c) some alert field value appears in evidence (alert-correlation)
        if any(val.lower() in evidence_lower for val in alert_values if val):
            continue
        # (d) failure citation — evidence cites ok:false and failures really happened
        if has_failed_observation and "ok:false" in evidence_lower:
            continue
        failed.append(idx)

    return len(failed) == 0, failed


def check_confidence_consistency(
    verdict: Verdict,
    observations: Sequence[ToolResult],
) -> bool:
    """Check 2: confidence is consistent with the evidence quantity.

    ``ok_count == 0`` → confidence must be in the zero-evidence clamp band
    ``[0.30, 0.40]``.  This single band rule subsumes the high-confidence rule
    (confidence ≥ 0.8 requires ≥1 ok observation): with zero ok observations,
    ANY confidence above the band ceiling — including ≥ 0.8 — fails.

    Phase-1 calibration: the original ``≥2-ok`` high-confidence rule
    false-flagged a recorded-correct verdict carrying one decisive ok
    observation at 0.88 confidence (RFC-0003 §Phasing requires a measured
    false-flag rate of 0 on the recorded suite).

    Returns True iff the verdict's confidence respects the evidence invariant.
    """
    ok_count = sum(1 for obs in observations if obs.ok)
    if ok_count == 0:
        # The clamp should have enforced this; detect if it slipped.
        return _ZERO_EVIDENCE_CONF_MIN <= verdict.confidence <= _ZERO_EVIDENCE_CONF_MAX
    return True


def check_action_traceability(
    verdict: Verdict,
    alert: Alert,  # noqa: ARG001 — reserved for future entity-scoping extension
) -> bool:
    """Check 3: every targeted action's entity param appears in a finding.

    This is the canonical enforcement point for action traceability (RFC-0003
    §Decision); ``verdict._filter_traceable_actions`` delegates here.

    Only targeted actions (those in ``TARGETED_ACTIONS``) are checked.
    Untargeted advisory actions always pass.

    A targeted action with no string params passes iff at least one finding exists
    (conservative fallback — the same rule as ``_filter_traceable_actions``).

    Returns True iff all targeted actions are traceable.
    """
    if not verdict.recommended_actions:
        return True

    finding_corpus = " ".join(f.statement + " " + f.evidence for f in verdict.findings)

    for action in verdict.recommended_actions:
        if not is_targeted(action):
            continue
        string_params = [v for v in (action.params or {}).values() if isinstance(v, str)]
        if string_params:
            if not entities_in_text(finding_corpus, string_params):
                return False
        elif not verdict.findings:
            # No string params — require at least one finding.
            return False

    return True


def check_coverage(
    verdict: Verdict,
    observations: Sequence[ToolResult],
    alert: Alert,
    call_args: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[bool, list[str]]:
    """Check 4: the investigation covers the alert's envelope entities.

    An entity value is *covered* when it:
    (a) appears in ≥1 tool call's args (the run targeted it — RFC-0003
        "targeting it (by args)"; ``call_args`` carries the executed calls'
        argument dicts),
    (b) appears in ≥1 observation's data values, OR
    (c) appears in ≥1 finding's statement or evidence text.

    The check FAILS only when **zero** envelope entities are covered — a verdict
    blind to every entity it triages.  Partial coverage passes (Phase-1
    calibration: 10/35 recorded-correct verdicts legitimately leave noise
    entities uninvestigated), but the full uncovered list is still returned for
    the journal event and the Phase-2 gap note.

    TI enrichment observations (``tool="threat_intel.enrich"``) count — their
    args and ``data`` dict contain the IOC value and related report fields.

    Only scalar string entity values and individual string items within list
    entity values are checked; non-string and empty values are skipped.

    Returns:
        (passed, uncovered_entities) — passed is False only when entities exist
        and none is covered; uncovered_entities is the list of entity values
        that had no coverage (reported even when the check passes).
    """
    finding_corpus = " ".join(f.statement + " " + f.evidence for f in verdict.findings)

    # (a) strings from executed tool calls' args — the targeting record.
    call_args_values: set[str] = set()
    for args in call_args or ():
        _collect_string_values(dict(args), call_args_values)

    # (b) strings from observation data values.
    observation_data_values: set[str] = set()
    for obs in observations:
        _collect_string_values(obs.data or {}, observation_data_values)

    targeted_corpus = call_args_values | observation_data_values

    entity_values = list(_entity_scalars(alert))
    uncovered: list[str] = []
    for entity_value in entity_values:
        val_lower = entity_value.lower()
        # (a)+(b) targeted by args or present in observation data
        if any(val_lower in stored.lower() for stored in targeted_corpus if stored):
            continue
        # (c) appears in a finding
        if val_lower in finding_corpus.lower():
            continue
        uncovered.append(entity_value)

    covered_count = len(entity_values) - len(uncovered)
    passed = covered_count > 0 or not entity_values
    return passed, uncovered


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------


def verify(
    verdict: Verdict,
    observations: Sequence[ToolResult],
    alert: Alert,
    call_args: Sequence[Mapping[str, Any]] | None = None,
) -> VerificationResult:
    """Run all four RFC-0003 verify checks and return a bounded result record.

    Runs all checks regardless of earlier failures — the full result is always
    available for journaling and for the gap note used in Phase-2 re-entry.

    Args:
        verdict: The synthesized Verdict to check.
        observations: The tool Observations gathered during the run.
        alert: The alert under investigation (used for alert-correlation and
            coverage checks).
        call_args: The executed tool calls' argument dicts (one per call, in
            order) — the targeting record the coverage check matches entities
            against.  ``None`` degrades coverage to data + finding matching.

    Returns:
        A ``VerificationResult`` with ``passed``, ``checks``, ``uncovered_entities``,
        ``failed_findings``, and ``failed_checks``.
    """
    checks: list[dict[str, Any]] = []
    failed_checks: list[str] = []
    uncovered_entities: list[str] = []
    failed_findings: list[int] = []

    # Check 1: citation validity
    c1_passed, c1_failed_findings = check_citation_validity(verdict, observations, alert)
    checks.append({"name": "citation_validity", "passed": c1_passed})
    if not c1_passed:
        failed_checks.append("citation_validity")
        failed_findings = c1_failed_findings

    # Check 2: confidence-evidence consistency
    c2_passed = check_confidence_consistency(verdict, observations)
    checks.append({"name": "confidence_consistency", "passed": c2_passed})
    if not c2_passed:
        failed_checks.append("confidence_consistency")

    # Check 3: action traceability
    c3_passed = check_action_traceability(verdict, alert)
    checks.append({"name": "action_traceability", "passed": c3_passed})
    if not c3_passed:
        failed_checks.append("action_traceability")

    # Check 4: coverage
    c4_passed, uncovered_entities = check_coverage(verdict, observations, alert, call_args)
    checks.append({"name": "coverage", "passed": c4_passed})
    if not c4_passed:
        failed_checks.append("coverage")

    passed = len(failed_checks) == 0
    return VerificationResult(
        passed=passed,
        checks=checks,
        uncovered_entities=uncovered_entities,
        failed_findings=failed_findings,
        failed_checks=failed_checks,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _collect_string_values(obj: Any, out: set[str]) -> None:  # noqa: ANN401
    """Recursively collect all non-empty string leaves from a JSON-like structure."""
    if isinstance(obj, str):
        if obj:
            out.add(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_string_values(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_string_values(item, out)


def _entity_scalars(alert: Alert) -> list[str]:
    """Return the string entity values from ``alert.entities`` (scalars + list items).

    Non-string values and empty strings are excluded.  Nested dicts are not
    recursed — only the immediate values of the ``entities`` dict and, for list
    values, their immediate string items.
    """
    result: list[str] = []
    for value in alert.entities.values():
        if isinstance(value, str) and value:
            result.append(value)
        elif isinstance(value, list):
            result.extend(item for item in value if isinstance(item, str) and item)
    return result
