"""Tests for the verdict verify hook (RFC-0003 §Verify hook, US-0008 group 2).

Structural assertions only — verifies deterministic grounding checks, not
whether verdicts are "correct" relative to ground truth.

Test scope:
* Each of the four checks in isolation (happy + failing cases).
* The combined ``verify()`` entry point.
* Edge cases: empty findings, empty observations, empty entities.
* The alert-correlation citation exemption (check 1c).
* The zero-evidence clamp band enforcement (check 2).
* The high-confidence min-ok requirement (check 2).
* Coverage with TI enrichment observations (check 4).
"""

from __future__ import annotations

import dataclasses

import pytest

from triage.models import Action, Alert, Finding, Severity, ToolResult, Verdict
from triage.verification import (
    VerificationResult,
    _collect_string_values,
    _entity_scalars,
    check_action_traceability,
    check_citation_validity,
    check_confidence_consistency,
    check_coverage,
    verify,
)

# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-1",
        "timestamp": "2026-06-05T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "data_exfiltration",
        "description": "Suspicious outbound transfer from alice.",
        "entities": {"user": "alice", "ip": "10.0.0.9"},
        "context": {},
    }
    return Alert.model_validate({**base, **overrides})


def _verdict(
    *,
    severity: Severity = "high",
    confidence: float = 0.8,
    findings: list[Finding] | None = None,
    actions: list[Action] | None = None,
) -> Verdict:
    return Verdict(
        severity=severity,
        confidence=confidence,
        findings=findings or [],
        recommended_actions=actions or [],
    )


def _finding(
    *,
    statement: str = "alice exfiltrated.",
    evidence: str = "query_logs showed data.",
) -> Finding:
    return Finding(statement=statement, evidence=evidence)


def _ok_obs(tool: str = "query_logs", data: dict | None = None) -> ToolResult:
    return ToolResult(tool=tool, ok=True, data=data or {"result": "found"})


def _fail_obs(tool: str = "lookup_user", error: str = "not found") -> ToolResult:
    return ToolResult(tool=tool, ok=False, error=error)


# ---------------------------------------------------------------------------
# check_citation_validity
# ---------------------------------------------------------------------------


class TestCheckCitationValidity:
    def test_evidence_with_tool_name_passes(self) -> None:
        """Evidence containing the called tool's name satisfies (a)."""
        verdict = _verdict(
            findings=[_finding(evidence="query_logs returned 5 MB outbound.")],
            confidence=0.8,
        )
        obs = [_ok_obs("query_logs")]
        passed, failed = check_citation_validity(verdict, obs, _alert())
        assert passed
        assert failed == []

    def test_evidence_with_observation_data_value_passes(self) -> None:
        """Evidence containing a data value from observations satisfies (b)."""
        verdict = _verdict(
            findings=[_finding(evidence="Transfer to 203.0.113.7 detected.")],
            confidence=0.8,
        )
        obs = [_ok_obs("query_logs", data={"dest_ip": "203.0.113.7"})]
        passed, failed = check_citation_validity(verdict, obs, _alert())
        assert passed
        assert failed == []

    def test_evidence_with_alert_field_value_passes(self) -> None:
        """Evidence referencing an alert field satisfies (c) — alert-correlation exemption."""
        verdict = _verdict(
            findings=[_finding(evidence="Alert described data_exfiltration from alice.")],
            confidence=0.35,
        )
        # No observations — zero-evidence run; evidence cites alert fields directly.
        passed, failed = check_citation_validity(verdict, [], _alert())
        assert passed
        assert failed == []

    def test_evidence_with_no_match_fails(self) -> None:
        """Evidence matching nothing — no tool, no data value, no alert field — fails."""
        verdict = _verdict(
            findings=[_finding(evidence="Bob performed suspicious lateral movement.")],
            confidence=0.8,
        )
        obs = [_ok_obs("query_logs", data={"info": "some other data"})]
        # 'Bob' is not a tool name, not in obs data, not in alert fields.
        passed, failed = check_citation_validity(verdict, obs, _alert())
        assert not passed
        assert failed == [0]

    def test_mixed_findings_partial_failure(self) -> None:
        """When one finding passes and one fails, only the failing index is reported."""
        verdict = _verdict(
            findings=[
                _finding(evidence="query_logs confirmed outbound."),  # passes (a)
                _finding(evidence="Totally hallucinated citation with no grounding."),  # fails
            ],
            confidence=0.7,
        )
        obs = [_ok_obs("query_logs")]
        passed, failed = check_citation_validity(verdict, obs, _alert())
        assert not passed
        assert 0 not in failed
        assert 1 in failed

    def test_empty_findings_passes(self) -> None:
        """No findings → citation check is vacuously true."""
        verdict = _verdict(findings=[], confidence=0.35)
        passed, failed = check_citation_validity(verdict, [], _alert())
        assert passed
        assert failed == []

    def test_case_insensitive_tool_match(self) -> None:
        """Tool name matching is case-insensitive."""
        verdict = _verdict(
            findings=[_finding(evidence="QUERY_LOGS returned an outbound event.")],
            confidence=0.8,
        )
        obs = [_ok_obs("query_logs")]
        passed, _failed = check_citation_validity(verdict, obs, _alert())
        assert passed

    def test_failed_observation_tool_name_still_counts(self) -> None:
        """A failed (ok=False) observation's tool name still counts for check (a)."""
        verdict = _verdict(
            findings=[_finding(evidence="lookup_user returned not found for alice.")],
            confidence=0.35,
        )
        obs = [_fail_obs("lookup_user")]
        passed, _failed = check_citation_validity(verdict, obs, _alert())
        assert passed

    def test_ti_obs_tool_name_counts(self) -> None:
        """TI enrichment observations' tool names satisfy check (a)."""
        verdict = _verdict(
            findings=[_finding(evidence="threat_intel.enrich returned high risk for 10.0.0.9.")],
            confidence=0.8,
        )
        obs = [_ok_obs("threat_intel.enrich", data={"ioc": "10.0.0.9", "risk": "high"})]
        passed, _failed = check_citation_validity(verdict, obs, _alert())
        assert passed

    def test_failure_citation_passes_with_failed_observations(self) -> None:
        """Check (d): evidence citing ``ok:false`` passes when failures happened.

        Phase-1 calibration: a summary finding over an all-failed trajectory
        ('All three observations were ok:false ...') names no single tool but is
        grounded in the run — it cannot be a hallucinated citation.
        """
        verdict = _verdict(
            findings=[_finding(evidence="All observations were ok:false; no data returned.")],
            confidence=0.35,
        )
        obs = [_fail_obs("nonmatching_tool_name")]
        # Evidence names no called tool, no data value, no alert value — only (d) saves it.
        passed, _failed = check_citation_validity(verdict, obs, _alert(entities={}))
        assert passed

    def test_failure_citation_fails_without_failed_observations(self) -> None:
        """Check (d) does NOT apply when every observation succeeded — citing
        ``ok:false`` against an all-ok trajectory is ungrounded."""
        verdict = _verdict(
            findings=[_finding(evidence="All observations were ok:false; nothing worked.")],
        )
        obs = [_ok_obs("query_logs", data={"events": "normal"})]
        passed, failed = check_citation_validity(verdict, obs, _alert(entities={}))
        assert not passed
        assert failed == [0]


# ---------------------------------------------------------------------------
# check_confidence_consistency
# ---------------------------------------------------------------------------


class TestCheckConfidenceConsistency:
    def test_zero_ok_in_range_passes(self) -> None:
        """ok_count=0, confidence in [0.30, 0.40] → pass."""
        verdict = _verdict(confidence=0.35)
        obs = [_fail_obs()]
        assert check_confidence_consistency(verdict, obs) is True

    def test_zero_ok_above_ceiling_fails(self) -> None:
        """ok_count=0, confidence > 0.40 → fail (clamp should have enforced this)."""
        verdict = _verdict(confidence=0.70)
        obs = [_fail_obs()]
        assert check_confidence_consistency(verdict, obs) is False

    def test_zero_ok_below_floor_fails(self) -> None:
        """ok_count=0, confidence < 0.30 → fail."""
        verdict = _verdict(confidence=0.10)
        obs = [_fail_obs()]
        assert check_confidence_consistency(verdict, obs) is False

    def test_zero_ok_at_floor_boundary_passes(self) -> None:
        """ok_count=0, confidence == 0.30 exactly → pass (inclusive boundary)."""
        verdict = _verdict(confidence=0.30)
        obs = [_fail_obs()]
        assert check_confidence_consistency(verdict, obs) is True

    def test_zero_ok_at_ceiling_boundary_passes(self) -> None:
        """ok_count=0, confidence == 0.40 exactly → pass (inclusive boundary)."""
        verdict = _verdict(confidence=0.40)
        obs = [_fail_obs()]
        assert check_confidence_consistency(verdict, obs) is True

    def test_one_ok_high_confidence_passes(self) -> None:
        """confidence >= 0.8 with 1 ok observation → pass (Phase-1 calibration).

        The original ≥2-ok rule false-flagged a recorded-correct verdict (one
        decisive ok observation at 0.88 confidence); the real hazard — high
        confidence with ZERO successful evidence — stays caught by the band rule.
        """
        verdict = _verdict(confidence=0.85)
        obs = [_ok_obs(), _fail_obs()]
        assert check_confidence_consistency(verdict, obs) is True

    def test_two_ok_high_confidence_passes(self) -> None:
        """confidence >= 0.8 with 2 ok observations → pass."""
        verdict = _verdict(confidence=0.85)
        obs = [_ok_obs("query_logs"), _ok_obs("check_reputation")]
        assert check_confidence_consistency(verdict, obs) is True

    def test_no_observations_no_findings_confidence_below_floor_fails(self) -> None:
        """Zero observations, confidence below floor → fails (no-evidence run)."""
        verdict = _verdict(confidence=0.20)
        assert check_confidence_consistency(verdict, []) is False

    def test_one_ok_moderate_confidence_passes(self) -> None:
        """confidence < 0.8 with 1 ok observation → pass (no extra constraint)."""
        verdict = _verdict(confidence=0.65)
        obs = [_ok_obs()]
        assert check_confidence_consistency(verdict, obs) is True

    def test_three_ok_high_confidence_passes(self) -> None:
        """confidence >= 0.8 with 3 ok observations → pass."""
        verdict = _verdict(confidence=0.91)
        obs = [_ok_obs("query_logs"), _ok_obs("lookup_user"), _ok_obs("check_reputation")]
        assert check_confidence_consistency(verdict, obs) is True

    def test_high_confidence_zero_ok_fails(self) -> None:
        """confidence >= 0.8 with ZERO ok observations → fails (outside the band)."""
        verdict = _verdict(confidence=0.8)
        obs = [_fail_obs(), _fail_obs()]
        assert check_confidence_consistency(verdict, obs) is False

    def test_exactly_08_threshold_with_two_ok_passes(self) -> None:
        """confidence == 0.8 exactly with 2 ok → passes."""
        verdict = _verdict(confidence=0.8)
        obs = [_ok_obs("query_logs"), _ok_obs("lookup_user")]
        assert check_confidence_consistency(verdict, obs) is True


# ---------------------------------------------------------------------------
# check_action_traceability
# ---------------------------------------------------------------------------


class TestCheckActionTraceability:
    def test_no_actions_passes(self) -> None:
        """No recommended actions → vacuously true."""
        verdict = _verdict(actions=[])
        assert check_action_traceability(verdict, _alert()) is True

    def test_untargeted_action_always_passes(self) -> None:
        """An untargeted advisory action is never checked for traceability."""
        verdict = _verdict(
            findings=[],
            actions=[Action(name="notify_soc", params={"channel": "#soc"})],
        )
        assert check_action_traceability(verdict, _alert()) is True

    def test_targeted_action_with_matching_param_passes(self) -> None:
        """block_user with 'alice' traceable to a finding containing 'alice' passes."""
        verdict = _verdict(
            findings=[_finding(statement="alice exfiltrated data.", evidence="logs showed alice.")],
            actions=[Action(name="block_user", params={"user": "alice"})],
            confidence=0.8,
        )
        assert check_action_traceability(verdict, _alert()) is True

    def test_targeted_action_with_no_match_fails(self) -> None:
        """block_user with 'mallory' not in any finding fails."""
        verdict = _verdict(
            findings=[_finding(statement="alice exfiltrated data.", evidence="logs showed alice.")],
            actions=[Action(name="block_user", params={"user": "mallory"})],
            confidence=0.8,
        )
        assert check_action_traceability(verdict, _alert()) is False

    def test_targeted_action_no_string_params_with_findings_passes(self) -> None:
        """Targeted action with no string params but with findings → passes."""
        verdict = _verdict(
            findings=[_finding()],
            actions=[Action(name="block_user", params={})],
        )
        assert check_action_traceability(verdict, _alert()) is True

    def test_targeted_action_no_string_params_no_findings_fails(self) -> None:
        """Targeted action with no string params and no findings → fails."""
        verdict = _verdict(
            findings=[],
            actions=[Action(name="block_user", params={})],
        )
        assert check_action_traceability(verdict, _alert()) is False

    def test_case_insensitive_matching(self) -> None:
        """Traceability matching is case-insensitive."""
        verdict = _verdict(
            findings=[_finding(statement="ALICE was the source.", evidence="logs show ALICE.")],
            actions=[Action(name="block_user", params={"user": "alice"})],
            confidence=0.8,
        )
        assert check_action_traceability(verdict, _alert()) is True


# ---------------------------------------------------------------------------
# check_coverage
# ---------------------------------------------------------------------------


class TestCheckCoverage:
    def test_entity_in_finding_passes(self) -> None:
        """An entity value appearing in a finding text is covered."""
        verdict = _verdict(
            findings=[_finding(statement="alice exfiltrated.", evidence="alice found in logs.")],
        )
        _passed, uncovered = check_coverage(verdict, [], _alert())
        # 'alice' is covered; '10.0.0.9' may not be.
        assert "alice" not in uncovered

    def test_entity_in_observation_data_passes(self) -> None:
        """An entity value appearing in an observation's data is covered."""
        obs = [_ok_obs("query_logs", data={"user": "alice", "dest_ip": "10.0.0.9"})]
        verdict = _verdict(findings=[])
        _passed, uncovered = check_coverage(verdict, obs, _alert())
        # Both 'alice' and '10.0.0.9' appear in obs data.
        assert "alice" not in uncovered
        assert "10.0.0.9" not in uncovered

    def test_uncovered_entity_reported(self) -> None:
        """An entity with no observation data and no finding mention is uncovered."""
        verdict = _verdict(
            findings=[_finding(statement="something else.", evidence="no relevant data.")],
        )
        obs = [_ok_obs("query_logs", data={"unrelated": "value"})]
        alert = _alert(entities={"user": "alice", "ip": "10.0.0.9"})
        passed, uncovered = check_coverage(verdict, obs, alert)
        assert not passed
        # Both entities are uncovered.
        assert "alice" in uncovered
        assert "10.0.0.9" in uncovered

    def test_empty_entities_passes(self) -> None:
        """No entities → coverage check is vacuously true."""
        verdict = _verdict(findings=[])
        alert = _alert(entities={})
        passed, uncovered = check_coverage(verdict, [], alert)
        assert passed
        assert uncovered == []

    def test_list_entity_values_covered(self) -> None:
        """Entity values that are lists have their string items checked individually."""
        alert = _alert(entities={"ips": ["10.0.0.9", "192.168.1.1"]})
        verdict = _verdict(
            findings=[_finding(statement="10.0.0.9 and 192.168.1.1 scanned.", evidence="logs.")],
        )
        passed, uncovered = check_coverage(verdict, [], alert)
        assert passed
        assert uncovered == []

    def test_ti_obs_data_covers_entity(self) -> None:
        """TI enrichment observation data values count as coverage for their IOC."""
        alert = _alert(entities={"ip": "10.0.0.9"})
        obs = [_ok_obs("threat_intel.enrich", data={"ioc": "10.0.0.9", "risk": "high"})]
        verdict = _verdict(findings=[])
        _passed, uncovered = check_coverage(verdict, obs, alert)
        assert "10.0.0.9" not in uncovered

    def test_non_string_entity_values_skipped(self) -> None:
        """Non-string entity values (e.g. ints) are skipped — only strings checked."""
        alert = _alert(entities={"user": "alice", "count": 42})  # type: ignore[arg-value]
        verdict = _verdict(findings=[_finding(statement="alice suspicious.", evidence="alice.")])
        _passed, uncovered = check_coverage(verdict, [], alert)
        # 'alice' covered; 42 is non-string → skipped.
        assert "alice" not in uncovered

    def test_partial_coverage_passes_but_reports_uncovered(self) -> None:
        """≥1 entity covered → pass; uncovered list still carries the gaps.

        Phase-1 calibration: 10/35 recorded-correct verdicts legitimately leave
        noise entities uninvestigated — partial coverage must not flag, but the
        gap list stays journaled for the Phase-2 gap note.
        """
        alert = _alert(entities={"user": "alice", "ip": "10.0.0.9"})
        verdict = _verdict(findings=[_finding(statement="alice is benign.", evidence="alice.")])
        passed, uncovered = check_coverage(verdict, [], alert)
        assert passed
        assert uncovered == ["10.0.0.9"]

    def test_call_args_target_covers_entity(self) -> None:
        """An entity targeted by a tool call's args is covered (RFC-0003 'by args').

        The fixture world may return data that never echoes the queried value —
        targeting alone proves the run investigated the entity.
        """
        alert = _alert(entities={"role": "arn:aws:iam::1:role/x"})
        verdict = _verdict(findings=[])
        obs = [_ok_obs("query_logs", data={"events": "none found"})]
        passed, uncovered = check_coverage(
            verdict, obs, alert, call_args=[{"entity": "arn:aws:iam::1:role/x"}]
        )
        assert passed
        assert uncovered == []

    def test_zero_covered_entities_fails(self) -> None:
        """No entity targeted, in data, or in findings → fail (blind verdict)."""
        alert = _alert(entities={"user": "alice"})
        verdict = _verdict(findings=[_finding(statement="generic.", evidence="generic.")])
        obs = [_ok_obs("query_logs", data={"unrelated": "value"})]
        passed, uncovered = check_coverage(
            verdict, obs, alert, call_args=[{"entity": "someone-else"}]
        )
        assert not passed
        assert uncovered == ["alice"]


# ---------------------------------------------------------------------------
# verify() — combined entry point
# ---------------------------------------------------------------------------


class TestVerify:
    def test_all_checks_pass_returns_passed_true(self) -> None:
        """All four checks pass → VerificationResult.passed is True."""
        alert = _alert()
        obs = [
            _ok_obs("query_logs", data={"user": "alice", "dest": "10.0.0.9"}),
            _ok_obs("lookup_user", data={"user": "alice", "status": "active"}),
        ]
        verdict = _verdict(
            confidence=0.85,
            findings=[
                _finding(
                    statement="alice exfiltrated data to 10.0.0.9.",
                    evidence="query_logs showed alice outbound to 10.0.0.9.",
                )
            ],
            actions=[Action(name="block_user", params={"user": "alice"})],
        )
        result = verify(verdict, obs, alert)
        assert isinstance(result, VerificationResult)
        assert result.passed is True
        assert result.failed_checks == []
        assert len(result.checks) == 4

    def test_returns_verification_result_type(self) -> None:
        """verify() always returns a VerificationResult."""
        result = verify(_verdict(), [], _alert())
        assert isinstance(result, VerificationResult)

    def test_checks_list_has_four_entries(self) -> None:
        """The checks list always has exactly four entries regardless of outcome."""
        result = verify(_verdict(), [], _alert())
        assert len(result.checks) == 4
        check_names = [c["name"] for c in result.checks]
        assert "citation_validity" in check_names
        assert "confidence_consistency" in check_names
        assert "action_traceability" in check_names
        assert "coverage" in check_names

    def test_failed_confidence_produces_failed_result(self) -> None:
        """A verdict with ok_count=0 and confidence outside [0.30, 0.40] fails."""
        obs = [_fail_obs()]
        # Confidence 0.70 violates the zero-evidence band.
        verdict = _verdict(confidence=0.70, findings=[], actions=[])
        result = verify(verdict, obs, _alert())
        assert result.passed is False
        assert "confidence_consistency" in result.failed_checks

    def test_hallucinated_citation_produces_failed_result(self) -> None:
        """A verdict with a hallucinated citation (no grounding) fails citation check."""
        obs = [_ok_obs("query_logs")]
        verdict = _verdict(
            confidence=0.7,
            findings=[
                _finding(evidence="A completely fabricated source with no grounding whatsoever.")
            ],
        )
        result = verify(verdict, obs, _alert())
        assert result.passed is False
        assert "citation_validity" in result.failed_checks
        assert 0 in result.failed_findings

    def test_uncovered_entities_reported(self) -> None:
        """Uncovered entities appear in uncovered_entities field."""
        alert = _alert(entities={"user": "alice", "ip": "10.0.0.9"})
        obs = [_fail_obs()]
        verdict = _verdict(
            confidence=0.35,
            findings=[_finding(statement="No tool data.", evidence="lookup_user returned error.")],
        )
        result = verify(verdict, obs, alert)
        # Both entities uncovered (obs data has nothing; findings don't mention them)
        assert isinstance(result.uncovered_entities, list)

    def test_all_checks_run_even_when_first_fails(self) -> None:
        """All four checks run regardless of earlier failures — full result available."""
        obs = [_fail_obs()]
        # Confidence 0.70 fails check 2; also no observations (check 4 may fail).
        verdict = _verdict(confidence=0.70, findings=[], actions=[])
        result = verify(verdict, obs, _alert())
        # All four checks should appear in result.checks.
        assert len(result.checks) == 4

    def test_zero_evidence_in_band_confidence_passes_check2(self) -> None:
        """Zero-evidence run with confidence in [0.30, 0.40] passes check 2."""
        obs = [_fail_obs()]
        verdict = _verdict(confidence=0.35, findings=[], actions=[])
        result = verify(verdict, obs, _alert())
        c2 = next(c for c in result.checks if c["name"] == "confidence_consistency")
        assert c2["passed"] is True

    def test_passed_field_is_false_when_any_check_fails(self) -> None:
        """passed is False as soon as any check fails."""
        obs = [_fail_obs()]
        verdict = _verdict(confidence=0.9)  # Fails: confidence >= 0.8, ok < 2
        result = verify(verdict, obs, _alert())
        assert result.passed is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_no_observations_no_findings_no_entities(self) -> None:
        """Minimal input — no crash, returns a VerificationResult."""
        alert = _alert(entities={})
        verdict = _verdict(confidence=0.35, findings=[], actions=[])
        result = verify(verdict, [], alert)
        assert isinstance(result, VerificationResult)

    def test_deeply_nested_observation_data_values_found(self) -> None:
        """String values nested in observation data are found by citation check."""
        nested_data = {"outer": {"inner": "deeply_nested_value"}}
        obs = [_ok_obs("query_logs", data=nested_data)]
        verdict = _verdict(
            confidence=0.8,
            findings=[_finding(evidence="deeply_nested_value was flagged.")],
        )
        obs2 = [_ok_obs("lookup_user", data={"user": "alice"})]
        passed, _failed = check_citation_validity(verdict, obs + obs2, _alert())
        assert passed

    def test_empty_string_entity_value_skipped(self) -> None:
        """An empty-string entity value is skipped in coverage (not counted as uncovered)."""
        alert = _alert(entities={"user": "", "ip": "10.0.0.9"})
        verdict = _verdict(
            findings=[_finding(statement="10.0.0.9 investigated.", evidence="10.0.0.9 found.")],
        )
        _passed, uncovered = check_coverage(verdict, [], alert)
        # Empty string is skipped; '10.0.0.9' is covered.
        assert "" not in uncovered
        assert "10.0.0.9" not in uncovered

    def test_verification_result_is_immutable(self) -> None:
        """VerificationResult is a frozen dataclass — attempting mutation raises."""
        result = verify(_verdict(), [], _alert())
        assert dataclasses.is_dataclass(result)
        try:
            result.passed = not result.passed  # ty: ignore[invalid-assignment]
            pytest.fail("Expected AttributeError for frozen dataclass")
        except (AttributeError, TypeError):
            pass  # Expected — frozen dataclass.

    def test_verify_action_traceability_failure_recorded(self) -> None:
        """verify() records action_traceability as failed when an untraceable action is present."""
        # One ok obs, one finding about alice, but the action targets mallory.
        obs = [_ok_obs("query_logs", data={"user": "alice"})]
        verdict = _verdict(
            confidence=0.7,
            findings=[
                _finding(statement="alice exfiltrated.", evidence="query_logs showed alice."),
            ],
            actions=[Action(name="block_user", params={"user": "mallory"})],
        )
        result = verify(verdict, obs, _alert())
        assert result.passed is False
        assert "action_traceability" in result.failed_checks

    def test_collect_string_values_with_nested_list(self) -> None:
        """_collect_string_values handles list values in observation data."""
        out: set[str] = set()
        _collect_string_values(["hello", "world", 42], out)
        assert out == {"hello", "world"}

    def test_collect_string_values_empty_string_skipped(self) -> None:
        """_collect_string_values skips empty strings."""
        out: set[str] = set()
        _collect_string_values("", out)
        assert out == set()

    def test_entity_scalars_with_list_containing_non_strings(self) -> None:
        """_entity_scalars extracts only string items from list entity values."""
        alert = _alert(entities={"items": ["valid", 42, "", "also_valid"]})  # type: ignore[arg-value]
        scalars = _entity_scalars(alert)
        assert "valid" in scalars
        assert "also_valid" in scalars
        assert 42 not in scalars  # type: ignore[operator]
        assert "" not in scalars

    def test_entity_scalars_with_empty_string_item_in_list(self) -> None:
        """Empty string items in list entity values are excluded by _entity_scalars."""
        # A list entity where one item is empty string — must not appear in output.
        alert = _alert(entities={"tags": ["", "non-empty"]})
        scalars = _entity_scalars(alert)
        assert "" not in scalars
        assert "non-empty" in scalars

    def test_observation_data_with_list_value_covers_entity(self) -> None:
        """String items in an observation data list value cover an entity."""
        alert = _alert(entities={"ip": "10.0.0.9"})
        # data contains a list with the entity value as a string item
        obs = [_ok_obs("query_logs", data={"addresses": ["10.0.0.9", "192.168.1.1"]})]
        verdict = _verdict(findings=[])
        _passed, uncovered = check_coverage(verdict, obs, alert)
        assert "10.0.0.9" not in uncovered
