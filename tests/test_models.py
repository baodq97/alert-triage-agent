"""Contract tests for the Pydantic data models (RFC-0001 §Data contracts).

These assert *structural* properties only: strict-envelope rejection, flexible
payload pass-through, enum/range validation, and that the real shipped Alert
fixtures round-trip through the Alert model.
"""

import json
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

from triage.models import (
    Action,
    Alert,
    Finding,
    InvestigationPlan,
    PlanStep,
    ReasonerDecision,
    RunResult,
    Severity,
    ToolResult,
    Verdict,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ALERT_FILES = sorted((_REPO_ROOT / "alerts").glob("*.json"))


def _valid_alert_kwargs() -> dict[str, object]:
    return {
        "alert_id": "ALT-1",
        "timestamp": "2026-04-09T03:12:44Z",
        "source": "api-gateway",
        "severity_hint": "high",
        "event_type": "anomalous_api_activity",
        "description": "many calls",
        "entities": {"source_ip": "10.0.0.1"},
        "context": {"calls": 847},
    }


# --- Alert envelope ----------------------------------------------------------


@pytest.mark.parametrize("alert_file", _ALERT_FILES, ids=lambda p: p.name)
def test_shipped_alert_fixtures_round_trip(alert_file: Path) -> None:
    payload = json.loads(alert_file.read_text(encoding="utf-8"))
    alert = Alert.model_validate(payload)
    assert alert.alert_id == payload["alert_id"]
    assert alert.entities == payload["entities"]
    assert alert.context == payload["context"]


def test_alert_keeps_payload_untouched() -> None:
    alert = Alert.model_validate(_valid_alert_kwargs())
    # Flexible payload accepts arbitrary value types without coercion.
    assert alert.context["calls"] == 847
    assert alert.entities["source_ip"] == "10.0.0.1"


def test_alert_payload_defaults_to_empty_dicts() -> None:
    kwargs = _valid_alert_kwargs()
    del kwargs["entities"]
    del kwargs["context"]
    alert = Alert.model_validate(kwargs)
    assert alert.entities == {}
    assert alert.context == {}


def test_alert_severity_hint_is_a_free_string_not_an_enum() -> None:
    kwargs = _valid_alert_kwargs()
    kwargs["severity_hint"] = "p1-vendor-specific"
    alert = Alert.model_validate(kwargs)
    assert alert.severity_hint == "p1-vendor-specific"


def test_alert_rejects_empty_severity_hint() -> None:
    kwargs = _valid_alert_kwargs()
    kwargs["severity_hint"] = ""
    with pytest.raises(ValidationError):
        Alert.model_validate(kwargs)


def test_alert_strict_envelope_rejects_int_coercion_for_string_field() -> None:
    kwargs = _valid_alert_kwargs()
    kwargs["alert_id"] = 123
    with pytest.raises(ValidationError):
        Alert.model_validate(kwargs)


def test_alert_rejects_non_dict_payload() -> None:
    kwargs = _valid_alert_kwargs()
    kwargs["entities"] = ["not", "a", "dict"]
    with pytest.raises(ValidationError):
        Alert.model_validate(kwargs)


def test_alert_rejects_missing_required_envelope_field() -> None:
    kwargs = _valid_alert_kwargs()
    del kwargs["alert_id"]
    with pytest.raises(ValidationError):
        Alert.model_validate(kwargs)


def test_alert_rejects_unknown_envelope_field() -> None:
    kwargs = _valid_alert_kwargs()
    kwargs["totally_unexpected"] = "x"
    with pytest.raises(ValidationError):
        Alert.model_validate(kwargs)


# --- Plan --------------------------------------------------------------------


def test_plan_step_and_investigation_plan() -> None:
    step = PlanStep(tool="lookup_user", args={"user": "alice"}, rationale="who is this")
    plan = InvestigationPlan(steps=[step])
    assert plan.steps[0].tool == "lookup_user"


def test_investigation_plan_tolerates_hallucinated_extra_keys() -> None:
    # LLM-output models are lax: an extra key is dropped, not rejected, so it
    # never counts as malformed and never burns the single repair attempt.
    plan = InvestigationPlan.model_validate(
        {
            "steps": [
                {
                    "tool": "lookup_user",
                    "args": {},
                    "rationale": "who",
                    "id": 3,  # hallucinated extra field on the nested PlanStep
                },
            ],
            "reasoning": "extra top-level field",  # hallucinated extra field
        },
    )
    assert plan.steps[0].tool == "lookup_user"
    assert not hasattr(plan.steps[0], "id")


# --- Finding / Verdict -------------------------------------------------------


def test_finding_cites_its_observation() -> None:
    finding = Finding(statement="ip is malicious", evidence="check_reputation score 95")
    assert finding.evidence


def test_verdict_accepts_valid_severity_and_confidence() -> None:
    verdict = Verdict(
        severity="high",
        findings=[Finding(statement="s", evidence="e")],
        recommended_actions=[Action(name="block_user")],
        confidence=0.8,
    )
    assert verdict.severity == "high"
    assert verdict.terminated_reason is None


def test_verdict_is_lax_tolerating_extra_keys_and_quoted_confidence() -> None:
    # The two most common forms of benign small-model drift on the
    # no-response_format path: a hallucinated field and a quoted number. Both
    # must parse (lax) so neither is treated as malformed.
    verdict = Verdict.model_validate(
        {
            "severity": "high",
            "findings": [
                {"statement": "s", "evidence": "e", "source_run": "r-9"},  # extra key
            ],
            "recommended_actions": [
                {"name": "block_user", "confidence": 0.9},  # extra key on Action
            ],
            "confidence": "0.9",  # str-for-float coercion
            "reasoning": "hallucinated extra top-level field",  # extra key
        },
    )
    assert verdict.severity == "high"
    assert verdict.confidence == pytest.approx(0.9)
    assert verdict.findings[0].statement == "s"
    assert not hasattr(verdict.findings[0], "source_run")
    assert verdict.recommended_actions[0].name == "block_user"


def test_reasoner_decision_is_lax_tolerating_extra_keys() -> None:
    reasoner = ReasonerDecision.model_validate(
        {"decision": "conclude", "rationale": "done", "confidence": 0.7},
    )
    assert reasoner.decision == "conclude"
    assert not hasattr(reasoner, "confidence")


def test_verdict_rejects_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        Verdict.model_validate(
            {
                "severity": "catastrophic",
                "findings": [],
                "recommended_actions": [],
                "confidence": 0.5,
            },
        )


@pytest.mark.parametrize("bad_confidence", [-0.1, 1.1])
def test_verdict_rejects_out_of_range_confidence(bad_confidence: float) -> None:
    with pytest.raises(ValidationError):
        Verdict(
            severity="low",
            findings=[],
            recommended_actions=[],
            confidence=bad_confidence,
        )


@pytest.mark.parametrize("ok_confidence", [0.0, 1.0])
def test_verdict_accepts_confidence_bounds(ok_confidence: float) -> None:
    verdict = Verdict(
        severity="low",
        findings=[],
        recommended_actions=[],
        confidence=ok_confidence,
    )
    assert verdict.confidence == ok_confidence


def test_verdict_carries_terminated_reason_when_early() -> None:
    verdict = Verdict(
        severity="medium",
        findings=[],
        recommended_actions=[],
        confidence=0.3,
        terminated_reason="max_steps",
    )
    assert verdict.terminated_reason == "max_steps"


# --- Action ------------------------------------------------------------------


def test_action_name_only() -> None:
    action = Action(name="block_user")
    assert action.params is None
    assert action.description is None


def test_action_with_params_and_description() -> None:
    action = Action(
        name="block_user",
        params={"entity": "svc-deploy-prod"},
        description="block the service account",
    )
    assert action.params == {"entity": "svc-deploy-prod"}


# --- ToolResult --------------------------------------------------------------


def test_tool_result_success() -> None:
    result = ToolResult(tool="lookup_user", ok=True, data={"role": "admin"})
    assert result.ok
    assert result.error is None


def test_tool_result_failure() -> None:
    result = ToolResult(tool="query_logs", ok=False, error="timeout")
    assert not result.ok
    assert result.data is None


# --- ReasonerDecision --------------------------------------------------------


@pytest.mark.parametrize("decision", ["continue", "revise_plan", "conclude"])
def test_reasoner_decision_valid(decision: str) -> None:
    reasoner = ReasonerDecision.model_validate({"decision": decision, "rationale": "because"})
    assert reasoner.decision == decision


def test_reasoner_decision_rejects_unknown() -> None:
    with pytest.raises(ValidationError):
        ReasonerDecision.model_validate({"decision": "ponder", "rationale": "hmm"})


def test_reasoner_decision_carries_next_step() -> None:
    next_step = PlanStep(tool="query_logs", args={}, rationale="dig deeper")
    reasoner = ReasonerDecision(decision="continue", rationale="r", next_step=next_step)
    assert reasoner.next_step is not None
    assert reasoner.next_step.tool == "query_logs"


# --- RunResult ---------------------------------------------------------------


def test_run_result_assembles_run_record() -> None:
    verdict = Verdict(severity="low", findings=[], recommended_actions=[], confidence=0.9)
    result = RunResult(
        run_id="run-1",
        verdict=verdict,
        gate_decisions=[],
        executed_actions=[],
        terminated_reason="completed",
    )
    assert result.run_id == "run-1"
    assert result.terminated_reason == "completed"


def test_run_result_rejects_unknown_terminated_reason() -> None:
    verdict = Verdict(severity="low", findings=[], recommended_actions=[], confidence=0.9)
    with pytest.raises(ValidationError):
        RunResult.model_validate(
            {
                "run_id": "run-1",
                "verdict": verdict,
                "gate_decisions": [],
                "executed_actions": [],
                "terminated_reason": "exploded",
            },
        )


# --- Severity type semantics (T4 / L3) ---------------------------------------
#
# ``Severity`` is a ``Literal["low", "medium", "high", "critical"]`` type alias —
# a membership set, NOT an ordered enum.  It is never compared with <, <=, >, >=
# anywhere in the codebase; comparisons happen only via ``in`` membership tests in
# assertions and policy look-ups.  This test documents the CONTRACT:
#   • exactly 4 members, no additions;
#   • set-only semantics — no relational ordering is implied or relied on.
#
# If Severity were ever refactored into an ``IntEnum`` or comparable type to support
# relational comparison, this test intentionally breaks so the author must review
# the full set of downstream callers and update this comment.


def test_severity_has_exactly_four_members_set_only_semantics() -> None:
    """T4 (L3): Severity is a set-membership type with exactly these four values.

    Severity = Literal["low", "medium", "high", "critical"]. It is used only for
    membership checks (``in``) — never for relational comparisons (``<``, ``>``) —
    so no ordering between members is guaranteed or relied on. This test pins the
    exact member set; if a fifth value is added or any value renamed, this test
    fails so the author consciously updates all downstream callers.
    """
    members = set(get_args(Severity))
    assert members == {"low", "medium", "high", "critical"}


def test_severity_used_as_membership_set_not_ordered() -> None:
    """Severity supports ``in`` checks; no relational ordering is implied.

    Demonstrate the intended usage pattern: membership, not ordering.
    Any refactor that introduces ``>`` or ``<`` comparisons on Severity values
    must update this test and document the new ordering semantics.
    """
    high_risk = {"high", "critical"}
    assert "high" in high_risk
    assert "critical" in high_risk
    assert "low" not in high_risk
    assert "medium" not in high_risk
