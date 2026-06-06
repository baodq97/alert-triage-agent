"""Tests for the eval harness (US-0003) — Tier A, deterministic, key-free.

Coverage targets (the eval-authoring skill is the contract):

* **assertion-engine purity** — ``assert_case`` is scored against a *constructed*
  ``RunRecord`` dict, importing only ``triage.evals.assertions`` /
  ``triage.evals.models``, never the runner (the AC: a foreign tool reuses the
  checks without importing the runner);
* every Tier-1 assertion type, positive AND negative;
* **Replay Mode** — ``ReplayLLM`` serves by ``prompt_hash`` and raises ``ReplayMiss``
  (a non-``LLMError`` typed error) on a miss; ``RecordingLLM`` round-trips a run
  into a cache that drives an identical replay with no script left (the tests-only
  synthetic fixture, generated deterministically — NO live calls);
* the **runner** end-to-end against a ``FakeLLM``-driven live-mode run of one case,
  nonzero exit on a failing Tier-1, and the advisory **Judge** never blocking;
* the loaders, the 6 shipped golden cases parse, and the deepeval adapter seam.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, TypeVar

import pytest
from pydantic import BaseModel

from tests._helpers import CapturingLLM
from triage.errors import ConfigError, LLMError
from triage.evals import runner
from triage.evals.adapters import DeepEvalProjection, project_reference
from triage.evals.assertions import assert_case
from triage.evals.judge import Judge
from triage.evals.loader import load_case, load_cases, load_run_record
from triage.evals.models import (
    GoldenCase,
    RunRecord,
    ScoreResult,
    TrajectoryExpect,
    VerdictExpect,
)
from triage.evals.replay import (
    REPLAY_SCHEMA_VERSION,
    RecordingLLM,
    ReplayCache,
    ReplayCacheError,
    ReplayError,
    ReplayLLM,
    ReplayMiss,
    replay_path,
)
from triage.evals.runner import (
    _CASES_DIR,
    case_replay_path,
    evaluate_case,
    format_report,
    run_case,
    run_suite,
)
from triage.journal import NoopJournal
from triage.llm import Completion, FakeLLM, Message, prompt_hash
from triage.models import Alert, ReasonerDecision, Verdict

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

T = TypeVar("T", bound=BaseModel)

# Purity boundary: the assertion engine + eval models are imported here WITHOUT the
# runner. ``test_assert_case_is_pure_over_a_constructed_record`` uses ONLY these two
# imports to score a hand-built record — proving a foreign tool reuses the checks
# without importing the runner (US-0003 AC). The runner/replay/judge imports above
# serve the other tests; they never participate in the purity test.

# --- shared builders ---------------------------------------------------------


def _event(seq: int, event: str, **payload: object) -> dict[str, object]:
    return {
        "seq": seq,
        "event_id": f"e{seq}",
        "ts": "2026-06-05T00:00:00Z",
        "event": event,
        **payload,
    }


def _verdict_obj(
    *,
    severity: str = "high",
    confidence: float = 0.8,
    findings: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "severity": severity,
        "confidence": confidence,
        "findings": findings
        if findings is not None
        else [
            {"statement": "svc-deploy-prod exfiltrated via 10.200.3.47", "evidence": "query_logs"}
        ],
        "recommended_actions": [],
        "terminated_reason": "completed",
    }


def _record(
    *,
    events: list[dict[str, object]] | None = None,
    terminated_reason: str = "completed",
    verdict: dict[str, object] | None = None,
) -> RunRecord:
    return RunRecord(
        result={
            "run_id": "R1",
            "terminated_reason": terminated_reason,
            "verdict": verdict if verdict is not None else _verdict_obj(),
        },
        journal=events if events is not None else [],
    )


def _case(
    trajectory: dict[str, Any] | None = None, verdict: dict[str, Any] | None = None
) -> GoldenCase:
    return GoldenCase(
        name="c",
        alert="alerts/x.json",
        trajectory=TrajectoryExpect.model_validate(trajectory or {}),
        verdict=VerdictExpect.model_validate(verdict or {}),
    )


def _names(results: list[ScoreResult]) -> dict[str, ScoreResult]:
    return {r.name: r for r in results}


# --- purity: constructed run_record, no runner import ------------------------


def test_assert_case_is_pure_over_a_constructed_record() -> None:
    # A foreign tool feeds a hand-built RunRecord dict and the case; no runner.
    record = _record(
        events=[
            _event(1, "tool_called", step=1, tool="check_reputation", args={"entity": "ip"}),
            _event(2, "tool_called", step=2, tool="query_logs", args={"entity": "svc"}),
        ],
    )
    case = _case(
        trajectory={"must_call_tools": ["check_reputation", "query_logs"]},
        verdict={"severity_in": ["high", "critical"]},
    )
    results = assert_case(case, record)

    assert all(r.passed for r in results)
    assert _names(results).keys() == {"must_call_tools", "severity_in"}


def test_importing_the_assertion_engine_does_not_import_the_runner() -> None:
    # US-0003 AC: a foreign tool reuses the checks WITHOUT importing the runner. Run
    # in a fresh subprocess so sibling tests' imports cannot mask the result. The
    # parent ``triage`` package __init__ (owned by another wave) eagerly imports
    # ``triage.core``, which is outside this layer's control; the contract this test
    # enforces is the one in scope — importing the pure engine pulls in NONE of the
    # eval harness's heavier modules (runner, judge, replay, loader, adapters).
    import subprocess  # noqa: PLC0415 — local: only this isolation test needs a subprocess.
    import sys  # noqa: PLC0415 — local: see above.

    forbidden = (
        "triage.evals.runner",
        "triage.evals.judge",
        "triage.evals.replay",
        "triage.evals.loader",
        "triage.evals.adapters",
    )
    code = (
        "import sys\n"
        "from triage.evals.assertions import assert_case\n"
        f"leaked = [m for m in {forbidden!r} if m in sys.modules]\n"
        "assert not leaked, leaked\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)  # noqa: S603 — fixed interpreter + a constant literal program, no untrusted input.


def test_empty_expectations_yield_no_scores() -> None:
    assert assert_case(_case(), _record()) == []


# --- must_call_tools ---------------------------------------------------------


def test_must_call_tools_positive_and_negative() -> None:
    events = [_event(1, "tool_called", step=1, tool="query_logs", args={})]
    ok = assert_case(_case(trajectory={"must_call_tools": ["query_logs"]}), _record(events=events))
    bad = assert_case(
        _case(trajectory={"must_call_tools": ["check_reputation"]}), _record(events=events)
    )

    assert _names(ok)["must_call_tools"].passed
    assert not _names(bad)["must_call_tools"].passed
    assert "check_reputation" in _names(bad)["must_call_tools"].detail


# --- must_observe_tool_failure ------------------------------------------------


def test_must_observe_tool_failure_positive_and_negative() -> None:
    # E2: a failure + a subsequent llm_call passes; failure with no subsequent llm_call fails.
    failed_with_continue = [
        _event(1, "tool_called", step=1, tool="query_logs", args={}, attempt=1),
        _event(2, "tool_result", step=1, attempt=1, ok=False, error="not found"),
        _event(3, "llm_call", purpose="reason", model="m", prompt_hash="h", tokens=0, latency_ms=1),
    ]
    succeeded = [
        _event(1, "tool_called", step=1, tool="query_logs", args={}, attempt=1),
        _event(2, "tool_result", step=1, attempt=1, ok=True, data={}),
    ]
    expect = {"must_observe_tool_failure": True}
    ok = assert_case(_case(trajectory=expect), _record(events=failed_with_continue))
    bad = assert_case(_case(trajectory=expect), _record(events=succeeded))

    assert _names(ok)["must_observe_tool_failure"].passed
    assert not _names(bad)["must_observe_tool_failure"].passed
    assert "no tool_result" in _names(bad)["must_observe_tool_failure"].detail


def test_must_observe_tool_failure_requires_llm_call_after_first_failure() -> None:
    """E2 strengthening: a failed tool_result alone is not enough — a subsequent
    llm_call with seq > first_failure_seq must exist to prove the loop continued."""
    # Failure at seq 2, no subsequent llm_call → must fail even though failure exists.
    failure_no_continuation = [
        _event(1, "tool_called", step=1, tool="query_logs", args={}, attempt=1),
        _event(2, "tool_result", step=1, attempt=1, ok=False, error="timeout"),
    ]
    # Failure at seq 2, then llm_call at seq 3 → passes.
    failure_with_continuation = [
        _event(1, "tool_called", step=1, tool="query_logs", args={}, attempt=1),
        _event(2, "tool_result", step=1, attempt=1, ok=False, error="timeout"),
        _event(
            3, "llm_call", purpose="reason", model="m", prompt_hash="h2", tokens=0, latency_ms=1
        ),
    ]
    expect = {"must_observe_tool_failure": True}

    no_cont = assert_case(_case(trajectory=expect), _record(events=failure_no_continuation))
    with_cont = assert_case(_case(trajectory=expect), _record(events=failure_with_continuation))

    assert not _names(no_cont)["must_observe_tool_failure"].passed
    assert "loop did not continue" in _names(no_cont)["must_observe_tool_failure"].detail
    assert _names(with_cont)["must_observe_tool_failure"].passed


def test_must_observe_tool_failure_absent_field_is_silent() -> None:
    events = [_event(1, "tool_result", step=1, attempt=1, ok=True, data={})]
    results = assert_case(_case(trajectory={"must_call_tools": []}), _record(events=events))

    assert "must_observe_tool_failure" not in _names(results)


# --- denied_actions_not_executed (E1) ----------------------------------------


_BLOCK_ALICE = {"name": "block_user", "params": {"user": "alice"}}
_BLOCK_NOPARAMS = {"name": "block_user", "params": {}}


def test_denied_actions_not_executed_passes_when_none_executed_after_denial() -> None:
    """E1: an action denied at the gate and never executed → passes."""
    events = [
        _event(1, "gate_requested", actions=[_BLOCK_ALICE], risk="high_risk"),
        _event(2, "gate_decision", decision="denied", by="auto"),
        # No action_executed event: the denial was honoured.
    ]
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    assert _names(results)["denied_actions_not_executed"].passed


def test_denied_actions_not_executed_fails_when_denied_action_is_executed() -> None:
    """E1: an action denied at the gate but later appearing as action_executed → fails."""
    events = [
        _event(1, "gate_requested", actions=[_BLOCK_ALICE], risk="high_risk"),
        _event(2, "gate_decision", decision="denied", by="auto"),
        _event(3, "action_executed", action=_BLOCK_ALICE, result={}),
    ]
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    r = _names(results)["denied_actions_not_executed"]
    assert not r.passed
    assert "block_user" in r.detail


def test_denied_actions_not_executed_vacuous_pass_with_no_denial() -> None:
    """E1: no gate_decision(denied) in the journal → vacuous pass (nothing was denied)."""
    events = [
        _event(1, "gate_requested", actions=[_BLOCK_NOPARAMS], risk="high_risk"),
        _event(2, "gate_decision", decision="approved", by="auto"),
        _event(3, "action_executed", action=_BLOCK_NOPARAMS, result={}),
    ]
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    assert _names(results)["denied_actions_not_executed"].passed


def test_denied_actions_not_executed_ignores_executed_before_denial() -> None:
    """E1: an action_executed whose seq is BEFORE the denial is not a violation."""
    events = [
        _event(1, "gate_requested", actions=[_BLOCK_ALICE], risk="high_risk"),
        _event(2, "action_executed", action=_BLOCK_ALICE, result={}),
        _event(3, "gate_decision", decision="denied", by="auto"),
    ]
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    # Executed at seq 2 < denial seq 3 — not a post-denial violation.
    assert _names(results)["denied_actions_not_executed"].passed


def test_denied_actions_not_executed_absent_field_is_silent() -> None:
    """E1: the assertion emits nothing when the field is not set."""
    events = [
        _event(1, "gate_decision", decision="denied", by="auto"),
    ]
    results = assert_case(_case(trajectory={}), _record(events=events))
    assert "denied_actions_not_executed" not in _names(results)


def test_denied_actions_not_executed_non_list_actions_ignored() -> None:
    """E1 coverage: gate_requested with non-list actions field does not crash and
    produces a vacuous pass (no batch was registered, so no denials are tracked)."""
    events = [
        # actions is a string, not a list — malformed event; the helper must ignore it
        _event(1, "gate_requested", actions="not-a-list", risk="high_risk"),
        _event(2, "gate_decision", decision="denied", by="auto"),
        # No action_executed: irrelevant since the batch was never registered.
    ]
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    # No batch was registered (raw_actions not a list), so no denied keys → vacuous pass.
    assert _names(results)["denied_actions_not_executed"].passed


def test_denied_actions_not_executed_denial_before_any_gate_requested() -> None:
    """E1 coverage: gate_decision(denied) with no preceding gate_requested is
    ignored gracefully (no crash, no denied keys collected)."""
    events = [
        # gate_decision arrives before any gate_requested — no batch to match against
        _event(1, "gate_decision", decision="denied", by="auto"),
        _event(2, "action_executed", action=_BLOCK_ALICE, result={}),
    ]
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    # No gate_requested precedes the denial, so denied_keys is empty → vacuous pass.
    assert _names(results)["denied_actions_not_executed"].passed


def test_action_key_with_non_dict_action() -> None:
    """Coverage: _action_key with a non-dict value falls back to repr()."""
    # Drive through _denied_action_keys by placing a non-dict element inside the
    # gate_requested actions list.  The key must still be a string (not crash).
    events = [
        _event(1, "gate_requested", actions=["not-a-dict"], risk="high_risk"),
        _event(2, "gate_decision", decision="denied", by="auto"),
    ]
    # Vacuous pass: even though a non-dict action was in the batch, no action_executed
    # follows with a matching key.
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    assert _names(results)["denied_actions_not_executed"].passed


def test_action_key_with_none_params() -> None:
    """Coverage: _action_key with params=None hits the repr(params) branch."""
    action_no_params = {"name": "block_user", "params": None}
    events = [
        _event(1, "gate_requested", actions=[action_no_params], risk="high_risk"),
        _event(2, "gate_decision", decision="denied", by="auto"),
        # Executed with matching name+params=None — must be caught as violation.
        _event(3, "action_executed", action=action_no_params, result={}),
    ]
    results = assert_case(
        _case(trajectory={"denied_actions_not_executed": True}), _record(events=events)
    )
    r = _names(results)["denied_actions_not_executed"]
    assert not r.passed
    assert "block_user" in r.detail


# --- gate_before_high_risk / no_action_without_gate --------------------------


def test_gate_before_high_risk_passes_when_executed_after_approval() -> None:
    events = [
        _event(1, "gate_decision", decision="approved", by="auto"),
        _event(2, "action_executed", action={"name": "block_user"}, result={}),
    ]
    results = assert_case(_case(trajectory={"gate_before_high_risk": True}), _record(events=events))
    assert _names(results)["gate_before_high_risk"].passed


def test_gate_before_high_risk_passes_with_no_executed_action() -> None:
    results = assert_case(_case(trajectory={"gate_before_high_risk": True}), _record(events=[]))
    assert _names(results)["gate_before_high_risk"].passed


def test_gate_before_high_risk_fails_when_executed_before_approval() -> None:
    events = [
        _event(1, "action_executed", action={"name": "block_user"}, result={}),
        _event(2, "gate_decision", decision="approved", by="auto"),
    ]
    results = assert_case(_case(trajectory={"gate_before_high_risk": True}), _record(events=events))
    assert not _names(results)["gate_before_high_risk"].passed


def test_gate_before_high_risk_fails_when_executed_with_no_approval() -> None:
    events = [_event(1, "action_executed", action={"name": "block_user"}, result={})]
    results = assert_case(_case(trajectory={"gate_before_high_risk": True}), _record(events=events))
    r = _names(results)["gate_before_high_risk"]
    assert not r.passed
    assert "no gate_decision(approved)" in r.detail


def test_no_action_without_gate_positive_negative_and_no_action() -> None:
    after = [
        _event(1, "gate_decision", decision="approved", by="auto"),
        _event(2, "action_executed", action={"name": "block_user"}, result={}),
    ]
    before = [
        _event(1, "action_executed", action={"name": "block_user"}, result={}),
        _event(2, "gate_decision", decision="approved", by="auto"),
    ]
    none_executed = assert_case(
        _case(trajectory={"no_action_without_gate": True}),
        _record(events=[]),
    )
    no_approval = assert_case(
        _case(trajectory={"no_action_without_gate": True}),
        _record(events=[_event(1, "action_executed", action={}, result={})]),
    )

    assert _names(
        assert_case(_case(trajectory={"no_action_without_gate": True}), _record(events=after))
    )["no_action_without_gate"].passed
    assert not _names(
        assert_case(_case(trajectory={"no_action_without_gate": True}), _record(events=before)),
    )["no_action_without_gate"].passed
    assert _names(none_executed)["no_action_without_gate"].passed
    assert not _names(no_approval)["no_action_without_gate"].passed


# --- max_steps_respected -----------------------------------------------------


def test_max_steps_respected_positive_and_negative() -> None:
    ok = assert_case(
        _case(trajectory={"max_steps_respected": True}),
        _record(terminated_reason="completed"),
    )
    bad = assert_case(
        _case(trajectory={"max_steps_respected": True}),
        _record(terminated_reason="max_steps"),
    )
    assert _names(ok)["max_steps_respected"].passed
    assert not _names(bad)["max_steps_respected"].passed


# --- no_repeated_identical_calls ---------------------------------------------


def test_no_repeated_identical_calls_positive_and_negative() -> None:
    distinct = [
        _event(1, "tool_called", step=1, tool="query_logs", args={"entity": "a"}),
        _event(2, "tool_called", step=2, tool="query_logs", args={"entity": "b"}),
    ]
    repeated = [
        _event(1, "tool_called", step=1, tool="query_logs", args={"entity": "a"}),
        _event(2, "tool_called", step=2, tool="query_logs", args={"entity": "a"}),
    ]
    ok = assert_case(
        _case(trajectory={"no_repeated_identical_calls": True}), _record(events=distinct)
    )
    bad = assert_case(
        _case(trajectory={"no_repeated_identical_calls": True}), _record(events=repeated)
    )
    assert _names(ok)["no_repeated_identical_calls"].passed
    assert not _names(bad)["no_repeated_identical_calls"].passed


def test_no_repeated_identical_calls_handles_non_dict_args() -> None:
    events = [
        _event(1, "tool_called", step=1, tool="t", args=["a"]),
        _event(2, "tool_called", step=2, tool="t", args=["a"]),
    ]
    bad = assert_case(
        _case(trajectory={"no_repeated_identical_calls": True}), _record(events=events)
    )
    assert not _names(bad)["no_repeated_identical_calls"].passed


# --- terminated_reason_in ----------------------------------------------------


def test_terminated_reason_in_positive_and_negative() -> None:
    ok = assert_case(
        _case(trajectory={"terminated_reason_in": ["completed"]}),
        _record(terminated_reason="completed"),
    )
    bad = assert_case(
        _case(trajectory={"terminated_reason_in": ["completed"]}),
        _record(terminated_reason="error"),
    )
    assert _names(ok)["terminated_reason_in"].passed
    assert not _names(bad)["terminated_reason_in"].passed


# --- verdict assertions ------------------------------------------------------


def test_severity_in_positive_and_negative() -> None:
    ok = assert_case(
        _case(verdict={"severity_in": ["high"]}), _record(verdict=_verdict_obj(severity="high"))
    )
    bad = assert_case(
        _case(verdict={"severity_in": ["low"]}), _record(verdict=_verdict_obj(severity="high"))
    )
    assert _names(ok)["severity_in"].passed
    assert not _names(bad)["severity_in"].passed


def test_confidence_min_and_max_bounds() -> None:
    record = _record(verdict=_verdict_obj(confidence=0.5))
    assert _names(assert_case(_case(verdict={"confidence_min": 0.4}), record))[
        "confidence_min"
    ].passed
    assert not _names(assert_case(_case(verdict={"confidence_min": 0.6}), record))[
        "confidence_min"
    ].passed
    assert _names(assert_case(_case(verdict={"confidence_max": 0.6}), record))[
        "confidence_max"
    ].passed
    assert not _names(assert_case(_case(verdict={"confidence_max": 0.4}), record))[
        "confidence_max"
    ].passed


def test_confidence_rejects_boolean_and_missing() -> None:
    # A JSON ``true`` is an ``int`` subtype in Python; the check must not accept it.
    boolean = _record(verdict={"severity": "high", "confidence": True, "findings": []})
    missing = _record(verdict={"severity": "high", "findings": []})
    assert not _names(assert_case(_case(verdict={"confidence_min": 0.0}), boolean))[
        "confidence_min"
    ].passed
    assert not _names(assert_case(_case(verdict={"confidence_min": 0.0}), missing))[
        "confidence_min"
    ].passed


def test_must_reference_entities_case_insensitive_positive_and_negative() -> None:
    record = _record(
        verdict=_verdict_obj(
            findings=[{"statement": "Service account SVC-Deploy-Prod abused", "evidence": "logs"}],
        ),
    )
    ok = assert_case(_case(verdict={"must_reference_entities": ["svc-deploy-prod"]}), record)
    bad = assert_case(_case(verdict={"must_reference_entities": ["mallory"]}), record)
    assert _names(ok)["must_reference_entities"].passed
    assert not _names(bad)["must_reference_entities"].passed
    assert "mallory" in _names(bad)["must_reference_entities"].detail


def test_findings_with_citations_positive_no_findings_and_uncited() -> None:
    cited = _record(verdict=_verdict_obj(findings=[{"statement": "x", "evidence": "query_logs"}]))
    empty = _record(verdict=_verdict_obj(findings=[]))
    uncited = _record(verdict=_verdict_obj(findings=[{"statement": "x", "evidence": "  "}]))
    assert _names(assert_case(_case(verdict={"verdict_has_findings_with_citations": True}), cited))[
        "verdict_has_findings_with_citations"
    ].passed
    assert not _names(
        assert_case(_case(verdict={"verdict_has_findings_with_citations": True}), empty)
    )["verdict_has_findings_with_citations"].passed
    assert not _names(
        assert_case(_case(verdict={"verdict_has_findings_with_citations": True}), uncited)
    )["verdict_has_findings_with_citations"].passed


def test_malformed_verdict_block_is_tolerated() -> None:
    # A non-dict verdict (a degraded/foreign record) must not crash the engine.
    record = RunRecord(result={"terminated_reason": "error", "verdict": "broken"}, journal=[])
    results = assert_case(_case(verdict={"severity_in": ["low"]}), record)
    assert not _names(results)["severity_in"].passed


def test_malformed_findings_list_is_tolerated() -> None:
    # A verdict whose `findings` is not a list (foreign/degraded record) yields no
    # findings rather than crashing the citation/entity checks.
    record = RunRecord(
        result={
            "terminated_reason": "completed",
            "verdict": {"severity": "low", "findings": "oops"},
        },
        journal=[],
    )
    results = assert_case(
        _case(
            verdict={"verdict_has_findings_with_citations": True, "must_reference_entities": ["x"]}
        ),
        record,
    )
    assert not _names(results)["verdict_has_findings_with_citations"].passed
    assert not _names(results)["must_reference_entities"].passed


def test_non_integer_seq_sorts_first_without_crashing() -> None:
    # A journal line with a missing/odd `seq` must not crash ordering (seq is the
    # contract, but a degraded line is tolerated, sorted ahead of the valid ones).
    no_seq: dict[str, object] = {"event": "tool_called", "tool": "check_reputation", "args": {}}
    events = [
        _event(1, "tool_called", step=1, tool="query_logs", args={}),
        no_seq,
    ]
    results = assert_case(
        _case(trajectory={"must_call_tools": ["query_logs", "check_reputation"]}),
        _record(events=events),
    )
    assert _names(results)["must_call_tools"].passed


def test_events_are_scored_in_seq_order_even_when_unordered() -> None:
    # Out-of-file-order events still score correctly: seq is the contract.
    events = [
        _event(2, "gate_decision", decision="approved", by="auto"),
        _event(1, "tool_called", step=1, tool="query_logs", args={}),
        _event(3, "action_executed", action={"name": "block_user"}, result={}),
    ]
    results = assert_case(_case(trajectory={"gate_before_high_risk": True}), _record(events=events))
    assert _names(results)["gate_before_high_risk"].passed


# --- LLM scripts for full agent runs -----------------------------------------


def _plan(*tools: str) -> str:
    return json.dumps(
        {
            "steps": [
                {"tool": t, "args": {"entity": "svc-deploy-prod"}, "rationale": "x"} for t in tools
            ]
        },
    )


def _cont() -> str:
    return json.dumps({"decision": "continue", "rationale": "more"})


def _conclude() -> str:
    return json.dumps({"decision": "conclude", "rationale": "enough"})


def _verdict_json(*, severity: str = "high") -> str:
    return json.dumps(
        {
            "severity": severity,
            "findings": [
                {"statement": "svc-deploy-prod abused via 10.200.3.47", "evidence": "query_logs"},
            ],
            "recommended_actions": [],
            "confidence": 0.8,
        },
    )


def _exfil_script(*, severity: str = "high") -> list[str]:
    # plan(2 tools) -> reason(continue after step 1) -> reason(conclude after step 2) -> verdict
    return [
        _plan("lookup_user", "query_logs"),
        _cont(),
        _conclude(),
        _verdict_json(severity=severity),
    ]


def _cases_dir() -> Path:

    return _CASES_DIR


def _case_path(name: str) -> Path:
    return _cases_dir() / f"{name}.yaml"


def _finding(*entities: str) -> str:
    text = " and ".join(entities) if entities else "investigated"
    return json.dumps(
        {
            "severity": "PLACEHOLDER",
            "findings": [{"statement": f"observed {text}", "evidence": "query_logs"}],
            "recommended_actions": [],
            "confidence": 0.7,
        },
    )


def _verdict_for(severity: str, *entities: str, confidence: float = 0.7) -> str:
    payload = json.loads(_finding(*entities))
    payload["severity"] = severity
    payload["confidence"] = confidence
    return json.dumps(payload)


def _ti_report_for(ioc_value: str = "185.220.101.5") -> str:
    """A minimal TIReport JSON suitable as a FakeLLM TI-synthesis entry.

    The verdict field of every entity in the TI case must reference this IOC
    value so ``must_reference_entities`` passes.  The format mirrors
    ``TIReport`` (validated by the TI loop's ``llm.complete`` call).
    """
    return json.dumps(
        {
            "ioc_type": "public_ip",
            "ioc_value": ioc_value,
            "source_findings": [
                {
                    "source": "multi_source_reputation",
                    "summary": f"{ioc_value} is a known Tor exit node.",
                    "citation": f"fixture:reputation/{ioc_value}",
                }
            ],
            "overall_assessment": f"{ioc_value}: confirmed malicious Tor exit node.",
            "confidence": 0.95,
        }
    )


# A case-appropriate script for each shipped golden case so a recorded cache makes
# that case pass under replay. Tools cover each case's must_call_tools; the verdict
# satisfies severity_in and must_reference_entities.
def _script_for(name: str) -> list[str]:
    tools = ("lookup_user", "query_logs", "check_reputation", "get_asset_info")
    plan = _plan(*tools)
    reasons = [_cont(), _cont(), _cont(), _conclude()]
    verdicts = {
        # --- 6 original core cases ---
        "exfil-prod": _verdict_for("high", "svc-deploy-prod", "10.200.3.47"),
        "priv-esc": _verdict_for("high", "dev-intern-jpark"),
        "unknown-event-type": _verdict_for("medium", "research-hsm-7"),
        "benign": _verdict_for("low", "dev-intern-jpark"),
        "tool-failure": _verdict_for("medium", "ghost-host-unregistered"),
        "benign-after-flagged": _verdict_for("low", "svc-deploy-prod"),
        # --- 24 extended cases ---
        "benign-low-vol-api": _verdict_for("low"),
        "benign-mfa-reset": _verdict_for("low"),
        "benign-new-user-onboard": _verdict_for("low"),
        "benign-readonly-scan": _verdict_for("low"),
        "benign-scheduled-job": _verdict_for("low"),
        "benign-vpn-change": _verdict_for("low"),
        "edge-contradictory-signals": _verdict_for("medium"),
        "edge-empty-entities": _verdict_for("medium"),
        "edge-max-steps-adversarial": _verdict_for("high"),
        "edge-multi-entity": _verdict_for("high"),
        "edge-novel-event-type-2": _verdict_for("medium"),
        "high-cred-stuffing": _verdict_for("high", "dev-intern-jpark"),
        "high-exfil-s3": _verdict_for("high", "svc-deploy-prod"),
        "high-lateral-move": _verdict_for("high", "svc-deploy-prod"),
        "high-persistence": _verdict_for("high"),
        "high-priv-escalation-2": _verdict_for("high", "dev-intern-jpark"),
        "high-supply-chain": _verdict_for("high", "svc-deploy-prod"),
        "medium-after-hours-admin": _verdict_for("medium"),
        "medium-bulk-read": _verdict_for("medium", "svc-deploy-prod"),
        "medium-first-time-resource": _verdict_for("medium", "svc-deploy-prod"),
        "medium-geo-anomaly": _verdict_for("medium"),
        "tool-failure-all-unknown-ip": _verdict_for("medium"),
        "tool-failure-partial": _verdict_for("medium"),
        "tool-failure-unknown-user": _verdict_for("medium"),
        # --- 4 round-4 cases ---
        "high-gate-denied": _verdict_for("high", "svc-ml-pipeline"),
        "edge-prompt-injection": _verdict_for("high"),
        "edge-max-steps-confidence": _verdict_for("medium", confidence=0.5),
        "medium-recall-elevates": _verdict_for("medium", "user-finops-charlie"),
    }
    # TI cases require a TI synthesis entry before the plan (the TI mini-loop fires
    # pre-step-0, so its LLM call is consumed before the plan call).  For all other
    # cases the script is [plan, *reasons, verdict].
    if name == "high-exfil-tor-ti":
        ti_verdict = _verdict_for("high", "185.220.101.5", "svc-ml-pipeline")
        return [_ti_report_for(), plan, *reasons, ti_verdict]
    return [plan, *reasons, verdicts[name]]


# --- Replay Mode: record (synthetic, no live calls) then replay --------------


def test_record_then_replay_reproduces_run_with_no_script_left() -> None:

    case = load_case(_case_path("exfil-prod"))
    fake = FakeLLM(_exfil_script())
    cache = ReplayCache({}, model="fake-model")
    recorder = RecordingLLM(fake, cache)

    live_record = run_case(case, recorder)
    assert len(cache) == 4  # plan + 2 reasons + verdict, all distinct prompts
    assert not fake._script  # noqa: SLF001 — the script is fully consumed by the live run

    replay_record = run_case(case, ReplayLLM(cache))
    # The replay reproduces the same verdict deterministically, key-free.
    assert replay_record.result["verdict"] == live_record.result["verdict"]
    assert [e["event"] for e in replay_record.journal] == [e["event"] for e in live_record.journal]


def test_replay_llm_serves_by_prompt_hash() -> None:

    messages = [Message(role="user", content="decide")]
    response = ReasonerDecision(decision="conclude", rationale="done").model_dump_json()
    cache = ReplayCache({prompt_hash(messages): response}, model="m")

    completion = ReplayLLM(cache).complete(messages, ReasonerDecision)
    assert completion.value.decision == "conclude"
    assert completion.prompt_hash == prompt_hash(messages)
    assert completion.model == "m"


def test_replay_miss_raises_typed_error_not_llmerror() -> None:

    messages = [Message(role="user", content="unseen prompt")]
    with pytest.raises(ReplayMiss) as excinfo:
        ReplayLLM(ReplayCache({}, model="m")).complete(messages, ReasonerDecision)
    # The miss carries the missing hash and is NOT an LLMError (would trigger repair).
    assert excinfo.value.prompt_hash == prompt_hash(messages)
    assert not isinstance(excinfo.value, LLMError)


def test_replay_validation_drift_raises_replay_error() -> None:

    messages = [Message(role="user", content="x")]
    # A recorded payload that no longer matches the model (bad enum value).
    cache = ReplayCache(
        {prompt_hash(messages): json.dumps({"decision": "not_a_verb", "rationale": "x"})},
        model="m",
    )
    with pytest.raises(ReplayError):
        ReplayLLM(cache).complete(messages, ReasonerDecision)


def test_replay_cache_round_trips_through_disk(tmp_path: Path) -> None:

    cache = ReplayCache({"h1": '{"a": 1}'}, model="rec-model")
    path = replay_path(tmp_path / "case.yaml")
    cache.dump(path)
    loaded = ReplayCache.load(path)

    assert loaded.get("h1") == '{"a": 1}'
    assert loaded.model == "rec-model"
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == REPLAY_SCHEMA_VERSION
    with pytest.raises(ReplayMiss):
        loaded.get("absent")


def test_replay_llm_from_path(tmp_path: Path) -> None:

    messages = [Message(role="user", content="p")]
    path = replay_path(tmp_path / "c.yaml")
    ReplayCache(
        {
            prompt_hash(messages): ReasonerDecision(
                decision="conclude", rationale="ok"
            ).model_dump_json()
        },
        model="disk",
    ).dump(path)

    completion = ReplayLLM.from_path(path).complete(messages, ReasonerDecision)
    assert completion.value.decision == "conclude"


def test_replay_cache_load_rejects_malformed_files(tmp_path: Path) -> None:

    missing = tmp_path / "absent.replay.json"
    not_json = tmp_path / "bad.replay.json"
    not_json.write_text("{not json", encoding="utf-8")
    wrong_shape = tmp_path / "shape.replay.json"
    wrong_shape.write_text(json.dumps({"entries": "nope"}), encoding="utf-8")
    no_model = tmp_path / "nomodel.replay.json"
    no_model.write_text(json.dumps({"entries": {"h": "{}"}}), encoding="utf-8")

    for path in (missing, not_json, wrong_shape):
        with pytest.raises(ReplayCacheError):
            ReplayCache.load(path)
    # A cache with entries but no model field loads with the fallback model name.
    assert ReplayCache.load(no_model).model == "replay"


# --- runner end-to-end (FakeLLM live-mode path) ------------------------------


def test_evaluate_case_passes_against_a_good_run() -> None:

    case = load_case(_case_path("exfil-prod"))
    report = evaluate_case(case, FakeLLM(_exfil_script()))

    assert not report.tier1_failures
    assert not report.gating_failed
    assert report.model == "fake-model"
    assert report.prompt_hashes  # llm_call provenance captured


def test_evaluate_case_fails_on_wrong_severity() -> None:

    case = load_case(_case_path("exfil-prod"))
    # severity 'low' violates severity_in: [high, critical] → a gating Tier-1 failure.
    report = evaluate_case(case, FakeLLM(_exfil_script(severity="low")))

    assert report.gating_failed
    assert "severity_in" in {f.name for f in report.tier1_failures}


def test_pending_case_failure_does_not_gate() -> None:
    # `pending:` stays a blessed convention for future cases (no shipped case uses
    # it now that benign-after-flagged gates). A SYNTHETIC pending case proves a
    # pending case's Tier-1 failure is reported but never gates — covering
    # `gating_failed`'s `and not self.pending` branch and the `PENDING` status line.
    case = GoldenCase.model_validate(
        {
            "name": "synthetic-pending",
            "alert": "src/triage/evals/cases/alerts/benign.json",
            "pending": "awaiting some future upstream wiring",
            "verdict": {"severity_in": ["critical"]},
        },
    )
    # A 'low' verdict violates the synthetic severity_in: [critical] — but it is
    # pending, so the failure is reported, never gated.
    script = [_plan("lookup_user"), _conclude(), _verdict_json(severity="low")]
    report = evaluate_case(case, FakeLLM(script))

    assert report.pending
    assert report.tier1_failures  # the assertion did fail
    assert not report.gating_failed  # but pending never gates
    assert "PENDING" in format_report([report])


def test_run_suite_and_format_report() -> None:

    # A FakeLLM that scripts a generic pass for every case in dir order. Each case
    # needs plan -> reason(s) -> verdict; an oversupplied script is harmless (extra
    # entries are simply never popped).

    script: list[str] = []
    for _ in range(35):
        # Oversupply TI entries so the TI-enabled cases consume them first without
        # exhausting the script (extra entries in a FakeLLM are harmless — they are
        # simply never popped).
        script.append(_ti_report_for())
        script.extend([_plan("lookup_user", "query_logs", "check_reputation", "get_asset_info")])
        script.extend([_cont(), _cont(), _cont(), _conclude()])
        script.append(_verdict_json())
    reports = run_suite(FakeLLM(script))
    text = format_report(reports)

    assert len(reports) == 35
    assert "Eval report" in text
    assert "RESULT:" in text


def test_build_live_llm_needs_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # The live path constructs OpenAICompatibleLLM, which raises ConfigError with no
    # LLM_API_KEY — this exercises the live-builder seam without a network or a key.
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        runner._build_live_llm()  # noqa: SLF001 — module-private live seam under test


def test_main_returns_nonzero_on_tier1_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    # Inject a FakeLLM whose verdict is 'low' everywhere → exfil-prod severity_in fails.
    script: list[str] = []
    for _ in range(35):
        # Oversupply TI entries for the TI-enabled cases (same as test_run_suite).
        script.append(_ti_report_for())
        script.extend([_plan("lookup_user", "query_logs", "check_reputation", "get_asset_info")])
        script.extend([_cont(), _cont(), _cont(), _conclude()])
        script.append(_verdict_json(severity="low"))
    monkeypatch.setattr(runner, "_build_live_llm", lambda: FakeLLM(script))

    assert runner.main([]) == 1


def test_main_returns_zero_when_all_pass(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    # The all-green path: record each case from its case-appropriate script into a
    # per-case cache, then run main(--replay) so every case passes Tier-1 with NO
    # live LLM call. This is the tests-only synthetic fixture in action.

    caches_dir = tmp_path / "cases"
    caches_dir.mkdir()
    for case in load_cases(runner._CASES_DIR):  # noqa: SLF001 — module-private dir under test
        cache = ReplayCache({}, model="fake-model")
        run_case(case, RecordingLLM(FakeLLM(_script_for(case.name)), cache))
        cache.dump(case_replay_path(case, caches_dir))
    monkeypatch.setattr(runner, "case_replay_path", lambda case: case_replay_path(case, caches_dir))

    code = runner.main(["--replay"])
    captured = capsys.readouterr()
    assert code == 0
    assert "RESULT: all Tier-1 assertions passed" in captured.out


def test_main_replay_path_never_reaches_live_llm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A guard: the replay path must not consult _build_live_llm at all (a live call
    # would need a key). Record one passing case, replay it, assert main returns 0
    # and the live builder was never invoked.

    caches_dir = tmp_path / "cases"
    caches_dir.mkdir()
    for case in load_cases(runner._CASES_DIR):  # noqa: SLF001
        cache = ReplayCache({}, model="fake-model")
        run_case(case, RecordingLLM(FakeLLM(_script_for(case.name)), cache))
        cache.dump(case_replay_path(case, caches_dir))
    monkeypatch.setattr(runner, "case_replay_path", lambda case: case_replay_path(case, caches_dir))

    def _boom() -> None:
        msg = "replay path must never build a live LLM"
        raise AssertionError(msg)

    monkeypatch.setattr(runner, "_build_live_llm", _boom)
    assert runner.main(["--replay"]) == 0


# --- memory seeding: declarative prior_runs wire recall into the planner -----


def test_seeded_case_wires_recall_into_the_planner_prompt() -> None:
    # The benign-after-flagged case declares a prior high-severity verdict for
    # svc-deploy-prod; run_case must persist it through the REAL MemoryStore and the
    # recall must reach the plan prompt. Asserted in-process (the run record cannot
    # carry prompt text). The verdict stays LOW — recall informs, never dictates.
    case = load_case(_case_path("benign-after-flagged"))
    capturer = CapturingLLM(FakeLLM(_script_for("benign-after-flagged")))

    record = run_case(case, capturer)

    plan_prompt = "\n".join(m["content"] for m in capturer.calls[0])
    assert "<recalled_memory>" in plan_prompt
    # The seeded prior finding's statement reaches the planner verbatim.
    assert "egressed 4.2GB of customer records" in plan_prompt
    # ...yet the benign verdict resists the prior HIGH flag (US-0003 AC).
    verdict = Verdict.model_validate(record.result["verdict"])
    assert verdict.severity == "low"


def test_unseeded_case_runs_memory_free() -> None:
    # A case WITHOUT prior_runs gets no recall block in its plan prompt — the loop is
    # byte-for-byte memory-free, identical to before the seam was wired.
    case = load_case(_case_path("benign"))
    capturer = CapturingLLM(FakeLLM(_script_for("benign")))

    run_case(case, capturer)

    assert "<recalled_memory>" not in capturer.calls[0][0]["content"]


def test_build_deps_defaults_memory_to_none() -> None:
    # The default (no seed) wiring keeps TriageDeps.memory None — the memory-free loop.
    deps = runner.build_deps(FakeLLM([]), runner._CapturingJournal())  # noqa: SLF001
    assert deps.memory is None


def test_build_deps_approve_true_wires_auto_gate_approve() -> None:
    """R1: build_deps(approve=True) wires AutoGate(approve=True) — gate approves."""
    from triage.gate import AutoGate  # noqa: PLC0415 — local import; avoids top-level coupling

    journal = runner._CapturingJournal()  # noqa: SLF001
    deps = runner.build_deps(FakeLLM([]), journal, approve=True)
    assert isinstance(deps.gate, AutoGate)
    assert deps.gate._approve is True  # noqa: SLF001 — AutoGate internal, test-only


def test_build_deps_approve_false_is_default_deny() -> None:
    """R1: default approve=False preserves the existing default-deny posture."""
    from triage.gate import AutoGate  # noqa: PLC0415 — local import

    journal = runner._CapturingJournal()  # noqa: SLF001
    deps = runner.build_deps(FakeLLM([]), journal)  # approve default = False
    assert isinstance(deps.gate, AutoGate)
    assert deps.gate._approve is False  # noqa: SLF001


def test_golden_case_gate_field_defaults_to_approve() -> None:
    """R1: GoldenCase.gate defaults to 'approve' — all existing cases are unchanged."""
    case = GoldenCase.model_validate(
        {"name": "c", "alert": "a.json", "trajectory": {}, "verdict": {}}
    )
    assert case.gate == "approve"


def test_golden_case_gate_field_deny_round_trips() -> None:
    """R1: GoldenCase.gate='deny' parses and is accessible."""
    case = GoldenCase.model_validate(
        {"name": "c", "alert": "a.json", "gate": "deny", "trajectory": {}, "verdict": {}}
    )
    assert case.gate == "deny"


def test_main_replay_skips_cases_with_no_cache(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """In replay mode, a case whose .replay.json is absent emits a loud NO CACHE note
    and is never a gating failure — this allows new cases to land before recording."""
    # Record ALL BUT ONE case so there is one missing cache.
    caches_dir = tmp_path / "cases"
    caches_dir.mkdir()
    all_cases = load_cases(runner._CASES_DIR)  # noqa: SLF001
    # Record all but the last case.
    for case in all_cases[:-1]:
        cache = ReplayCache({}, model="fake-model")
        run_case(case, RecordingLLM(FakeLLM(_script_for(case.name)), cache))
        cache.dump(case_replay_path(case, caches_dir))
    # The last case has no cache file in caches_dir.

    def _patched_path(case: Any) -> Any:
        return case_replay_path(case, caches_dir)

    monkeypatch.setattr(runner, "case_replay_path", _patched_path)

    code = runner.main(["--replay"])
    captured = capsys.readouterr()

    # The missing-cache case is reported loudly but does not gate (exit code 0 as
    # long as the recorded cases all passed).
    assert code == 0
    assert "[NO CACHE]" in captured.out


def test_seed_store_never_touches_the_configured_memory_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Isolation: a seeded run persists into its OWN tmp dir, never the developer's
    # configured MEMORY_DIR. Point MEMORY_DIR at an empty tmp dir and assert it stays
    # empty after a seeded run.
    configured = tmp_path / "real-memory"
    configured.mkdir()
    monkeypatch.setenv("MEMORY_DIR", str(configured))

    case = load_case(_case_path("benign-after-flagged"))
    run_case(case, CapturingLLM(FakeLLM(_script_for("benign-after-flagged"))))

    assert list(configured.iterdir()) == []


def test_seeded_case_persists_through_the_real_store(tmp_path: Path) -> None:
    # The seed path uses the real MemoryStore.persist API (no hand-written atoms):
    # seeding the case's prior_runs yields a store whose recall reproduces the prior
    # finding for the overlapping entity — and ONLY that entity (the prior source_ip
    # differs from the benign one, so it never matches).
    case = load_case(_case_path("benign-after-flagged"))
    assert case.prior_runs is not None
    store = runner._seed_memory(case.prior_runs, tmp_path)  # noqa: SLF001

    benign = Alert.model_validate_json(
        (runner._REPO_ROOT / case.alert).read_text(encoding="utf-8"),  # noqa: SLF001
    )
    recalled = store.recall(benign)
    assert len(recalled) == 1
    assert "egressed 4.2GB of customer records" in recalled[0]["content"]


# --- judge: advisory, never blocks -------------------------------------------


class _ScriptedJudgeLLM:
    """An LLM that returns one scripted judge reply, or raises if told to."""

    model = "judge-model"

    def __init__(self, *, raise_error: bool = False) -> None:
        self._raise = raise_error

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Any = None,
        on_repair: Any = None,
    ) -> Completion[T]:
        if self._raise:
            msg = "judge llm down"
            raise LLMError(msg)
        value = response_model.model_validate({"score": 84, "rationale": "plan fit the entities"})
        return Completion(
            value=value,
            model=self.model,
            prompt_hash=prompt_hash(messages),
            tokens=0,
            latency_ms=1,
        )


def test_judge_scores_and_emits_llm_call() -> None:

    class Rec:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def emit(self, event: str, payload: Mapping[str, Any], *, agent: str = "triage") -> None:
            self.events.append((event, dict(payload)))

    rec = Rec()
    result = Judge(llm=_ScriptedJudgeLLM(), journal=rec).score(_record())

    assert result.scored
    assert result.score == 84
    assert rec.events[0][0] == "llm_call"
    assert rec.events[0][1]["purpose"] == "judge"


def test_judge_failure_degrades_to_not_scored_never_blocks() -> None:

    result = Judge(llm=_ScriptedJudgeLLM(raise_error=True), journal=NoopJournal()).score(_record())
    assert not result.scored
    assert result.score is None


def test_runner_threads_judge_into_report() -> None:

    case = load_case(_case_path("exfil-prod"))
    judge = Judge(llm=_ScriptedJudgeLLM(), journal=NoopJournal())
    report = evaluate_case(case, FakeLLM(_exfil_script()), judge=judge)

    assert report.judge is not None
    assert report.judge.scored
    text = _format_report_with_judge(report)
    assert "judge:" in text


def _format_report_with_judge(report: Any) -> str:

    return format_report([report])


def test_format_report_renders_unscored_judge() -> None:

    case = load_case(_case_path("exfil-prod"))
    judge = Judge(llm=_ScriptedJudgeLLM(raise_error=True), journal=NoopJournal())
    report = evaluate_case(case, FakeLLM(_exfil_script()), judge=judge)
    assert "not scored" in format_report([report])


# --- judge multi-sample median scoring (J2) -----------------------------------


class _MultiScriptedJudgeLLM:
    """An LLM that returns sequentially scripted scores, or raises on demand.

    ``scores`` is a list of ``int | None``; ``None`` means raise ``LLMError``
    for that call index. Once the list is exhausted the LLM raises to catch bugs.
    """

    model = "judge-model"

    def __init__(self, scores: list[int | None]) -> None:
        self._scores: list[int | None] = list(scores)
        self._call_idx = 0

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Any = None,
        on_repair: Any = None,
    ) -> Completion[T]:
        if self._call_idx >= len(self._scores):
            msg = "MultiScriptedJudgeLLM: script exhausted"
            raise LLMError(msg)
        val = self._scores[self._call_idx]
        self._call_idx += 1
        if val is None:
            msg = "scripted judge failure"
            raise LLMError(msg)
        value = response_model.model_validate({"score": val, "rationale": f"score-{val}"})
        return Completion(
            value=value,
            model=self.model,
            prompt_hash=prompt_hash(messages),
            tokens=0,
            latency_ms=1,
        )


def test_judge_median_of_3_picks_median_score_and_journals_3_llm_calls() -> None:
    # Scores: 40, 80, 60 → median = 60; rationale must come from the score-60 sample.
    class Rec:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def emit(self, event: str, payload: Mapping[str, Any], *, agent: str = "triage") -> None:
            self.events.append((event, dict(payload)))

    rec = Rec()
    llm = _MultiScriptedJudgeLLM([40, 80, 60])
    result = Judge(llm=llm, journal=rec, samples=3).score(_record())

    assert result.scored
    assert result.score == 60
    assert result.rationale == "score-60"
    # Exactly 3 llm_call events journaled, all purpose="judge".
    judge_calls = [e for e in rec.events if e[0] == "llm_call"]
    assert len(judge_calls) == 3
    assert all(e[1]["purpose"] == "judge" for e in judge_calls)


def test_judge_partial_failure_uses_median_of_successes() -> None:
    # Scores: 70, None (fail), 50 → successes are [70, 50]; median = 60.
    class Rec:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def emit(self, event: str, payload: Mapping[str, Any], *, agent: str = "triage") -> None:
            self.events.append((event, dict(payload)))

    rec = Rec()
    llm = _MultiScriptedJudgeLLM([70, None, 50])
    result = Judge(llm=llm, journal=rec, samples=3).score(_record())

    assert result.scored
    assert result.score == 60
    # Only 2 successful llm_call events journaled (the failing call is not journaled).
    judge_calls = [e for e in rec.events if e[0] == "llm_call"]
    assert len(judge_calls) == 2


def test_judge_all_samples_fail_degrades_to_not_scored() -> None:
    # All 3 samples raise → scored=False, never blocks.
    llm = _MultiScriptedJudgeLLM([None, None, None])
    result = Judge(llm=llm, journal=NoopJournal(), samples=3).score(_record())

    assert not result.scored
    assert result.score is None


def test_judge_default_samples_1_is_byte_identical_to_original() -> None:
    # samples=1 (the default) behaves exactly as before: one call, one llm_call event.
    class Rec:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def emit(self, event: str, payload: Mapping[str, Any], *, agent: str = "triage") -> None:
            self.events.append((event, dict(payload)))

    rec = Rec()
    llm = _MultiScriptedJudgeLLM([75])
    result = Judge(llm=llm, journal=rec).score(_record())  # default samples=1

    assert result.scored
    assert result.score == 75
    judge_calls = [e for e in rec.events if e[0] == "llm_call"]
    assert len(judge_calls) == 1


# --- judge_min soft gate (US-0007) -------------------------------------------


def _case_with_judge_min(judge_min: float | None) -> GoldenCase:
    """Return a minimal GoldenCase with judge_min set for soft-gate tests."""
    return GoldenCase.model_validate(
        {
            "name": "sentinel",
            "alert": "src/triage/evals/cases/alerts/benign.json",
            "judge_min": judge_min,
            "verdict": {"severity_in": ["high", "critical"]},  # passes with default high verdict
        }
    )


def test_judge_min_fail_exits_2_with_warn_section(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """A case with judge_min whose judge score falls below → exit 2 + TIER-2 WARN section."""
    # Build one case with judge_min=80; the scripted judge returns score=40 (< 80).
    # Tier-1 passes (severity high satisfies severity_in: [high, critical]).
    case = _case_with_judge_min(judge_min=80)
    # Score=40 < judge_min=80 → soft gate trip.
    judge = Judge(llm=_MultiScriptedJudgeLLM([40]), journal=NoopJournal(), samples=1)

    caches_dir = tmp_path / "cases"
    caches_dir.mkdir()
    cache = ReplayCache({}, model="fake-model")
    run_case(case, RecordingLLM(FakeLLM(_exfil_script()), cache))
    cache.dump(case_replay_path(case, caches_dir))

    def _patched_path(c: Any) -> Any:
        return case_replay_path(c, caches_dir)

    monkeypatch.setattr(runner, "case_replay_path", _patched_path)
    monkeypatch.setattr(runner, "load_cases", lambda _: [case])
    monkeypatch.setattr(runner, "_build_live_llm", lambda: _MultiScriptedJudgeLLM([40]))

    # Inject judge into evaluate_case via monkeypatching the suite call.
    original_evaluate = runner.evaluate_case

    def _patched_evaluate(c: Any, llm: Any, **_: Any) -> Any:
        return original_evaluate(c, llm, judge=judge)

    monkeypatch.setattr(runner, "evaluate_case", _patched_evaluate)

    code = runner.main(["--replay"])
    captured = capsys.readouterr()

    assert code == 2, f"Expected exit 2 (soft gate), got {code}"
    assert "TIER-2 WARN" in captured.out
    assert "sentinel" in captured.out
    assert "score=40" in captured.out
    assert "judge_min=80" in captured.out


def test_tier1_fail_wins_over_judge_soft_fail(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """When both Tier-1 and judge_min fail, Tier-1 wins: exit 1, NOT exit 2."""
    # Tier-1 fails: 'low' verdict violates severity_in: [high, critical].
    # judge_min=80 also fails: score=40 < 80.
    case = _case_with_judge_min(judge_min=80)
    low_score_judge = Judge(llm=_MultiScriptedJudgeLLM([40]), journal=NoopJournal(), samples=1)

    caches_dir = tmp_path / "cases"
    caches_dir.mkdir()
    cache = ReplayCache({}, model="fake-model")
    # Record with low severity so Tier-1 fails.
    run_case(case, RecordingLLM(FakeLLM(_exfil_script(severity="low")), cache))
    cache.dump(case_replay_path(case, caches_dir))

    def _patched_path(c: Any) -> Any:
        return case_replay_path(c, caches_dir)

    monkeypatch.setattr(runner, "case_replay_path", _patched_path)
    monkeypatch.setattr(runner, "load_cases", lambda _: [case])

    original_evaluate = runner.evaluate_case

    def _patched_evaluate(c: Any, llm: Any, **_: Any) -> Any:
        return original_evaluate(c, llm, judge=low_score_judge)

    monkeypatch.setattr(runner, "evaluate_case", _patched_evaluate)

    code = runner.main(["--replay"])
    captured = capsys.readouterr()

    # Tier-1 failure wins: exit 1, not 2.
    assert code == 1, f"Expected exit 1 (Tier-1 wins), got {code}"
    # TIER-2 WARN must NOT appear (Tier-1 already failed).
    assert "TIER-2 WARN" not in captured.out


def test_judge_min_both_pass_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """When both Tier-1 and judge score pass → exit 0."""
    # judge_min=50; score=84 (from _ScriptedJudgeLLM) → passes.
    # Tier-1 passes: severity high satisfies severity_in: [high, critical].
    case = _case_with_judge_min(judge_min=50)
    passing_judge = Judge(llm=_ScriptedJudgeLLM(), journal=NoopJournal(), samples=1)

    caches_dir = tmp_path / "cases"
    caches_dir.mkdir()
    cache = ReplayCache({}, model="fake-model")
    run_case(case, RecordingLLM(FakeLLM(_exfil_script()), cache))
    cache.dump(case_replay_path(case, caches_dir))

    def _patched_path(c: Any) -> Any:
        return case_replay_path(c, caches_dir)

    monkeypatch.setattr(runner, "case_replay_path", _patched_path)
    monkeypatch.setattr(runner, "load_cases", lambda _: [case])

    original_evaluate = runner.evaluate_case

    def _patched_evaluate(c: Any, llm: Any, **_: Any) -> Any:
        return original_evaluate(c, llm, judge=passing_judge)

    monkeypatch.setattr(runner, "evaluate_case", _patched_evaluate)

    code = runner.main(["--replay"])
    assert code == 0


def test_main_live_wires_judge_only_for_judge_min_cases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``main`` (live mode) natively judges judge_min cases and ONLY those.

    The CLI builds the Tier-2 Judge itself (US-0007 consumer scope: ``make
    eval``); cases without ``judge_min`` must not pay the judge's live cost.
    """
    sentinel = _case_with_judge_min(judge_min=50)
    plain = _case_with_judge_min(judge_min=None)
    judged_records: list[Any] = []

    class _SpyJudge:
        def score(self, run_record: Any) -> Any:
            judged_records.append(run_record)
            from triage.evals.judge import JudgeResult  # noqa: PLC0415

            return JudgeResult(scored=True, score=84, rationale="spy")

    monkeypatch.setattr(runner, "load_cases", lambda _: [sentinel, plain])
    monkeypatch.setattr(runner, "_build_live_llm", lambda: FakeLLM(_exfil_script() * 2))
    monkeypatch.setattr(runner, "_build_judge", lambda _llm: _SpyJudge())

    code = runner.main([])

    assert code == 0
    # Exactly one case (the judge_min sentinel) was judged.
    assert len(judged_records) == 1


def test_judge_min_absent_no_behavior_change() -> None:
    """Absent judge_min → zero behavior change (gate identical to before)."""
    case = _case_with_judge_min(judge_min=None)
    # Even a low judge score should not trigger soft gate when judge_min is None.
    low_score_judge = Judge(llm=_MultiScriptedJudgeLLM([10]), journal=NoopJournal(), samples=1)

    report = evaluate_case(case, FakeLLM(_exfil_script()), judge=low_score_judge)

    # judge_min is None → judge_failed must always be False.
    assert not report.judge_failed
    assert report.judge_min is None


def test_not_scored_judge_never_fails_soft_gate() -> None:
    """A judge that returns scored=False must never trigger the soft gate."""
    # judge_min=50; judge raises error → scored=False → no soft fail.
    case = _case_with_judge_min(judge_min=50)
    failing_judge = Judge(llm=_ScriptedJudgeLLM(raise_error=True), journal=NoopJournal())

    report = evaluate_case(case, FakeLLM(_exfil_script()), judge=failing_judge)

    assert report.judge is not None
    assert not report.judge.scored
    assert not report.judge_failed, "Not-scored judge must never fail the soft gate"


def test_case_report_judge_failed_property() -> None:
    """Unit-level: CaseReport.judge_failed reflects the score vs judge_min contract."""
    from triage.evals.judge import JudgeResult  # noqa: PLC0415 — local to this test block
    from triage.evals.runner import CaseReport  # noqa: PLC0415

    # Scored below threshold → fails.
    r_fail = CaseReport(
        name="x",
        pending=False,
        judge=JudgeResult(scored=True, score=40, rationale="low"),
        judge_min=80.0,
    )
    assert r_fail.judge_failed

    # Scored above threshold → passes.
    r_pass = CaseReport(
        name="x",
        pending=False,
        judge=JudgeResult(scored=True, score=85, rationale="good"),
        judge_min=80.0,
    )
    assert not r_pass.judge_failed

    # No judge result → no soft fail.
    r_no_judge = CaseReport(name="x", pending=False, judge=None, judge_min=80.0)
    assert not r_no_judge.judge_failed

    # Not scored → no soft fail (degradation rule).
    r_not_scored = CaseReport(
        name="x",
        pending=False,
        judge=JudgeResult(scored=False, rationale="unavail"),
        judge_min=80.0,
    )
    assert not r_not_scored.judge_failed

    # judge_min=None → never fails.
    r_no_min = CaseReport(
        name="x",
        pending=False,
        judge=JudgeResult(scored=True, score=10, rationale="terrible"),
        judge_min=None,
    )
    assert not r_no_min.judge_failed

    # Pending case → never fails soft gate.
    r_pending = CaseReport(
        name="x",
        pending=True,
        judge=JudgeResult(scored=True, score=10, rationale="bad"),
        judge_min=50.0,
    )
    assert not r_pending.judge_failed


def test_sentinel_cases_have_judge_min_set() -> None:
    """The 5 stable sentinel cases must have judge_min=50; known-hard tail must not."""
    cases = {c.name: c for c in load_cases(_CASES_DIR)}
    sentinels = {"exfil-prod", "priv-esc", "benign", "high-gate-denied", "high-exfil-tor-ti"}
    for name in sentinels:
        assert cases[name].judge_min == 50, f"{name} should have judge_min=50"
    # Known-hard tail cases must NOT have judge_min set.
    hard_tail = {n for n in cases if n.startswith(("tool-failure", "edge-"))}
    for name in hard_tail:
        assert cases[name].judge_min is None, f"{name} should not have judge_min (known-hard tail)"


def test_alert_paths_use_cases_alerts_convention() -> None:
    """All 6 original cases must use the src/triage/evals/cases/alerts/ convention."""
    cases = {c.name: c for c in load_cases(_CASES_DIR)}
    originals = {
        "exfil-prod",
        "priv-esc",
        "unknown-event-type",
        "benign",
        "tool-failure",
        "benign-after-flagged",
    }
    for name in originals:
        alert_path = cases[name].alert
        assert alert_path.startswith("src/triage/evals/cases/alerts/"), (
            f"{name}: alert path must use cases/alerts/ convention, got: {alert_path}"
        )


# --- loaders + shipped cases + adapters --------------------------------------


def test_all_golden_cases_parse() -> None:
    # All 35 shipped cases (6 original + 24 extended + 4 round-4 + 1 TI) must
    # parse and declare at least one assertion each.
    cases = load_cases(_CASES_DIR)
    assert len(cases) == 35
    # Original core 6 must still be present.
    core_names = {
        "exfil-prod",
        "priv-esc",
        "unknown-event-type",
        "benign",
        "tool-failure",
        "benign-after-flagged",
    }
    assert core_names.issubset({c.name for c in cases})
    # Round-4 new cases must also be present.
    round4_names = {
        "high-gate-denied",
        "edge-prompt-injection",
        "edge-max-steps-confidence",
        "medium-recall-elevates",
    }
    assert round4_names.issubset({c.name for c in cases})
    # Each case declares at least one assertion (the skill bans decoration cases).
    for case in cases:
        populated = case.expect_trajectory.model_dump(
            exclude_none=True
        ) or case.expect_verdict.model_dump(
            exclude_none=True,
        )
        assert populated, case.name


def test_load_case_rejects_malformed_yaml(tmp_path: Path) -> None:

    missing = tmp_path / "nope.yaml"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("name: [unterminated", encoding="utf-8")
    not_mapping = tmp_path / "list.yaml"
    not_mapping.write_text("- a\n- b\n", encoding="utf-8")
    bad_schema = tmp_path / "schema.yaml"
    bad_schema.write_text("alert: x.json\n", encoding="utf-8")  # missing required name

    for path in (missing, bad_yaml, not_mapping, bad_schema):
        with pytest.raises(ConfigError):
            load_case(path)


def test_load_cases_rejects_empty_dir(tmp_path: Path) -> None:

    with pytest.raises(ConfigError):
        load_cases(tmp_path)


def test_load_run_record_from_disk(tmp_path: Path) -> None:

    run_dir = tmp_path / "R1"
    run_dir.mkdir()
    (run_dir / "result.json").write_text(json.dumps(_record().result), encoding="utf-8")
    (run_dir / "journal.jsonl").write_text(
        json.dumps(_event(1, "run_started", alert_id="A")) + "\n\n",  # blank line tolerated
        encoding="utf-8",
    )
    record = load_run_record(run_dir)
    assert record.journal[0]["event"] == "run_started"
    assert record.result["run_id"] == "R1"


def test_load_run_record_rejects_missing_and_malformed(tmp_path: Path) -> None:

    # No result.json at all.
    with pytest.raises(ConfigError):
        load_run_record(tmp_path / "absent")

    # result.json present but not JSON.
    bad_result = tmp_path / "badres"
    bad_result.mkdir()
    (bad_result / "result.json").write_text("{not json", encoding="utf-8")
    (bad_result / "journal.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_run_record(bad_result)

    # result.json valid, journal missing.
    no_journal = tmp_path / "nojournal"
    no_journal.mkdir()
    (no_journal / "result.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_run_record(no_journal)

    # result.json valid, journal present but a line is not JSON.
    bad_journal = tmp_path / "badjournal"
    bad_journal.mkdir()
    (bad_journal / "result.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
    (bad_journal / "journal.jsonl").write_text("{not json\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_run_record(bad_journal)


def test_load_run_record_then_assert_is_the_external_seam(tmp_path: Path) -> None:
    # The whole external-adapter story: read artifacts off disk, score them, no
    # import of src/triage beyond models.

    run_dir = tmp_path / "R2"
    run_dir.mkdir()
    (run_dir / "result.json").write_text(json.dumps(_record().result), encoding="utf-8")
    (run_dir / "journal.jsonl").write_text(
        json.dumps(_event(1, "tool_called", step=1, tool="query_logs", args={})) + "\n",
        encoding="utf-8",
    )
    record = load_run_record(run_dir)
    results = assert_case(_case(trajectory={"must_call_tools": ["query_logs"]}), record)
    assert _names(results)["must_call_tools"].passed


def test_deepeval_adapter_projects_reference() -> None:

    case = load_case(_CASES_DIR / "exfil-prod.yaml")
    projection = project_reference(case)

    assert isinstance(projection, DeepEvalProjection)
    assert {t["name"] for t in projection.expected_tools} == {"lookup_user", "query_logs"}
    assert projection.expected_severity == "high"
    assert projection.expected_actions == ["block_user"]
    assert projection.should_consider_ordering is False
    assert projection.should_exact_match is False


def test_deepeval_adapter_carries_input_parameters() -> None:

    case = GoldenCase.model_validate(
        {
            "name": "c",
            "alert": "a.json",
            "reference": {
                "expected_tools": [{"name": "query_logs", "input_parameters": {"entity": "x"}}],
                "ordered": True,
                "exact": True,
            },
        },
    )
    projection = project_reference(case)
    assert projection.expected_tools[0]["input_parameters"] == {"entity": "x"}
    assert projection.should_consider_ordering is True
    assert projection.should_exact_match is True


# --- ti_enabled wiring: deps override, GoldenCase threading, default-off -----


def _is_ti_enrich_call(event: dict[str, object]) -> bool:
    """Return True when ``event`` is a primary-loop threat_intel.enrich tool_called."""
    return event.get("event") == "tool_called" and event.get("tool") == "threat_intel.enrich"


def _ti_alert_json(name: str) -> str:
    """Read the text of a TI-test alert fixture resolved from the repo root."""
    return (
        runner._REPO_ROOT / "src/triage/evals/cases/alerts" / name  # noqa: SLF001
    ).read_text(encoding="utf-8")


def test_ti_enabled_deps_override_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """TriageDeps.ti_enabled=False suppresses TI even when TI_ENABLED env is 'true'.

    The env var is the process-global fallback; the explicit deps field overrides it.
    This is the race-free seam for eval runner parallel threads.
    """
    from triage.core import TriageDeps, triage  # noqa: PLC0415 — local to this test block
    from triage.gate import AutoGate, RiskPolicy  # noqa: PLC0415
    from triage.tools import FixtureDataSource, ToolRegistry  # noqa: PLC0415

    monkeypatch.setenv("TI_ENABLED", "true")
    journal = runner._CapturingJournal()  # noqa: SLF001
    # Explicit False → TI suppressed regardless of env.
    alert_json = _ti_alert_json("benign.json")
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict_json()]),
        journal=journal,
        registry=ToolRegistry(),
        source=FixtureDataSource(),
        gate=AutoGate(journal, approve=False),
        policy=RiskPolicy(),
        ti_enabled=False,
    )
    result = triage(Alert.model_validate_json(alert_json), deps)

    assert result.terminated_reason == "completed"
    ti_calls = [e for e in journal.events if _is_ti_enrich_call(e)]
    assert ti_calls == [], "ti_enabled=False must suppress TI even when env is 'true'"


def test_ti_enabled_deps_override_true_enables_ti(monkeypatch: pytest.MonkeyPatch) -> None:
    """TriageDeps.ti_enabled=True enables TI even when TI_ENABLED env is unset.

    The explicit True in deps bypasses the env read entirely — parallel-safe.
    """
    from triage.core import TriageDeps, triage  # noqa: PLC0415
    from triage.gate import AutoGate, RiskPolicy  # noqa: PLC0415
    from triage.tools import FixtureDataSource, ToolRegistry  # noqa: PLC0415

    monkeypatch.delenv("TI_ENABLED", raising=False)
    journal = runner._CapturingJournal()  # noqa: SLF001
    alert_json = _ti_alert_json("high-exfil-tor-ti.json")
    # Script: TI synthesis, plan, reason(conclude), verdict.
    deps = TriageDeps(
        llm=FakeLLM([_ti_report_for(), _plan("lookup_user"), _conclude(), _verdict_json()]),
        journal=journal,
        registry=ToolRegistry(),
        source=FixtureDataSource(),
        gate=AutoGate(journal, approve=False),
        policy=RiskPolicy(),
        ti_enabled=True,
    )
    result = triage(Alert.model_validate_json(alert_json), deps)

    assert result.terminated_reason == "completed"
    ti_calls = [e for e in journal.events if _is_ti_enrich_call(e)]
    assert len(ti_calls) == 1, "ti_enabled=True must enable TI even when env is unset"
    # Verify the ioc arg via string repr to sidestep ty's dict[Unknown] inference
    # on journal event payloads (the journal carries dict[str, object]).
    args_repr = str(ti_calls[0].get("args"))
    assert "185.220.101.5" in args_repr


def test_ti_enabled_none_falls_back_to_env_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """TriageDeps.ti_enabled=None (default) falls back to env — disabled when unset."""
    from triage.core import TriageDeps, triage  # noqa: PLC0415
    from triage.gate import AutoGate, RiskPolicy  # noqa: PLC0415
    from triage.tools import FixtureDataSource, ToolRegistry  # noqa: PLC0415

    monkeypatch.delenv("TI_ENABLED", raising=False)
    journal = runner._CapturingJournal()  # noqa: SLF001
    alert_json = _ti_alert_json("high-exfil-tor-ti.json")
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict_json()]),
        journal=journal,
        registry=ToolRegistry(),
        source=FixtureDataSource(),
        gate=AutoGate(journal, approve=False),
        policy=RiskPolicy(),
        ti_enabled=None,  # explicit None → env fallback
    )
    triage(Alert.model_validate_json(alert_json), deps)

    ti_calls = [e for e in journal.events if _is_ti_enrich_call(e)]
    assert ti_calls == [], "ti_enabled=None + no env → TI disabled (env fallback)"


def test_golden_case_ti_enabled_default_false() -> None:
    """GoldenCase.ti_enabled defaults to False — all existing 34 cases unaffected."""
    case = load_case(_CASES_DIR / "exfil-prod.yaml")
    assert case.ti_enabled is False


def test_golden_case_ti_enabled_true_loads_correctly() -> None:
    """The new high-exfil-tor-ti case loads with ti_enabled=True."""
    case = load_case(_CASES_DIR / "high-exfil-tor-ti.yaml")
    assert case.ti_enabled is True
    assert case.name == "high-exfil-tor-ti"
    assert case.expect_trajectory.must_call_tools == ["threat_intel.enrich"]


def test_build_deps_threads_ti_enabled_to_deps() -> None:
    """build_deps passes ti_enabled to TriageDeps — both True and False values."""
    from triage.evals.runner import build_deps  # noqa: PLC0415

    journal = runner._CapturingJournal()  # noqa: SLF001
    deps_on = build_deps(FakeLLM([]), journal, ti_enabled=True)
    deps_off = build_deps(FakeLLM([]), journal, ti_enabled=False)

    assert deps_on.ti_enabled is True
    assert deps_off.ti_enabled is False


def test_run_case_threads_ti_enabled_from_golden_case() -> None:
    """run_case wires case.ti_enabled into build_deps — the end-to-end seam.

    A case with ti_enabled=True must produce at least one threat_intel.enrich
    tool_called event; a case with ti_enabled=False must produce none.
    """
    case_on = load_case(_CASES_DIR / "high-exfil-tor-ti.yaml")
    # Script for TI case: TI synthesis first, then plan+reason+verdict.
    script_on = [
        _ti_report_for(),
        _plan("lookup_user"),
        _conclude(),
        _verdict_for("high", "185.220.101.5", "svc-ml-pipeline"),
    ]
    record_on = run_case(case_on, FakeLLM(script_on))
    ti_calls_on = [e for e in record_on.journal if _is_ti_enrich_call(e)]
    assert len(ti_calls_on) == 1, "ti_enabled=True case must fire threat_intel.enrich"

    case_off = load_case(_CASES_DIR / "exfil-prod.yaml")
    script_off = [
        _plan("lookup_user", "query_logs"),
        _cont(),
        _conclude(),
        _verdict_for("high", "svc-deploy-prod", "10.200.3.47"),
    ]
    record_off = run_case(case_off, FakeLLM(script_off))
    ti_calls_off = [e for e in record_off.journal if _is_ti_enrich_call(e)]
    assert ti_calls_off == [], "ti_enabled=False case must not fire threat_intel.enrich"


def test_default_case_byte_identical_under_new_wiring(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing cases (ti_enabled=False) produce no TI events under the new wiring.

    The ti_enabled=False path sets TriageDeps.ti_enabled=False (explicit, not None),
    bypassing the env read. Journal must contain no threat_intel.enrich tool_called.
    """
    monkeypatch.delenv("TI_ENABLED", raising=False)
    case = load_case(_CASES_DIR / "benign.yaml")

    record = run_case(case, FakeLLM(list(_script_for("benign"))))
    event_names = [e.get("event") for e in record.journal]
    tool_names = [e.get("tool") for e in record.journal]

    # No TI events — byte-identical to pre-wiring behaviour.
    assert "threat_intel.enrich" not in tool_names
    assert "run_started" in event_names
    assert "verdict" in event_names
