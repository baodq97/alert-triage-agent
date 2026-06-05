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

# Purity boundary: the assertion engine + eval models are imported here WITHOUT the
# runner. ``test_assert_case_is_pure_over_a_constructed_record`` uses ONLY these two
# imports to score a hand-built record — proving a foreign tool reuses the checks
# without importing the runner (US-0003 AC). The runner/replay/judge imports below
# serve the other tests; they never participate in the purity test.
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
    failed = [
        _event(1, "tool_called", step=1, tool="query_logs", args={}, attempt=1),
        _event(2, "tool_result", step=1, attempt=1, ok=False, error="not found"),
    ]
    succeeded = [
        _event(1, "tool_called", step=1, tool="query_logs", args={}, attempt=1),
        _event(2, "tool_result", step=1, attempt=1, ok=True, data={}),
    ]
    expect = {"must_observe_tool_failure": True}
    ok = assert_case(_case(trajectory=expect), _record(events=failed))
    bad = assert_case(_case(trajectory=expect), _record(events=succeeded))

    assert _names(ok)["must_observe_tool_failure"].passed
    assert not _names(bad)["must_observe_tool_failure"].passed
    assert "no tool_result" in _names(bad)["must_observe_tool_failure"].detail


def test_must_observe_tool_failure_absent_field_is_silent() -> None:
    events = [_event(1, "tool_result", step=1, attempt=1, ok=True, data={})]
    results = assert_case(_case(trajectory={"must_call_tools": []}), _record(events=events))

    assert "must_observe_tool_failure" not in _names(results)


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


def _verdict_for(severity: str, *entities: str) -> str:
    payload = json.loads(_finding(*entities))
    payload["severity"] = severity
    return json.dumps(payload)


# A case-appropriate script for each shipped golden case so a recorded cache makes
# that case pass under replay. Tools cover each case's must_call_tools; the verdict
# satisfies severity_in and must_reference_entities.
def _script_for(name: str) -> list[str]:
    tools = ("lookup_user", "query_logs", "check_reputation", "get_asset_info")
    plan = _plan(*tools)
    reasons = [_cont(), _cont(), _cont(), _conclude()]
    verdicts = {
        "exfil-prod": _verdict_for("high", "svc-deploy-prod", "10.200.3.47"),
        "priv-esc": _verdict_for("high", "dev-intern-jpark"),
        "unknown-event-type": _verdict_for("medium", "research-hsm-7"),
        "benign": _verdict_for("low", "dev-intern-jpark"),
        "tool-failure": _verdict_for("medium", "ghost-host-unregistered"),
        "benign-after-flagged": _verdict_for("low", "svc-deploy-prod"),
    }
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
    for _ in range(6):
        script.extend([_plan("lookup_user", "query_logs", "check_reputation", "get_asset_info")])
        script.extend([_cont(), _cont(), _cont(), _conclude()])
        script.append(_verdict_json())
    reports = run_suite(FakeLLM(script))
    text = format_report(reports)

    assert len(reports) == 6
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
    for _ in range(6):
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


class _CapturingLLM:
    """Wraps a ``FakeLLM`` and keeps EVERY call's messages (not just the last).

    ``FakeLLM`` retains only ``last_messages`` (the verdict call); the plan is the
    first ``complete``. This capturer records each call's rendered messages so a
    test can inspect the plan prompt (``calls[0]``) for the recalled-memory block.
    """

    def __init__(self, inner: FakeLLM) -> None:
        self._inner = inner
        self.model = inner.model
        self.calls: list[list[Message]] = []

    def complete(self, messages: Sequence[Message], response_model: type[T]) -> Completion[T]:
        self.calls.append(list(messages))
        return self._inner.complete(messages, response_model)


def test_seeded_case_wires_recall_into_the_planner_prompt() -> None:
    # The benign-after-flagged case declares a prior high-severity verdict for
    # svc-deploy-prod; run_case must persist it through the REAL MemoryStore and the
    # recall must reach the plan prompt. Asserted in-process (the run record cannot
    # carry prompt text). The verdict stays LOW — recall informs, never dictates.
    case = load_case(_case_path("benign-after-flagged"))
    capturer = _CapturingLLM(FakeLLM(_script_for("benign-after-flagged")))

    record = run_case(case, capturer)

    plan_prompt = capturer.calls[0][0]["content"]
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
    capturer = _CapturingLLM(FakeLLM(_script_for("benign")))

    run_case(case, capturer)

    assert "<recalled_memory>" not in capturer.calls[0][0]["content"]


def test_build_deps_defaults_memory_to_none() -> None:
    # The default (no seed) wiring keeps TriageDeps.memory None — the memory-free loop.
    deps = runner.build_deps(FakeLLM([]), runner._CapturingJournal())  # noqa: SLF001
    assert deps.memory is None


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
    run_case(case, _CapturingLLM(FakeLLM(_script_for("benign-after-flagged"))))

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

    def complete(self, messages: Sequence[Message], response_model: type[T]) -> Completion[T]:
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

        def emit(self, event: str, payload: Mapping[str, Any], *, agent: str = "triage") -> None:  # noqa: ARG002
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


def _format_report_with_judge(report: Any) -> str:  # noqa: ANN401

    return format_report([report])


def test_format_report_renders_unscored_judge() -> None:

    case = load_case(_case_path("exfil-prod"))
    judge = Judge(llm=_ScriptedJudgeLLM(raise_error=True), journal=NoopJournal())
    report = evaluate_case(case, FakeLLM(_exfil_script()), judge=judge)
    assert "not scored" in format_report([report])


# --- loaders + shipped cases + adapters --------------------------------------


def test_all_six_golden_cases_parse() -> None:

    cases = load_cases(_CASES_DIR)
    names = {c.name for c in cases}
    assert names == {
        "exfil-prod",
        "priv-esc",
        "unknown-event-type",
        "benign",
        "tool-failure",
        "benign-after-flagged",
    }
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
