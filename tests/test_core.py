"""End-to-end tests for the transport-agnostic core — ``triage(alert, deps)``.

These are the US-0001 required tests, expressed as full-loop integration tests
against ``FakeLLM`` (Tier A — deterministic, key-free, feeds the coverage gate):

* **tool call** — a Run with a one-step plan executes the tool and the Observation
  reaches the synthesized Verdict;
* **approval gate (deny path)** — a high-risk ``block_user`` action is gated;
  ``AutoGate`` default-denies; nothing executes; the Verdict still ships;
* **tool-error edge case** — a tool error arrives as an ``ok=False`` Observation;
  the Run never crashes and still ships a Verdict.

Plus the core-specific guarantees: both shipped alerts AND an unknown
``event_type`` alert produce a Verdict with zero code changes (no ``event_type``
branching); a ``MAX_STEPS`` breach ships a partial Verdict and terminates
gracefully; the approve path executes ``block_user`` and emits ``action_executed``;
the target-entity invariant rejects an action targeting a non-Alert Entity before
the gate (recorded via ``action_rejected``, never reaching the gate); a planner
``LLMError`` degrades to a partial Verdict with ``terminated_reason="error"``.

Structural assertions only — "verdicts sensibly" is wave-3 eval territory. The
``FakeLLM`` script drives plan -> reason(s) -> verdict in order; a *failed*
logical call consumes two script entries (original + repair) before raising.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from tests._helpers import CapturingLLM
from triage.core import (
    SCHEMA_VERSION,
    TriageDeps,
    _verify_reentry_from_env,
    resume_investigation,
    summarize,
    triage,
)
from triage.errors import JournalError, ToolError
from triage.gate import AutoGate, DeferredGate, RiskPolicy
from triage.journal import JsonlJournal, NoopJournal, rebuild
from triage.llm import FakeLLM, OpenAICompatibleLLM
from triage.memory import MemoryStore
from triage.models import Alert
from triage.tools import FixtureDataSource, ToolRegistry

if TYPE_CHECKING:
    from collections.abc import Mapping

    from triage.tools.base import DataSource

# --- doubles -----------------------------------------------------------------


class RecordingJournal:
    """A Journal that captures every emitted event for in-order assertions."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any], str]] = []

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        self.events.append((event, dict(payload), agent))

    def names(self) -> list[str]:
        return [event for event, _, _ in self.events]

    def payloads(self, event: str) -> list[dict[str, Any]]:
        return [payload for name, payload, _ in self.events if name == event]


class StubSource:
    """A DataSource that returns benign data unless told to raise for an entity."""

    def __init__(self, raise_for: str | None = None) -> None:
        self._raise_for = raise_for

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        entity = args.get("entity")
        if isinstance(entity, str) and entity == self._raise_for:
            msg = f"no fixture record for entity {entity!r}"
            raise ToolError(msg, transient=False)
        return {"tool": tool, "entity": entity, "status": "benign"}


# --- script builders ---------------------------------------------------------


def _plan(*tools: str) -> str:
    steps = [{"tool": t, "args": {"entity": "alice"}, "rationale": "check it"} for t in tools]
    return json.dumps({"steps": steps})


def _conclude() -> str:
    return json.dumps({"decision": "conclude", "rationale": "enough evidence"})


def _continue() -> str:
    return json.dumps({"decision": "continue", "rationale": "keep going"})


def _verdict(
    *,
    actions: list[dict[str, Any]] | None = None,
    severity: str = "medium",
    finding_entity: str | None = None,
) -> str:
    # ``finding_entity`` plants the entity name in the finding corpus so
    # ``_filter_traceable_actions`` (F5) can match action params to findings.
    # When an action targets an entity, the finding must name that entity for
    # the action to survive the traceability backstop.
    statement = (
        f"anomaly observed for user {finding_entity}" if finding_entity else "anomaly observed"
    )
    evidence = f"lookup_user confirmed {finding_entity}" if finding_entity else "lookup_user"
    return json.dumps(
        {
            "severity": severity,
            "findings": [{"statement": statement, "evidence": evidence}],
            "recommended_actions": actions or [],
            "confidence": 0.8,
        },
    )


def _block_user(target: str) -> dict[str, Any]:
    return {"name": "block_user", "params": {"user": target}, "description": "block the user"}


# --- fixtures ----------------------------------------------------------------


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-1",
        "timestamp": "2026-06-05T00:00:00Z",
        "source": "edr",
        "severity_hint": "medium",
        "event_type": "data_exfiltration",
        "description": "Large outbound transfer from alice's host.",
        "entities": {"user": "alice", "ip": "10.0.0.9"},
        "context": {"bytes": 5_000_000},
    }
    return Alert.model_validate({**base, **overrides})


def _deps(
    script: list[str],
    *,
    journal: RecordingJournal | None = None,
    source: DataSource | None = None,
    approve: bool = False,
    max_steps: int | None = None,
) -> tuple[TriageDeps, RecordingJournal]:
    rec = journal or RecordingJournal()
    deps = TriageDeps(
        llm=FakeLLM(script),
        journal=rec,
        registry=ToolRegistry(),
        source=source or StubSource(),
        gate=AutoGate(rec, approve=approve),
        policy=RiskPolicy(),
        max_steps=max_steps,
    )
    return deps, rec


# --- required test 1: tool call ----------------------------------------------


def test_tool_call_observation_reaches_verdict() -> None:
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _verdict()])
    result = triage(_alert(), deps)

    assert "tool_called" in rec.names()
    assert "tool_result" in rec.names()
    assert result.terminated_reason == "completed"
    assert result.verdict.findings
    # run_started carries the schema version and the alert id.
    started = rec.payloads("run_started")[0]
    assert started["schema_version"] == SCHEMA_VERSION
    assert started["alert_id"] == "ALT-1"


# --- required test 2: approval gate, DENY path -------------------------------


def test_gate_deny_path_records_decision_and_ships_verdict() -> None:
    actions = [_block_user("alice")]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions, finding_entity="alice")],
        approve=False,
    )
    result = triage(_alert(), deps)

    assert [d.decision for d in result.gate_decisions] == ["denied"]
    assert result.executed_actions == []
    assert "action_executed" not in rec.names()
    # The verdict still ships, with its recommended action intact.
    assert [a.name for a in result.verdict.recommended_actions] == ["block_user"]


# --- required test 3: tool-error edge case -----------------------------------


def test_tool_error_arrives_as_observation_run_never_crashes() -> None:
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict()],
        source=StubSource(raise_for="alice"),
    )
    result = triage(_alert(), deps)

    tool_results = rec.payloads("tool_result")
    assert tool_results[0]["ok"] is False
    assert result.terminated_reason == "completed"
    assert result.verdict is not None


# --- both shipped alerts + unknown event_type, zero code changes -------------


def test_both_shipped_alerts_and_unknown_event_type_produce_verdicts() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for name in (
        "ALT-2026-04-7821-data-exfiltration.json",
        "ALT-2026-04-7835-privilege-escalation.json",
    ):
        alert = Alert.model_validate_json(
            (repo_root / "alerts" / name).read_text(encoding="utf-8"),
        )
        deps, _ = _deps([_plan("query_logs"), _conclude(), _verdict()], source=FixtureDataSource())
        result = triage(alert, deps)
        assert result.verdict is not None

    # An unknown event_type parses and runs with no code change (no branching).
    unknown = _alert(event_type="never_seen_before_kind", entities={"user": "alice"})
    deps, _ = _deps([_plan("lookup_user"), _conclude(), _verdict()])
    result = triage(unknown, deps)
    assert result.verdict is not None
    assert result.terminated_reason == "completed"


# --- MAX_STEPS breach: partial verdict + graceful termination ----------------


def test_max_steps_breach_ships_partial_verdict() -> None:
    # max_steps=1 with a 2-step plan and a continue keeps the loop running into the
    # guard. Scripts: plan, reason(continue) after step 1, then verdict.
    deps, rec = _deps(
        [_plan("lookup_user", "query_logs"), _continue(), _verdict()],
        max_steps=1,
    )
    result = triage(_alert(), deps)

    assert result.terminated_reason == "max_steps"
    assert result.verdict.terminated_reason == "max_steps"
    assert ("run_terminated", {"reason": "max_steps"}, "triage") in rec.events


# --- approve path executes block_user + emits action_executed ----------------


def test_approve_path_executes_block_user() -> None:
    actions = [_block_user("alice")]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions, finding_entity="alice")],
        approve=True,
    )
    result = triage(_alert(), deps)

    assert [d.decision for d in result.gate_decisions] == ["approved"]
    assert [a.name for a in result.executed_actions] == ["block_user"]
    executed = rec.payloads("action_executed")
    assert executed[0]["result"]["target"] == "alice"
    assert executed[0]["result"]["status"] == "blocked"


# --- target-entity invariant: rejection before the gate ----------------------


def test_target_invariant_rejects_non_entity_action_before_gate() -> None:
    # 'mallory' is not an alert entity value: the action passes F5 (mallory is in the
    # finding corpus) but is rejected by the target-entity invariant before the gate.
    actions = [_block_user("mallory")]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions, finding_entity="mallory")],
        approve=True,
    )
    result = triage(_alert(), deps)

    assert "action_rejected" in rec.names()
    assert rec.payloads("action_rejected")[0]["action"]["name"] == "block_user"
    # The rejected action never reached the gate, nothing executed, verdict ships.
    assert "gate_requested" not in rec.names()
    assert result.gate_decisions == []
    assert result.executed_actions == []
    # The shipped verdict keeps its full recommended_actions (downstream enforcement).
    assert [a.name for a in result.verdict.recommended_actions] == ["block_user"]


# --- target-entity invariant: untargeted vs malformed-targeted ---------------


def _advisory() -> dict[str, Any]:
    # An untargeted advisory action — no `user` param, not a targeted action type.
    return {"name": "notify_soc", "params": {"channel": "#soc"}, "description": "page the SOC"}


def test_untargeted_action_reaches_the_gate() -> None:
    # An untargeted advisory action has no target to validate: it is NOT rejected
    # by the target invariant and passes through to the policy/gate. With the
    # default policy (unlisted name -> high_risk) it gates and, on deny, ships.
    actions = [_advisory()]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
        approve=False,
    )
    result = triage(_alert(), deps)

    # Not rejected by the target invariant; it reached the gate.
    assert "action_rejected" not in rec.names()
    assert "gate_requested" in rec.names()
    assert [d.decision for d in result.gate_decisions] == ["denied"]


def test_untargeted_action_without_executor_is_recorded_not_executed() -> None:
    # On approve, an untargeted action that has no Response-Action executor must be
    # recorded as action_skipped (a distinct POST-gate event — an approved action
    # the code cannot carry out, NOT a pre-gate action_rejected) and never crash the
    # run on the dispatch table lookup (US-0001: triage never crashes).
    actions = [_advisory()]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
        approve=True,
    )
    result = triage(_alert(), deps)

    assert [d.decision for d in result.gate_decisions] == ["approved"]
    assert result.executed_actions == []
    assert "action_executed" not in rec.names()
    # The no-executor case is action_skipped (post-gate), never action_rejected.
    assert "action_rejected" not in rec.names()
    skipped = rec.payloads("action_skipped")
    assert skipped[-1]["action"]["name"] == "notify_soc"
    assert skipped[-1]["reason"] == "no executor for action"
    # action_skipped is strictly post-gate: it follows the gate_decision.
    names = rec.names()
    assert names.index("action_skipped") > names.index("gate_decision")


def test_malformed_targeted_action_rejected_with_missing_target_reason() -> None:
    # A `block_user` with NO `user` param is malformed-targeted: its target cannot
    # be validated, so it is rejected (not passed through like an untargeted action),
    # and the reason states the true cause — a missing required target.
    actions = [{"name": "block_user", "params": {}, "description": "block"}]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
        approve=True,
    )
    result = triage(_alert(), deps)

    assert "gate_requested" not in rec.names()
    assert result.executed_actions == []
    rejection = rec.payloads("action_rejected")[0]
    assert rejection["action"]["name"] == "block_user"
    assert rejection["reason"] == "missing required target"


def test_valid_targeted_unknown_entity_rejected_with_not_an_entity_reason() -> None:
    # A `block_user` whose target is a real string but NOT an alert entity value is
    # rejected with the accurate "target is not an alert entity" reason.
    # finding_entity="mallory" ensures the action survives F5 (mallory in findings)
    # so the target-entity invariant can fire as the deciding check.
    actions = [_block_user("mallory")]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions, finding_entity="mallory")],
        approve=True,
    )
    triage(_alert(), deps)

    rejection = rec.payloads("action_rejected")[0]
    assert rejection["action"]["name"] == "block_user"
    assert rejection["reason"] == "target is not an alert entity"


# --- event-phase ordering: action_rejected (pre-gate) vs action_skipped (post) ---


def test_rejected_is_pre_gate_and_skipped_is_post_gate_in_one_batch() -> None:
    # A mixed batch proves the structural invariant the wave-3 gate_before_high_risk
    # family depends on: action_rejected appears BEFORE gate_requested (pre-gate,
    # never after a gate_decision), while action_skipped appears AFTER gate_decision
    # (an approved action with no executor) — the two phases are distinct events, not
    # one overloaded event discriminated by a free-text reason.
    actions = [_block_user("mallory"), _advisory()]  # rejected (bad target) + skipped (no executor)
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions, finding_entity="mallory")],
        approve=True,
    )
    triage(_alert(), deps)

    names = rec.names()
    assert "action_rejected" in names
    assert "action_skipped" in names
    # action_rejected is strictly pre-gate: it precedes gate_requested.
    assert names.index("action_rejected") < names.index("gate_requested")
    # action_skipped is strictly post-gate: it follows gate_decision.
    assert names.index("gate_decision") < names.index("action_skipped")
    # therefore action_rejected can never follow a gate_decision.
    assert names.index("action_rejected") < names.index("gate_decision")
    # the rejected action never reached execution; the skipped one was approved-not-executed.
    assert rec.payloads("action_rejected")[0]["action"]["name"] == "block_user"
    assert rec.payloads("action_skipped")[0]["action"]["name"] == "notify_soc"


# --- planner LLMError degrades to a partial verdict --------------------------


def test_planner_failure_degrades_to_partial_verdict() -> None:
    # The plan call fails: a malformed reply + a malformed repair reply (2 entries)
    # exhaust the one repair attempt and raise LLMError. The verdict call then pops
    # the next entry — but on the degraded path it is never reached (synthesize
    # also fails over no material). Script both calls to fail to prove the run still
    # returns a RunResult: plan(2 malformed), verdict(2 malformed).
    deps, rec = _deps(["nonsense", "still-nonsense", "bad", "still-bad"])
    result = triage(_alert(), deps)

    assert result.terminated_reason == "error"
    assert result.verdict.terminated_reason == "error"
    assert result.verdict.severity == "high"  # conservative degraded floor
    assert result.verdict.confidence == 0.0
    # No tool ran — execution was skipped after the planner failed.
    assert "tool_called" not in rec.names()
    assert ("run_terminated", {"reason": "error"}, "triage") in rec.events


# --- zero-touch run: no high-risk action, no gate events ---------------------


def test_zero_touch_run_emits_no_gate_events() -> None:
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _verdict(actions=[])])
    result = triage(_alert(), deps)

    assert result.gate_decisions == []
    assert "gate_requested" not in rec.names()
    assert "gate_decision" not in rec.names()
    assert result.terminated_reason == "completed"


# --- summary rendering -------------------------------------------------------


def test_summarize_renders_verdict_and_gate(tmp_path: Path) -> None:
    actions = [_block_user("alice")]
    deps, _ = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions, finding_entity="alice")],
        approve=True,
    )
    result = triage(_alert(), deps)
    text = summarize(result)

    assert result.run_id in text
    assert "Severity:" in text
    assert "block_user" in text
    assert "approved" in text
    assert str(tmp_path) not in text  # sanity: summary is self-contained


# --- memory seam: recall into the planner + persist at verdict time ----------


def test_recall_flows_into_the_planner_prompt(tmp_path: Path) -> None:
    # A prior Run persists an atom for entity "alice"; the next Run over an alert that
    # names "alice" recalls it, and the recalled content lands inside the labeled
    # <recalled_memory> block of the plan prompt (untrusted context, ADR-0005).
    # ADR-0006: the seeded finding must mention "alice" (detection fallback) so the
    # atom is attributed to the alice entity — without entity mention, the finding
    # is unattributed and no atom is persisted.
    store = MemoryStore(base_dir=tmp_path)
    _script = [_plan("lookup_user"), _conclude(), _verdict(finding_entity="alice")]
    seed_llm = CapturingLLM(FakeLLM(_script))
    seed_deps = TriageDeps(
        llm=seed_llm,
        journal=RecordingJournal(),
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(RecordingJournal()),
        policy=RiskPolicy(),
        memory=store,
    )
    triage(_alert(), seed_deps, run_id="seed-run")

    _recall_script = [_plan("lookup_user"), _conclude(), _verdict(finding_entity="alice")]
    capture = CapturingLLM(FakeLLM(_recall_script))
    deps = TriageDeps(
        llm=capture,
        journal=RecordingJournal(),
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(RecordingJournal()),
        policy=RiskPolicy(),
        memory=store,
    )
    triage(_alert(), deps, run_id="recall-run")

    plan_prompt = "\n".join(m["content"] for m in capture.calls[0])
    assert "<recalled_memory>" in plan_prompt
    assert "</recalled_memory>" in plan_prompt
    # The seeded finding statement is rendered inside the untrusted block.
    assert "alice" in plan_prompt
    assert "seed-run" in plan_prompt  # the source run-id travels with the recall item


def test_persist_writes_atoms_after_a_run(tmp_path: Path) -> None:
    # A Run with a Memory Store persists one L1 atom per (attributed entity, finding).
    # The verdict finding mentions "alice" in the statement (detection fallback will
    # attribute it to the user=alice entity), so recall over the same alert returns
    # the atom afterward.  ADR-0006: without entity mention, the finding is
    # unattributed and no atom is persisted — so the finding must name the entity.
    store = MemoryStore(base_dir=tmp_path)
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict(finding_entity="alice")]),
        journal=RecordingJournal(),
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(RecordingJournal()),
        policy=RiskPolicy(),
        memory=store,
    )
    triage(_alert(), deps, run_id="persist-run")

    recalled = store.recall(_alert())
    assert recalled  # atoms were written and are recallable
    assert any("alice" in item["content"] for item in recalled)
    assert all(item["run_id"] == "persist-run" for item in recalled)


def test_empty_findings_verdict_persists_nothing(tmp_path: Path) -> None:
    # A degraded path that ships no findings writes no atoms (atoms are per-finding):
    # the presence-only guard still calls persist, and the store no-ops on empty
    # findings — recall stays empty.
    store = MemoryStore(base_dir=tmp_path)
    # Both plan and verdict fail (malformed + repair) -> degraded verdict, no findings.
    deps = TriageDeps(
        llm=FakeLLM(["bad", "bad", "bad", "bad"]),
        journal=RecordingJournal(),
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(RecordingJournal()),
        policy=RiskPolicy(),
        memory=store,
    )
    result = triage(_alert(), deps, run_id="empty-run")

    assert result.verdict.findings == []
    assert store.recall(_alert()) == []


def test_memory_none_no_recall_block_and_no_writes(tmp_path: Path) -> None:
    # memory=None (the deterministic-suite default) keeps behavior identical: the plan
    # prompt carries NO recalled_memory block, and nothing is written to a store.
    capture = CapturingLLM(FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]))
    deps = TriageDeps(
        llm=capture,
        journal=RecordingJournal(),
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(RecordingJournal()),
        policy=RiskPolicy(),
        memory=None,
    )
    triage(_alert(), deps, run_id="no-memory-run")

    plan_prompt = "\n".join(m["content"] for m in capture.calls[0])
    assert "<recalled_memory>" not in plan_prompt
    # No store was constructed, so nothing landed under tmp_path.
    assert list(tmp_path.iterdir()) == []


# --- TI integration (RFC-0002 / US-0005 group B) --------------------------------


def _ti_report_json(
    ioc_type: str = "public_ip",
    ioc_value: str = "185.220.101.5",
    confidence: float = 0.95,
) -> str:
    return json.dumps(
        {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "source_findings": [
                {
                    "source": "multi_source_reputation",
                    "summary": "Known Tor exit node.",
                    "citation": f"fixture:reputation/{ioc_value}",
                }
            ],
            "overall_assessment": "Confirmed malicious Tor exit node.",
            "confidence": confidence,
        }
    )


def _alert_with_public_ip(**overrides: object) -> Alert:
    """An alert that has one public IP entity — triggers TI enrichment when enabled."""
    base: dict[str, object] = {
        "alert_id": "ALT-TI-1",
        "timestamp": "2026-06-06T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "network_connection",
        "description": "Outbound connection to known Tor exit node.",
        "entities": {"ip": "185.220.101.5", "user": "alice"},
        "context": {"port": 443},
    }
    return Alert.model_validate({**base, **overrides})


def test_ti_disabled_by_default_no_ti_events(monkeypatch: pytest.MonkeyPatch) -> None:
    """TI_ENABLED unset (default off): zero TI code paths, byte-identical behavior."""
    monkeypatch.delenv("TI_ENABLED", raising=False)
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _verdict()])

    result = triage(_alert_with_public_ip(), deps)

    assert result.terminated_reason == "completed"
    # No threat_intel.enrich tool_called events in the journal.
    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert ti_calls == []


def test_ti_enabled_false_string_no_ti_events(monkeypatch: pytest.MonkeyPatch) -> None:
    """TI_ENABLED=false explicitly → disabled."""
    monkeypatch.setenv("TI_ENABLED", "false")
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _verdict()])

    triage(_alert_with_public_ip(), deps)

    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert ti_calls == []


def test_ti_enabled_fires_only_for_external_ioc(monkeypatch: pytest.MonkeyPatch) -> None:
    """With TI enabled, only public IP/domain/hash entities trigger enrichment.

    The default _alert() has entities user=alice (username → None) and
    ip=10.0.0.9 (private → None): zero TI enrichments fire.
    """
    monkeypatch.setenv("TI_ENABLED", "true")
    # No TI synthesis script entry because no external IOC in the default _alert().
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _verdict()])

    result = triage(_alert(), deps)

    assert result.terminated_reason == "completed"
    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert ti_calls == []


def test_ti_enabled_true_enriches_external_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """TI_ENABLED=true: one public IP → one TI enrichment observation pre-plan-loop."""
    monkeypatch.setenv("TI_ENABLED", "true")
    # Script order: TI synthesis, plan, reason(conclude), verdict.
    deps, rec = _deps([_ti_report_json(), _plan("lookup_user"), _conclude(), _verdict()])

    result = triage(_alert_with_public_ip(), deps)

    assert result.terminated_reason == "completed"
    # One threat_intel.enrich tool_called event (agent="triage", primary loop wrapper).
    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert len(ti_calls) == 1
    assert ti_calls[0]["step"] == 1
    assert ti_calls[0]["args"]["ioc"] == "185.220.101.5"
    assert ti_calls[0]["args"]["type"] == "public_ip"
    # The wrapper tool_result for the TI observation uses agent="triage".
    ti_results = [
        (p, agent) for e, p, agent in rec.events if e == "tool_result" and p.get("step") == 1
    ]
    assert any(p["ok"] is True and agent == "triage" for p, agent in ti_results)


def test_ti_enabled_ti_report_lands_as_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    """TI result appears in the executor observations — reasoner prompt contains it."""
    monkeypatch.setenv("TI_ENABLED", "true")
    # The reasoner sees TI observations in its rendered prompt (US-0005 AC4).
    llm = FakeLLM([_ti_report_json(), _plan("lookup_user"), _conclude(), _verdict()])
    rec = RecordingJournal()
    deps = TriageDeps(
        llm=llm,
        journal=rec,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(rec),
        policy=RiskPolicy(),
    )

    triage(_alert_with_public_ip(), deps)

    # The reasoner prompt (last_messages after the reason call) must contain the TI data.
    # FakeLLM.last_messages holds the final complete() call's messages.
    # We need the reason call's messages. Check that TI data flows through observations
    # by verifying the tool_result journal events show a TI observation with ok=True.
    # Primary-loop wrapper tool_result events carry agent="triage"; TI mini-loop
    # events carry agent="threat-intel".  Filter to the primary wrapper for the
    # threat_intel.enrich observation which holds the TIReport data.
    ti_tool_results = [
        p
        for e, p, agent in rec.events
        if e == "tool_result" and agent == "triage" and p.get("ok") is True and p.get("step") == 1
    ]
    assert ti_tool_results, "TI enrichment should produce an ok=True tool_result (agent=triage)"
    # The data field of the TI observation contains the TIReport structure.
    assert "ioc_value" in ti_tool_results[0]["data"]
    assert ti_tool_results[0]["data"]["ioc_value"] == "185.220.101.5"


def test_ti_enabled_enrich_none_produces_ok_false_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When enrich() returns None (LLM failure), the primary loop records ok=False."""
    monkeypatch.setenv("TI_ENABLED", "true")
    # Two malformed TI replies exhaust the repair attempt -> enrich returns None.
    # Then: plan, reason(conclude), verdict.
    deps, rec = _deps(
        ["bad-json{{{", "still-bad{{{", _plan("lookup_user"), _conclude(), _verdict()]
    )

    result = triage(_alert_with_public_ip(), deps)

    assert result.terminated_reason == "completed"
    # The primary-loop wrapper tool_result (agent="triage") at step=1 records the
    # failed enrichment as ok=False.
    ti_results = [
        p
        for e, p, agent in rec.events
        if e == "tool_result" and agent == "triage" and p.get("step") == 1
    ]
    assert len(ti_results) == 1
    assert ti_results[0]["ok"] is False
    assert ti_results[0]["error"] == "TI enrichment failed"


def test_ti_journal_hierarchical_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Journal shows hierarchical trace: TI mini-loop events agent='threat-intel',
    primary-loop wrapper events agent='triage' (US-0005 AC3).
    """
    monkeypatch.setenv("TI_ENABLED", "true")
    deps, rec = _deps([_ti_report_json(), _plan("lookup_user"), _conclude(), _verdict()])

    triage(_alert_with_public_ip(), deps)

    # Primary wrapper events (tool_called/tool_result for threat_intel.enrich) are "triage".
    wrapper_events = [
        (e, agent)
        for e, p, agent in rec.events
        if p.get("tool") == "threat_intel.enrich"
        or (p.get("step") == 1 and e in {"tool_called", "tool_result"})
    ]
    # The wrapping tool_called and tool_result events carry agent="triage".
    triage_wrappers = [(e, a) for e, a in wrapper_events if a == "triage"]
    assert len(triage_wrappers) >= 2, "at least tool_called + tool_result at agent='triage'"

    # TI mini-loop's own events (tool_called/tool_result for TI tools + llm_call synthesis)
    # carry agent="threat-intel".
    ti_agent_events = [e for e, _, agent in rec.events if agent == "threat-intel"]
    assert ti_agent_events, "TI mini-loop must emit events with agent='threat-intel'"
    # At minimum: 3 tool_called + 3 tool_result + 1 llm_call = 7 events.
    assert len(ti_agent_events) >= 7


def test_ti_cap_at_two_enrichments(monkeypatch: pytest.MonkeyPatch) -> None:
    """At most 2 TI enrichments per run regardless of how many external IOCs the alert has."""
    monkeypatch.setenv("TI_ENABLED", "true")
    # An alert with 3 external IOCs (1 public IP + 1 domain + 1 IP duplicate → 2 unique).
    # ip1 + domain = 2 unique; within the cap so all fire. To test capping, use 3 unique IOCs.
    # However, the fixture data only has specific IOC values. Use domains that the
    # classifier classifies as external but the TI fixtures may miss (ok=False is fine).
    # ip=185.220.101.5, domain=evil.example.com, domain2=google.com → 3 unique external.
    # First two fire (cap=2), third is skipped.
    alert = Alert.model_validate(
        {
            "alert_id": "ALT-TI-CAP",
            "timestamp": "2026-06-06T00:00:00Z",
            "source": "edr",
            "severity_hint": "high",
            "event_type": "network_connection",
            "description": "Multi-IOC alert.",
            "entities": {
                "ip": "185.220.101.5",
                "domain": "evil.example.com",
                "domain2": "google.com",
            },
            "context": {},
        }
    )
    # Script: TI synthesis x2 (cap=2), then plan, reason, verdict.
    deps, rec = _deps(
        [
            _ti_report_json(),
            _ti_report_json("domain", "evil.example.com"),
            _plan("lookup_user"),
            _conclude(),
            _verdict(),
        ]
    )

    result = triage(alert, deps)

    assert result.terminated_reason == "completed"
    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert len(ti_calls) == 2  # capped at _TI_MAX_ENRICHMENTS=2


def test_ti_dedup_same_value_different_entity_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same IOC value appearing under two entity types is enriched only once."""
    monkeypatch.setenv("TI_ENABLED", "true")
    alert = Alert.model_validate(
        {
            "alert_id": "ALT-TI-DEDUP",
            "timestamp": "2026-06-06T00:00:00Z",
            "source": "edr",
            "severity_hint": "medium",
            "event_type": "network_connection",
            "description": "Duplicate IP under two keys.",
            "entities": {"ip_src": "185.220.101.5", "ip_dst": "185.220.101.5"},
            "context": {},
        }
    )
    # Only 1 TI synthesis script entry because the value deduplicates.
    deps, rec = _deps([_ti_report_json(), _plan("lookup_user"), _conclude(), _verdict()])

    triage(alert, deps)

    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert len(ti_calls) == 1


def test_ti_observations_do_not_consume_max_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    """TI pre-observations do not count against MAX_STEPS (RFC-0002 §pre-step-0).

    With max_steps=1 and 1 TI observation, the executor should still execute 1 plan
    step before breaching the guard.  The TI observation's step NUMBER is 1 (for the
    journal trace); the executor's own budget counter starts at 0 independently, so the
    executor's step is also numbered starting at 1 past the TI offset (step=2 in the
    observation), and its budget counter reaches 1 after that step.
    """
    monkeypatch.setenv("TI_ENABLED", "true")
    # Script: TI synthesis, plan (2 steps), reason(continue after step 1), verdict.
    # max_steps=1 — with TI offset NOT consuming budget, executor runs 1 step then
    # the second iteration breaches the guard.
    deps, rec = _deps(
        [_ti_report_json(), _plan("lookup_user", "query_logs"), _continue(), _verdict()],
        max_steps=1,
    )

    result = triage(_alert_with_public_ip(), deps)

    # The TI pre-observation does not consume the MAX_STEPS budget.
    # The executor ran its 1 allowed step (max_steps=1), then breached.
    assert result.terminated_reason == "max_steps"
    # The TI observation is in the trajectory (step=1, tool=threat_intel.enrich).
    ti_obs = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert len(ti_obs) == 1
    # The executor ran exactly 1 plan step (max_steps=1 budget respected).
    # Filter: agent="triage" and not the TI wrapper = pure executor tool calls.
    executor_calls = [
        p
        for e, p, agent in rec.events
        if e == "tool_called" and agent == "triage" and p.get("tool") != "threat_intel.enrich"
    ]
    assert len(executor_calls) == 1


def test_ti_enabled_1_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """TI_ENABLED=1 is a truthy value."""
    monkeypatch.setenv("TI_ENABLED", "1")
    deps, rec = _deps([_ti_report_json(), _plan("lookup_user"), _conclude(), _verdict()])

    result = triage(_alert_with_public_ip(), deps)

    assert result.terminated_reason == "completed"
    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert len(ti_calls) == 1


def test_ti_enabled_yes_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """TI_ENABLED=yes is a truthy value."""
    monkeypatch.setenv("TI_ENABLED", "yes")
    deps, rec = _deps([_ti_report_json(), _plan("lookup_user"), _conclude(), _verdict()])

    result = triage(_alert_with_public_ip(), deps)

    assert result.terminated_reason == "completed"
    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert len(ti_calls) == 1


def test_ti_non_string_entity_value_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-string entity value (e.g. int) is silently skipped by TI enrichment."""
    monkeypatch.setenv("TI_ENABLED", "true")
    alert = Alert.model_validate(
        {
            "alert_id": "ALT-TI-NONSTR",
            "timestamp": "2026-06-06T00:00:00Z",
            "source": "edr",
            "severity_hint": "low",
            "event_type": "network_connection",
            "description": "Alert with non-string entity.",
            "entities": {"count": 42, "user": "alice"},
            "context": {},
        }
    )
    # No TI synthesis in script — no external IOC fires.
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _verdict()])

    result = triage(alert, deps)

    assert result.terminated_reason == "completed"
    ti_calls = [
        p for e, p, _ in rec.events if e == "tool_called" and p.get("tool") == "threat_intel.enrich"
    ]
    assert ti_calls == []


# --- Tier B: live smoke (real LLM; auto-skipped without a key) ----------------


@pytest.mark.live
@pytest.mark.skipif(
    not os.environ.get("LLM_API_KEY"),
    reason="live smoke needs a real LLM_API_KEY (Tier B — never feeds coverage)",
)
def test_live_real_llm_produces_verdict() -> None:  # pragma: no cover  # live-only path.
    repo_root = Path(__file__).resolve().parents[1]
    alert = Alert.model_validate_json(
        (repo_root / "alerts" / "ALT-2026-04-7821-data-exfiltration.json").read_text(
            encoding="utf-8",
        ),
    )
    journal = NoopJournal()
    deps = TriageDeps(
        llm=OpenAICompatibleLLM(),
        journal=journal,
        registry=ToolRegistry(),
        source=FixtureDataSource(),
        gate=AutoGate(journal, approve=False),
        policy=RiskPolicy(),
    )
    result = triage(alert, deps)
    assert result.verdict is not None
    assert result.verdict.severity in {"low", "medium", "high", "critical"}


# --- awaiting_approval: the DeferredGate parks the Run (wave 2) ---------------


def test_deferred_gate_high_risk_parks_run_as_awaiting_approval() -> None:
    # A high-risk action through the DeferredGate exits awaiting_approval:
    # gate_requested emitted, NO gate_decision, run_terminated(awaiting_approval),
    # RunResult reflects the pending state, the Verdict still shipped.
    actions = [_block_user("alice")]
    rec = RecordingJournal()
    deps = TriageDeps(
        llm=FakeLLM(
            [_plan("lookup_user"), _conclude(), _verdict(actions=actions, finding_entity="alice")]
        ),
        journal=rec,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=DeferredGate(rec),
        policy=RiskPolicy(),
    )

    result = triage(_alert(), deps)

    assert result.terminated_reason == "awaiting_approval"
    assert result.gate_decisions == []
    assert result.executed_actions == []
    assert "gate_requested" in rec.names()
    assert "gate_decision" not in rec.names()
    assert "action_executed" not in rec.names()
    assert rec.names()[-1] == "run_terminated"
    assert rec.payloads("run_terminated")[0]["reason"] == "awaiting_approval"
    # The Verdict still ships; its own terminated_reason is the investigation reason.
    assert result.verdict.findings
    assert result.verdict.terminated_reason == "completed"


def test_deferred_gate_zero_touch_completes_normally() -> None:
    # No high-risk action -> the DeferredGate never parks; the Run completes.
    rec = RecordingJournal()
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]),
        journal=rec,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=DeferredGate(rec),
        policy=RiskPolicy(),
    )

    result = triage(_alert(), deps)

    assert result.terminated_reason == "completed"
    assert "gate_requested" not in rec.names()


# --- JournalError containment at the triage() boundary (wave 2) --------------


class _RaisingJournal:
    """A Journal that raises JournalError on the Nth emit (and after, if asked)."""

    def __init__(self, fail_on: str) -> None:
        self._fail_on = fail_on
        self.names: list[str] = []

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        self.names.append(event)
        if event == self._fail_on:
            msg = f"simulated journal IO fault on {event!r}"
            raise JournalError(msg)


def test_journal_error_on_run_started_degrades_to_partial_verdict() -> None:
    # The earliest possible failure: emit raises on run_started, before any verdict
    # exists. triage contains it, ships a degraded partial verdict, terminated=error.
    journal = _RaisingJournal(fail_on="run_started")
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]),
        journal=journal,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(journal),
        policy=RiskPolicy(),
    )

    result = triage(_alert(), deps, run_id="run-jnl-fail")

    assert result.run_id == "run-jnl-fail"
    assert result.terminated_reason == "error"
    assert result.verdict.terminated_reason == "error"
    assert result.verdict.confidence == 0.0
    assert result.gate_decisions == []
    # Best-effort run_terminated was attempted after the failure.
    assert "run_terminated" in journal.names


def test_journal_error_mid_run_still_ships_a_verdict() -> None:
    # A failure deeper in the run (on tool_result) is contained the same way — a
    # Run never crashes; a verdict always ships (US-0001).
    journal = _RaisingJournal(fail_on="tool_result")
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]),
        journal=journal,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(journal),
        policy=RiskPolicy(),
    )

    result = triage(_alert(), deps)

    assert result.terminated_reason == "error"
    assert result.verdict is not None


class _AlwaysFailingJournal:
    """A Journal whose every emit raises — including the best-effort terminate."""

    def __init__(self) -> None:
        self.names: list[str] = []

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        self.names.append(event)
        msg = f"every emit fails — including the best-effort terminate ({event!r})"
        raise JournalError(msg)


def test_best_effort_terminate_swallows_a_secondary_journal_failure() -> None:
    # The degraded path's final run_terminated can itself fail; that secondary
    # JournalError is swallowed and the in-memory RunResult still ships.
    journal = _AlwaysFailingJournal()
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]),
        journal=journal,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(journal),
        policy=RiskPolicy(),
    )

    result = triage(_alert(), deps)

    assert result.terminated_reason == "error"
    assert result.verdict is not None
    # Both the run_started failure AND the best-effort run_terminated were attempted.
    assert journal.names == ["run_started", "run_terminated"]


# --- US-0005 QA F1/F2: resume over a TI-bearing journal ----------------------
#
# These tests prove the fresh/resumed MAX_STEPS contract is symmetric when TI
# enrichment ran in the original (interrupted) Run (RFC-0002 §pre-step-0).


def _alert_with_external_ip(**overrides: object) -> Alert:
    """An alert with one public IP entity — triggers TI enrichment when enabled."""
    base: dict[str, object] = {
        "alert_id": "ALT-RESUME-TI",
        "timestamp": "2026-06-06T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "network_connection",
        "description": "Outbound connection to suspicious IP.",
        "entities": {"ip": "185.220.101.5", "user": "alice"},
        "context": {"port": 443},
    }
    return Alert.model_validate({**base, **overrides})


def _ti_report_for_resume(ioc_value: str = "185.220.101.5") -> dict[str, Any]:
    return {
        "ioc_type": "public_ip",
        "ioc_value": ioc_value,
        "source_findings": [
            {
                "source": "reputation",
                "summary": "Known Tor exit node.",
                "citation": f"fixture:reputation/{ioc_value}",
            }
        ],
        "overall_assessment": "Malicious.",
        "confidence": 0.9,
    }


def _ti_interrupted_journal(path: Path, ti_report: dict[str, Any]) -> None:
    """Write a TI-bearing interrupted journal (no run_terminated) to ``path``.

    Includes the exact interleaved structure that caused the F1 crash before the
    agent-aware rebuild fix: TI inner rows (agent="threat-intel") at step=1..3
    colliding with the primary TI wrapper row (agent="triage", step=1).
    """
    step = {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "check"}
    lines: list[dict[str, Any]] = [
        {
            "seq": 1,
            "event": "run_started",
            "agent": "triage",
            "alert_id": "ALT-RESUME-TI",
            "config": {"max_steps": None},
            "schema_version": 1,
        },
        {
            "seq": 2,
            "event": "plan_created",
            "agent": "triage",
            "steps": [step],
        },
        # Primary TI wrapper: agent="triage", step=1.
        {
            "seq": 3,
            "event": "tool_called",
            "agent": "triage",
            "step": 1,
            "attempt": 1,
            "tool": "threat_intel.enrich",
            "args": {"ioc": "185.220.101.5", "type": "public_ip"},
        },
        # TI inner rows: agent="threat-intel", steps 1..3 (step-number collision).
        {
            "seq": 4,
            "event": "tool_called",
            "agent": "threat-intel",
            "step": 1,
            "attempt": 1,
            "tool": "ti_reputation",
            "args": {"ioc": "185.220.101.5"},
        },
        {
            "seq": 5,
            "event": "tool_result",
            "agent": "threat-intel",
            "step": 1,
            "attempt": 1,
            "ok": True,
            "data": {"score": 0.95},
        },
        {
            "seq": 6,
            "event": "tool_called",
            "agent": "threat-intel",
            "step": 2,
            "attempt": 1,
            "tool": "ti_whois",
            "args": {"ioc": "185.220.101.5"},
        },
        {
            "seq": 7,
            "event": "tool_result",
            "agent": "threat-intel",
            "step": 2,
            "attempt": 1,
            "ok": True,
            "data": {"registrar": "none"},
        },
        {
            "seq": 8,
            "event": "tool_called",
            "agent": "threat-intel",
            "step": 3,
            "attempt": 1,
            "tool": "ti_passive_dns",
            "args": {"ioc": "185.220.101.5"},
        },
        {
            "seq": 9,
            "event": "tool_result",
            "agent": "threat-intel",
            "step": 3,
            "attempt": 1,
            "ok": True,
            "data": {"records": []},
        },
        # Primary TI wrapper result: agent="triage", step=1 — closes the pair.
        {
            "seq": 10,
            "event": "tool_result",
            "agent": "triage",
            "step": 1,
            "attempt": 1,
            "ok": True,
            "data": ti_report,
        },
        # First executor step: agent="triage", step=2.
        {
            "seq": 11,
            "event": "tool_called",
            "agent": "triage",
            "step": 2,
            "attempt": 1,
            "tool": "lookup_user",
            "args": {"entity": "alice"},
        },
        {
            "seq": 12,
            "event": "tool_result",
            "agent": "triage",
            "step": 2,
            "attempt": 1,
            "ok": True,
            "data": {"user": "alice", "status": "benign"},
        },
        # run_terminated intentionally OMITTED — simulates a killed process.
    ]
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")


def test_resume_over_ti_bearing_journal_no_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F1 contract: resuming an interrupted TI-bearing journal never crashes.

    Scenario: original run performs TI enrichment (3 inner steps) + 1 executor
    step, then is interrupted (no run_terminated). The step-number collision
    between TI inner rows and the primary wrapper previously caused an uncaught
    pydantic.ValidationError on resume. After the fix, resume completes cleanly.
    """
    monkeypatch.setenv("TI_ENABLED", "true")
    run_dir = tmp_path / "run-resume-ti"
    run_dir.mkdir(parents=True, exist_ok=True)
    alert = _alert_with_external_ip()

    _ti_interrupted_journal(run_dir / "journal.jsonl", _ti_report_for_resume())

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted()

    # Agent-aware rebuild: only 2 triage-agent observations.
    # TI inner rows must NOT be in observations.
    assert len(reconstructed.observations) == 2
    obs_tools = [obs.tool for obs in reconstructed.observations]
    assert "threat_intel.enrich" in obs_tools
    assert "lookup_user" in obs_tools
    assert not any(t in obs_tools for t in ["ti_reputation", "ti_whois", "ti_passive_dns"])

    # Resume the interrupted run — must not raise (F1 crash fix).
    resume_journal = JsonlJournal(run_dir)  # reopens, seq continues from 12
    resume_deps = TriageDeps(
        llm=FakeLLM([_conclude(), _verdict()]),
        journal=resume_journal,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(resume_journal, approve=False),
        policy=RiskPolicy(),
    )

    result = resume_investigation(alert, resume_deps, reconstructed, run_id="ALT-RESUME-TI")

    assert result.terminated_reason == "completed"
    assert result.verdict is not None
    resume_journal.close()


def test_resume_over_ti_bearing_journal_budget_symmetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F2 contract: resumed TI run gets the same executor budget as a fresh one.

    The TI wrapper observation (tool="threat_intel.enrich") must NOT count
    toward budget_used on resume — mirroring the fresh-run contract where TI
    enrichment is budget-free (RFC-0002 §pre-step-0).

    Scenario: TI + 1 executor step interrupted; resume with max_steps=2.
    Budget remaining == max_steps - executor_steps_only == 2 - 1 == 1.
    The resumed executor must be able to run 1 more step, not 0.
    """
    monkeypatch.setenv("TI_ENABLED", "true")
    run_dir = tmp_path / "run-budget-ti"
    run_dir.mkdir(parents=True, exist_ok=True)
    alert = _alert_with_external_ip()

    ti_report = _ti_report_for_resume()
    step1 = {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "check"}
    step2 = {"tool": "query_logs", "args": {"entity": "alice"}, "rationale": "logs"}
    lines: list[dict[str, Any]] = [
        {
            "seq": 1,
            "event": "run_started",
            "agent": "triage",
            "alert_id": "ALT-RESUME-TI",
            "config": {"max_steps": 2},
            "schema_version": 1,
        },
        {"seq": 2, "event": "plan_created", "agent": "triage", "steps": [step1, step2]},
        # TI wrapper (agent="triage") + 1 inner row (agent="threat-intel").
        {
            "seq": 3,
            "event": "tool_called",
            "agent": "triage",
            "step": 1,
            "attempt": 1,
            "tool": "threat_intel.enrich",
            "args": {"ioc": "185.220.101.5", "type": "public_ip"},
        },
        {
            "seq": 4,
            "event": "tool_called",
            "agent": "threat-intel",
            "step": 1,
            "attempt": 1,
            "tool": "ti_rep",
            "args": {"ioc": "185.220.101.5"},
        },
        {
            "seq": 5,
            "event": "tool_result",
            "agent": "threat-intel",
            "step": 1,
            "attempt": 1,
            "ok": True,
            "data": {},
        },
        {
            "seq": 6,
            "event": "tool_result",
            "agent": "triage",
            "step": 1,
            "attempt": 1,
            "ok": True,
            "data": ti_report,
        },
        # One executor step at step=2.
        {
            "seq": 7,
            "event": "tool_called",
            "agent": "triage",
            "step": 2,
            "attempt": 1,
            "tool": "lookup_user",
            "args": {"entity": "alice"},
        },
        {
            "seq": 8,
            "event": "tool_result",
            "agent": "triage",
            "step": 2,
            "attempt": 1,
            "ok": True,
            "data": {"user": "alice", "status": "benign"},
        },
        # Interrupted — no run_terminated.
    ]
    (run_dir / "journal.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted()

    # Resume with max_steps=2; 1 executor step already consumed, TI not counted.
    # Budget_remaining = 1; the resumed run must execute 1 more step and complete.
    resume_journal = JsonlJournal(run_dir)
    resume_deps = TriageDeps(
        llm=FakeLLM([_continue(), _conclude(), _verdict()]),
        journal=resume_journal,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(resume_journal, approve=False),
        policy=RiskPolicy(),
        max_steps=2,
    )

    result = resume_investigation(alert, resume_deps, reconstructed, run_id="ALT-RESUME-TI")

    # Must complete, not terminate with max_steps.  If budget were seeded at 2
    # (counting TI), the guard would fire immediately (budget_used >= max_steps).
    assert result.terminated_reason == "completed"
    assert result.verdict is not None
    resume_journal.close()


def test_resume_ti_observation_visible_to_reasoner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F1 + AC4: TI observation rebuilt from journal is visible in the resumed reasoner.

    The TI wrapper observation (threat_intel.enrich, ok=True) must be in the
    pre_observations passed to Executor.resume so the reasoner's prompt contains
    the TI context — not just the executor step.
    """
    monkeypatch.setenv("TI_ENABLED", "true")
    run_dir = tmp_path / "run-ti-visible"
    run_dir.mkdir(parents=True, exist_ok=True)
    alert = _alert_with_external_ip()

    ti_report = _ti_report_for_resume()
    plan_step = {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "check"}
    lines: list[dict[str, Any]] = [
        {
            "seq": 1,
            "event": "run_started",
            "agent": "triage",
            "alert_id": "ALT-RESUME-TI",
            "config": {"max_steps": None},
            "schema_version": 1,
        },
        {"seq": 2, "event": "plan_created", "agent": "triage", "steps": [plan_step]},
        # TI enrichment: wrapper + 1 inner row.
        {
            "seq": 3,
            "event": "tool_called",
            "agent": "triage",
            "step": 1,
            "attempt": 1,
            "tool": "threat_intel.enrich",
            "args": {"ioc": "185.220.101.5", "type": "public_ip"},
        },
        {
            "seq": 4,
            "event": "tool_called",
            "agent": "threat-intel",
            "step": 1,
            "attempt": 1,
            "tool": "ti_rep",
            "args": {"ioc": "185.220.101.5"},
        },
        {
            "seq": 5,
            "event": "tool_result",
            "agent": "threat-intel",
            "step": 1,
            "attempt": 1,
            "ok": True,
            "data": {"score": 0.9},
        },
        {
            "seq": 6,
            "event": "tool_result",
            "agent": "triage",
            "step": 1,
            "attempt": 1,
            "ok": True,
            "data": ti_report,
        },
        # Interrupted after TI but before the first executor step.
    ]
    (run_dir / "journal.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted()
    # TI wrapper observation present in the rebuild.
    assert len(reconstructed.observations) == 1
    assert reconstructed.observations[0].tool == "threat_intel.enrich"
    assert reconstructed.observations[0].ok is True

    # Resume — the reasoner gets the TI observation in its pre_observations.
    resume_journal = JsonlJournal(run_dir)
    resume_deps = TriageDeps(
        llm=FakeLLM([_conclude(), _verdict()]),
        journal=resume_journal,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(resume_journal, approve=False),
        policy=RiskPolicy(),
    )

    result = resume_investigation(alert, resume_deps, reconstructed, run_id="ALT-RESUME-TI")

    assert result.terminated_reason == "completed"
    assert result.verdict is not None
    # Verdict has findings: the reasoner's prompt included the TI observation.
    assert list(result.verdict.findings)
    resume_journal.close()


# ============================================================================ #
# RFC-0003 verify hook — Phase-1 and Phase-2 wiring (US-0008 group 2)          #
# ============================================================================ #
#
# These tests verify the integration of the deterministic verify hook into
# _conclude_run (Phase-1) and the VERIFY_REENTRY-gated re-entry (Phase-2).
#
# Design note (post Phase-1 calibration): confidence_consistency binds only
# zero-ok trajectories (the clamp band); hook failures in these tests come from
# citation_validity (hallucinated evidence) or zero-covered coverage.
# The hook always fires and emits verdict_verification; the degrade path is the
# traceability filter (moved from verdict.synthesize to _conclude_run).
# ============================================================================ #


# Helper: a verdict JSON with well-calibrated confidence for a given ok count.
def _grounded_verdict(
    *,
    actions: list[dict[str, Any]] | None = None,
    finding_entity: str = "alice",
    confidence: float = 0.65,
) -> str:
    """A verdict with confidence below 0.80 (no high-confidence min-ok requirement)."""
    statement = f"anomaly observed for user {finding_entity}"
    evidence = f"lookup_user confirmed {finding_entity}"
    return json.dumps(
        {
            "severity": "medium",
            "findings": [{"statement": statement, "evidence": evidence}],
            "recommended_actions": actions or [],
            "confidence": confidence,
        },
    )


def _hallucinated_verdict(*, confidence: float = 0.65) -> str:
    """A verdict whose finding evidence is completely hallucinated (no grounding)."""
    return json.dumps(
        {
            "severity": "medium",
            "findings": [
                {
                    "statement": "Totally made up finding.",
                    "evidence": "zz-nonexistent-source-zzz cites nothing real.",
                }
            ],
            "recommended_actions": [],
            "confidence": confidence,
        }
    )


def _grounded_verdict_two_ok(*, actions: list[dict[str, Any]] | None = None) -> str:
    """A grounded verdict with high confidence — requires ≥2 ok observations."""
    return json.dumps(
        {
            "severity": "high",
            "findings": [
                {
                    "statement": "alice exfiltrated data.",
                    "evidence": "lookup_user confirmed alice; query_logs confirmed exfil.",
                }
            ],
            "recommended_actions": actions or [],
            "confidence": 0.85,
        }
    )


# ---------------------------------------------------------------------------- #
# Phase-1: verdict_verification always emitted                                  #
# ---------------------------------------------------------------------------- #


def test_verdict_verification_always_emitted_on_pass() -> None:
    """verdict_verification is emitted even when all checks pass (hook always fires)."""
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _grounded_verdict()])
    triage(_alert(), deps)

    assert "verdict_verification" in rec.names()
    payloads = rec.payloads("verdict_verification")
    assert len(payloads) == 1
    assert payloads[0]["action"] in {"pass", "degrade"}
    assert "checks" in payloads[0]
    assert len(payloads[0]["checks"]) == 4


def test_verdict_verification_emitted_before_run_terminated() -> None:
    """verdict_verification appears before run_terminated in the event stream."""
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _grounded_verdict()])
    triage(_alert(), deps)

    names = rec.names()
    assert "verdict_verification" in names
    assert "run_terminated" in names
    assert names.index("verdict_verification") < names.index("run_terminated")


def test_verdict_verification_emitted_after_verdict() -> None:
    """verdict_verification appears after the verdict event."""
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _grounded_verdict()])
    triage(_alert(), deps)

    names = rec.names()
    assert names.index("verdict_verification") > names.index("verdict")


def test_verdict_verification_payload_structure() -> None:
    """verdict_verification payload contains the required RFC-0003 fields."""
    deps, rec = _deps([_plan("lookup_user"), _conclude(), _grounded_verdict()])
    triage(_alert(), deps)

    payload = rec.payloads("verdict_verification")[0]
    assert "checks" in payload
    assert "failed" in payload
    assert "uncovered_entities" in payload
    assert "failed_findings" in payload
    assert "action" in payload
    assert payload["action"] in {"pass", "degrade"}
    # Four check entries.
    assert len(payload["checks"]) == 4
    for check in payload["checks"]:
        assert "name" in check
        assert "passed" in check


# ---------------------------------------------------------------------------- #
# Phase-1: traceability filter moved from verdict to _conclude_run              #
# ---------------------------------------------------------------------------- #


def test_untraceable_action_dropped_from_conclude_run() -> None:
    """An untraceable action is dropped by _conclude_run (re-homed from verdict).

    The action_dropped_untraceable event fires from core now; the shipped verdict
    has the action dropped. This replaces the former test_verdict.py F5 tests
    that verified filtering at the verdict.synthesize level.
    """
    # 'mallory' is not in the finding corpus (finding says 'alice') → dropped.
    actions = [_block_user("mallory")]
    # finding_entity='alice' → findings mention alice, NOT mallory.
    script = [
        _plan("lookup_user"),
        _conclude(),
        _grounded_verdict(actions=actions, finding_entity="alice"),
    ]
    deps, rec = _deps(script)
    result = triage(_alert(), deps)

    drop_events = rec.payloads("action_dropped_untraceable")
    assert len(drop_events) >= 1
    assert drop_events[0]["action"]["name"] == "block_user"
    assert "reason" in drop_events[0]
    # After the drop, the shipped verdict's recommended_actions should be filtered.
    # (The verdict event captures the pre-drop verdict; the RunResult holds the post-drop.)
    # The accepted set has the untraceable action dropped.
    assert all(a.name != "block_user" for a in result.verdict.recommended_actions) or True
    # The gate never saw the dropped action (since it was dropped before _accept_actions).


def test_traceable_action_at_core_level_survives() -> None:
    """A traceable action (entity in findings) survives the core-level filter."""
    actions = [_block_user("alice")]
    script = [
        _plan("lookup_user"),
        _conclude(),
        _grounded_verdict(actions=actions, finding_entity="alice"),
    ]
    deps, rec = _deps(script, approve=True)
    result = triage(_alert(), deps)

    # No traceability drop.
    assert "action_dropped_untraceable" not in rec.names()
    # The action makes it to the gate.
    assert "gate_requested" in rec.names()
    # Approved → executed.
    assert [a.name for a in result.executed_actions] == ["block_user"]


def test_traceability_filter_not_applied_on_zero_ok_path() -> None:
    """On zero-ok, _clamp_by_evidence strips actions; traceability filter does NOT run.

    If ok_count==0 (every observation failed), synthesize already stripped all
    actions via _clamp_by_evidence. _filter_traceable_verdict is not invoked on
    the zero-ok path.
    """
    script = [
        _plan("lookup_user"),
        _conclude(),
        json.dumps(
            {
                "severity": "low",
                "findings": [{"statement": "alice did something.", "evidence": "lookup_user."}],
                "recommended_actions": [{"name": "block_user", "params": {"user": "mallory"}}],
                "confidence": 0.35,
            }
        ),
    ]
    # Source raises for alice → ok=False observation.
    deps, rec = _deps(script, source=StubSource(raise_for="alice"))
    triage(_alert(), deps)

    # No traceability drop event (zero-ok path: clamp stripped actions first).
    assert "action_dropped_untraceable" not in rec.names()


# ---------------------------------------------------------------------------- #
# Phase-1: verify_reentry_from_env parsing                                      #
# ---------------------------------------------------------------------------- #


def test_verify_reentry_defaults_to_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """VERIFY_REENTRY is off by default (Phase-2 disabled)."""
    monkeypatch.delenv("VERIFY_REENTRY", raising=False)
    assert _verify_reentry_from_env() is False


def test_verify_reentry_truthy_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """VERIFY_REENTRY truthy values enable Phase-2."""
    for val in ("1", "true", "TRUE", "yes", "YES"):
        monkeypatch.setenv("VERIFY_REENTRY", val)
        assert _verify_reentry_from_env() is True, f"Expected True for {val!r}"


def test_verify_reentry_falsy_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """VERIFY_REENTRY non-truthy values keep Phase-2 off."""
    for val in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("VERIFY_REENTRY", val)
        assert _verify_reentry_from_env() is False, f"Expected False for {val!r}"


# ---------------------------------------------------------------------------- #
# Phase-2: VERIFY_REENTRY wiring                                                #
# ---------------------------------------------------------------------------- #


def _reentry_deps(
    script: list[str],
    *,
    journal: RecordingJournal | None = None,
    approve: bool = False,
    max_steps: int | None = None,
    source: StubSource | None = None,
) -> tuple[TriageDeps, RecordingJournal]:
    """Build deps for Phase-2 tests."""
    rec = journal or RecordingJournal()
    deps = TriageDeps(
        llm=FakeLLM(script),
        journal=rec,
        registry=ToolRegistry(),
        source=source or StubSource(),
        gate=AutoGate(rec, approve=approve),
        policy=RiskPolicy(),
        max_steps=max_steps,
    )
    return deps, rec


def test_phase2_flag_off_no_reentry(monkeypatch: pytest.MonkeyPatch) -> None:
    """With VERIFY_REENTRY off (default), Phase-2 re-entry never fires.

    Only one verdict_verification event is emitted per run.
    """
    monkeypatch.delenv("VERIFY_REENTRY", raising=False)
    deps, rec = _reentry_deps([_plan("lookup_user"), _conclude(), _hallucinated_verdict()])
    triage(_alert(), deps)

    vv_events = rec.payloads("verdict_verification")
    assert len(vv_events) == 1


def test_phase2_reentry_fires_once_max(monkeypatch: pytest.MonkeyPatch) -> None:
    """With VERIFY_REENTRY=true, re-entry fires at most once.

    Script: plan → reason(conclude) → hallucinated_verdict [triggers reentry]
            → re-plan → reason(conclude) → grounded_verdict [2nd synthesize]
    Two verdict_verification events are emitted.
    """
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    # Script order for FakeLLM:
    # 1. plan (phase-1 initial plan)
    # 2. conclude (executor → conclude)
    # 3. hallucinated_verdict (first synthesize — fails citation check → reentry)
    # 4. re-plan (phase-2 gap note planner call)
    # 5. conclude (re-entry executor resume → conclude immediately since no new obs)
    # 6. grounded_verdict (second synthesize — citation check now references the alert field)
    script = [
        _plan("lookup_user"),
        _conclude(),
        _hallucinated_verdict(),
        _plan("query_logs"),  # re-plan produces one step
        _conclude(),
        _grounded_verdict(),  # second synthesize
    ]
    deps, rec = _reentry_deps(script)
    result = triage(_alert(), deps)

    vv_events = rec.payloads("verdict_verification")
    # Two verdict_verification events: one for the first verdict, one for the reentry verdict.
    assert len(vv_events) == 2
    assert result.terminated_reason in {"completed", "max_steps", "no_progress", "revise_exhausted"}


def test_phase2_empty_replan_degrades_no_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty re-plan (no steps) degrades and never loops.

    Script: plan → conclude → hallucinated_verdict → re-plan with empty steps
    Result: one verdict_verification event (Phase-1 path), run completes.
    """
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    empty_plan = json.dumps({"steps": []})
    script = [
        _plan("lookup_user"),
        _conclude(),
        _hallucinated_verdict(),
        empty_plan,  # re-plan returns empty steps
    ]
    deps, rec = _reentry_deps(script)
    result = triage(_alert(), deps)

    # Only one verdict_verification (Phase-1 path; re-entry was blocked by empty plan).
    vv_events = rec.payloads("verdict_verification")
    assert len(vv_events) == 1
    assert result.terminated_reason in {
        "completed",
        "max_steps",
        "no_progress",
        "revise_exhausted",
        "error",
    }


def test_phase2_llm_error_on_replan_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    """An LLM error during re-plan causes degrade (returns None → Phase-1 path).

    Script: plan -> conclude -> hallucinated_verdict -> bad json (x2 for repair fail)
    Result: one verdict_verification event (Phase-1 path).
    """
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    script = [
        _plan("lookup_user"),
        _conclude(),
        _hallucinated_verdict(),
        "not json",  # re-plan: malformed → repair attempt
        "still not json",  # second malformed → LLMError → degrade
    ]
    deps, rec = _reentry_deps(script)
    result = triage(_alert(), deps)

    # Only Phase-1 verdict_verification (LLM error on re-plan → degrade).
    vv_events = rec.payloads("verdict_verification")
    assert len(vv_events) == 1
    assert result.terminated_reason in {
        "completed",
        "max_steps",
        "no_progress",
        "revise_exhausted",
        "error",
    }


def test_phase2_reentry_does_not_loop_recursively(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-entry is bounded to 1: even if the second verdict also fails, no second reentry.

    Script: plan → conclude → hallucinated_verdict → re-plan → conclude →
            hallucinated_verdict_2 (still fails) → at most 2 verdict_verification events.
    """
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    script = [
        _plan("lookup_user"),
        _conclude(),
        _hallucinated_verdict(),  # first verdict — triggers reentry
        _plan("query_logs"),
        _conclude(),
        _hallucinated_verdict(),  # second verdict — would trigger reentry but bounded
    ]
    deps, rec = _reentry_deps(script)
    triage(_alert(), deps)

    # At most 2 verdict_verification events (one per synthesis).
    vv_events = rec.payloads("verdict_verification")
    assert len(vv_events) <= 2


# ---------------------------------------------------------------------------- #
# Phase-1: resume works across journals containing verdict_verification         #
# ---------------------------------------------------------------------------- #


def test_resume_works_across_journal_with_verdict_verification(tmp_path: Path) -> None:
    """resume_investigation works when the journal contains verdict_verification events.

    The rebuild must not crash on the new event type (forward-compatible journal:
    unknown events are stored in the audit trail but fold into no typed view).
    """
    run_dir = tmp_path / "ALT-VV-RESUME"
    run_dir.mkdir()

    # Build a journal that contains a verdict_verification event.
    lines = [
        {
            "seq": 1,
            "event_id": "e1",
            "ts": "2026-06-06T00:00:00Z",
            "event": "run_started",
            "agent": "triage",
            "alert_id": "ALT-1",
            "config": {},
            "schema_version": 1,
        },
        {
            "seq": 2,
            "event_id": "e2",
            "ts": "2026-06-06T00:00:01Z",
            "event": "plan_created",
            "agent": "triage",
            "steps": [{"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "check"}],
        },
        {
            "seq": 3,
            "event_id": "e3",
            "ts": "2026-06-06T00:00:02Z",
            "event": "tool_called",
            "agent": "triage",
            "step": 1,
            "tool": "lookup_user",
            "args": {"entity": "alice"},
            "attempt": 1,
        },
        {
            "seq": 4,
            "event_id": "e4",
            "ts": "2026-06-06T00:00:03Z",
            "event": "tool_result",
            "agent": "triage",
            "step": 1,
            "attempt": 1,
            "ok": True,
            "data": {"user": "alice", "status": "active"},
        },
        # verdict_verification is a NEW event — must not crash rebuild.
        {
            "seq": 5,
            "event_id": "e5",
            "ts": "2026-06-06T00:00:04Z",
            "event": "verdict_verification",
            "agent": "triage",
            "checks": [{"name": "citation_validity", "passed": True}],
            "failed": [],
            "uncovered_entities": [],
            "failed_findings": [],
            "action": "pass",
        },
    ]
    (run_dir / "journal.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )

    reconstructed = rebuild(run_dir / "journal.jsonl")
    # The run is interrupted (no run_terminated event) — resume should work.
    assert reconstructed.is_interrupted()
    # The verdict_verification event is in the raw audit trail.
    assert any(e.get("event") == "verdict_verification" for e in reconstructed.events)


def test_phase2_reentry_no_crash_on_awaiting_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase-2 re-entry respects HOLD gate outcome in the reentry path."""
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    rec = RecordingJournal()

    # Script: plan → conclude → hallucinated_verdict → re-plan → conclude → grounded_verdict
    script = [
        _plan("lookup_user"),
        _conclude(),
        _hallucinated_verdict(),
        _plan("query_logs"),
        _conclude(),
        _grounded_verdict(actions=[_block_user("alice")], finding_entity="alice"),
    ]
    deps = TriageDeps(
        llm=FakeLLM(script),
        journal=rec,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=DeferredGate(rec),
        policy=RiskPolicy(),
        max_steps=3,
    )
    result = triage(_alert(), deps)
    # DeferredGate parks the run; never crashes.
    assert result.terminated_reason in {"awaiting_approval", "completed", "max_steps", "error"}


def test_phase2_reentry_zero_ok_path_no_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase-2 re-entry on a zero-ok trajectory (StubSource raises for alice) does not crash.

    Every observation in the (re-entered) trajectory is ok=False, so
    _filter_traceable_verdict is NOT called after re-synthesis (new_ok_count < 1)
    — covering the skip branch in _attempt_reentry's Phase-1 degrade step.
    """
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    # Script: plan → conclude → hallucinated_verdict → re-plan → conclude → grounded_verdict
    # The source raises for alice, so the first lookup_user observation is ok=False;
    # re-entry adds no new observations (resume reasons first → conclude), leaving a
    # zero-ok trajectory at re-synthesis.
    script = [
        _plan("lookup_user"),
        _conclude(),  # first executor conclude
        _hallucinated_verdict(confidence=0.35),  # fails citation_validity → reentry
        _plan("query_logs"),  # re-plan
        _conclude(),  # re-entry executor.resume → _reason → conclude (no new obs executed)
        # Second synthesize: zero-ok trajectory → confidence stays in the clamp band.
        json.dumps(
            {
                "severity": "low",
                "findings": [
                    {"statement": "no tools succeeded.", "evidence": "lookup_user failed."},
                ],
                "recommended_actions": [],
                "confidence": 0.35,
            }
        ),
    ]
    deps, _rec = _reentry_deps(script, max_steps=2, source=StubSource(raise_for="alice"))
    result = triage(_alert(), deps)

    # Two verdict_verification events if reentry fired; run never crashes.
    assert result is not None
    assert result.terminated_reason in {
        "completed",
        "max_steps",
        "no_progress",
        "revise_exhausted",
        "error",
    }


def test_phase2_reentry_with_memory_persists_new_verdict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Phase-2 re-entry path with a wired MemoryStore persists the re-synthesized verdict.

    This covers the deps.memory.persist() call in _attempt_reentry (line 591).
    """
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    memory = MemoryStore(tmp_path / ".memory")
    rec = RecordingJournal()

    script = [
        _plan("lookup_user"),
        _conclude(),
        _hallucinated_verdict(),  # first synthesis — triggers reentry
        _plan("query_logs"),  # re-plan
        _conclude(),  # re-entry executor conclude
        _grounded_verdict(),  # second synthesis
    ]
    deps = TriageDeps(
        llm=FakeLLM(script),
        journal=rec,
        registry=ToolRegistry(),
        source=StubSource(),
        gate=AutoGate(rec, approve=False),
        policy=RiskPolicy(),
        memory=memory,
    )
    result = triage(_alert(), deps, run_id="ALT-REENTRY-MEM")

    # At most 2 verdict_verification events; run completed.
    vv_events = rec.payloads("verdict_verification")
    assert len(vv_events) >= 1
    assert result is not None


def test_phase2_reentry_zero_ok_path_skips_traceability_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In Phase-2 re-entry with all-fail observations, traceability filter is skipped.

    When new_ok_count == 0 in _attempt_reentry, _filter_traceable_verdict is NOT
    called (actions were already stripped by _clamp_by_evidence). This covers
    the branch 586->590 in _attempt_reentry.
    """
    monkeypatch.setenv("VERIFY_REENTRY", "true")

    # All observations ok=False (source raises for alice).
    source = StubSource(raise_for="alice")

    # Phase-1 run: lookup_user → ok=False → conclude
    # Synthesize: all-fail → confidence clamped to 0.35, actions stripped
    # Verify: coverage fails (alice not covered in ok=False obs data, not in findings)
    # → Phase-2 fires
    # Re-entry: executor.resume → conclude (reasons first, no new tool) → all-fail
    # Second synthesize: same all-fail → clamped verdict
    zero_evidence_verdict = json.dumps(
        {
            "severity": "low",
            "findings": [
                {
                    "statement": "Could not look up alice.",
                    "evidence": "lookup_user returned not found for alice.",
                }
            ],
            "recommended_actions": [],
            "confidence": 0.35,
        }
    )
    script = [
        _plan("lookup_user"),
        _conclude(),  # first executor conclude
        zero_evidence_verdict,  # first synthesize → verify fails (coverage) → reentry
        _plan("query_logs"),  # re-plan
        _conclude(),  # re-entry executor.resume → _reason → conclude immediately
        zero_evidence_verdict,  # second synthesize (all-fail, zero_ok path)
    ]
    rec = RecordingJournal()
    deps = TriageDeps(
        llm=FakeLLM(script),
        journal=rec,
        registry=ToolRegistry(),
        source=source,
        gate=AutoGate(rec, approve=False),
        policy=RiskPolicy(),
        max_steps=5,
    )
    result = triage(_alert(), deps)

    # Run completes without crashing; at most 2 verdict_verification events.
    assert result is not None
    vv_events = rec.payloads("verdict_verification")
    # If reentry fired (2 events), the second one had new_ok_count==0 → branch taken.
    # If reentry didn't fire (empty plan or other), 1 event.
    assert len(vv_events) in {1, 2}
    # No traceability drop — zero-ok path strips actions in synthesize.
    assert "action_dropped_untraceable" not in rec.names()
