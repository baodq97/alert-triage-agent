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

from triage.core import SCHEMA_VERSION, TriageDeps, summarize, triage
from triage.errors import JournalError, ToolError
from triage.gate import AutoGate, DeferredGate, RiskPolicy
from triage.journal import NoopJournal
from triage.llm import Completion, FakeLLM, OpenAICompatibleLLM
from triage.memory import MemoryStore
from triage.models import Alert
from triage.tools import FixtureDataSource, ToolRegistry

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from triage.llm import Message
    from triage.models import InvestigationPlan
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


def _verdict(*, actions: list[dict[str, Any]] | None = None, severity: str = "medium") -> str:
    return json.dumps(
        {
            "severity": severity,
            "findings": [{"statement": "anomaly observed", "evidence": "lookup_user"}],
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
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
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
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
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
    # 'mallory' is not an alert entity value: the action is rejected before the gate.
    actions = [_block_user("mallory")]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
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
    actions = [_block_user("mallory")]
    deps, rec = _deps(
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
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
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
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
        [_plan("lookup_user"), _conclude(), _verdict(actions=actions)],
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


class _CapturingLLM(FakeLLM):
    """A FakeLLM that records the message list of EVERY ``complete`` call.

    ``FakeLLM.last_messages`` is overwritten per call, so the first (plan) call's
    rendered prompt is lost by the time the verdict call lands. This subclass keeps
    the full history so a test can inspect the plan prompt specifically — the rendered
    ``<recalled_memory>`` block is asserted on the prompt the planner actually sent.
    """

    def __init__(self, script: list[str]) -> None:
        super().__init__(script)
        self.all_messages: list[list[Message]] = []

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[InvestigationPlan],
    ) -> Completion[InvestigationPlan]:
        completion = super().complete(messages, response_model)
        self.all_messages.append(list(messages))
        return completion


def test_recall_flows_into_the_planner_prompt(tmp_path: Path) -> None:
    # A prior Run persists an atom for entity "alice"; the next Run over an alert that
    # names "alice" recalls it, and the recalled content lands inside the labeled
    # <recalled_memory> block of the plan prompt (untrusted context, ADR-0005).
    store = MemoryStore(base_dir=tmp_path)
    seed_llm = _CapturingLLM([_plan("lookup_user"), _conclude(), _verdict()])
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

    capture = _CapturingLLM([_plan("lookup_user"), _conclude(), _verdict()])
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

    plan_prompt = capture.all_messages[0][0]["content"]
    assert "<recalled_memory>" in plan_prompt
    assert "</recalled_memory>" in plan_prompt
    # The seeded finding statement is rendered inside the untrusted block.
    assert "anomaly observed" in plan_prompt
    assert "seed-run" in plan_prompt  # the source run-id travels with the recall item


def test_persist_writes_atoms_after_a_run(tmp_path: Path) -> None:
    # A Run with a Memory Store persists one L1 atom per (matchable entity, finding).
    # The verdict ships a single finding; the alert names entities user=alice + ip,
    # so recall over the same alert returns the atom afterward.
    store = MemoryStore(base_dir=tmp_path)
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]),
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
    assert any("anomaly observed" in item["content"] for item in recalled)
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
    capture = _CapturingLLM([_plan("lookup_user"), _conclude(), _verdict()])
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

    plan_prompt = capture.all_messages[0][0]["content"]
    assert "<recalled_memory>" not in plan_prompt
    # No store was constructed, so nothing landed under tmp_path.
    assert list(tmp_path.iterdir()) == []


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
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict(actions=actions)]),
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
        payload: Mapping[str, Any],  # noqa: ARG002 — protocol signature.
        *,
        agent: str = "triage",  # noqa: ARG002 — protocol signature.
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
        payload: Mapping[str, Any],  # noqa: ARG002 — protocol signature.
        *,
        agent: str = "triage",  # noqa: ARG002 — protocol signature.
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
