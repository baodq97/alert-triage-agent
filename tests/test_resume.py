"""Tests for the Resume flow (US-0002 AC3-AC6) — rebuild + continue / approve / deny.

These exercise the wave-2 resume seams end-to-end against a *real* ``JsonlJournal``
under ``tmp_path`` (never the repo's ``runs/``), driving the core entrypoints
``resume_investigation`` / ``resume_approve`` / ``resume_deny`` over a journal
reconstructed by ``journal.rebuild``:

* **kill-after-step-2 (AC3):** a journal that ENDS at ``tool_result`` of step 2 with
  NO ``run_terminated`` is the interrupted state — asserted via
  ``rebuild(...).is_interrupted()`` before any resume, so the fixture really
  simulates a process kill rather than a graceful error. Resume completes the Run
  with a ``FakeLLM``; the recorded steps are reused, never re-executed (asserted via
  the journal: no duplicate ``step``/``attempt`` pairs).
* **awaiting_approval round-trip (AC4):** a Run parked by the ``DeferredGate`` is
  resumed with ``--approve`` (executes the batch exactly once) and ``--deny``
  (records the denial, the Verdict still ships).
* **idempotency (AC6):** a journal that already records ``action_executed`` for the
  approved Action reuses the recorded result on the next ``--approve`` — never
  double-executing (the kill-between-execute-and-record case).
* **seq continuity / non-pending guard:** a reopened journal continues ``seq``; an
  ``--approve|--deny`` on a non-pending Run raises with no mutation.

The reasoner verb is never journaled, so a resumed investigation re-fires the reason
call with fresh LLM reasoning — the recorded Tool Steps are what is reused.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from triage.core import (
    TriageDeps,
    resume_approve,
    resume_deny,
    resume_investigation,
    triage,
)
from triage.errors import GateError
from triage.gate import AutoGate, DeferredGate, RiskPolicy
from triage.journal import JsonlJournal, rebuild
from triage.llm import FakeLLM
from triage.models import Alert
from triage.tools import ToolRegistry

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


# --- doubles / builders ------------------------------------------------------


class _BenignSource:
    """A DataSource returning benign, deterministic data for any lookup."""

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        return {"tool": tool, "entity": args.get("entity"), "status": "benign"}


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-RESUME-1",
        "timestamp": "2026-06-05T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "data_exfiltration",
        "description": "Large outbound transfer from alice's host.",
        "entities": {"user": "alice"},
        "context": {},
    }
    return Alert.model_validate({**base, **overrides})


def _plan(*tools: str) -> str:
    steps = [{"tool": t, "args": {"entity": "alice"}, "rationale": "check it"} for t in tools]
    return json.dumps({"steps": steps})


def _conclude() -> str:
    return json.dumps({"decision": "conclude", "rationale": "enough evidence"})


def _continue() -> str:
    return json.dumps({"decision": "continue", "rationale": "keep going"})


def _verdict(
    *, actions: list[dict[str, Any]] | None = None, finding_entity: str | None = None
) -> str:
    statement = f"anomaly detected for user {finding_entity}" if finding_entity else "anomaly"
    evidence = f"lookup_user confirmed {finding_entity}" if finding_entity else "lookup_user"
    return json.dumps(
        {
            "severity": "high",
            "findings": [{"statement": statement, "evidence": evidence}],
            "recommended_actions": actions or [],
            "confidence": 0.8,
        },
    )


def _block_alice() -> dict[str, Any]:
    return {"name": "block_user", "params": {"user": "alice"}, "description": "block"}


def _read_events(run_dir: Path) -> list[dict[str, Any]]:
    text = (run_dir / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _tool_pairs(events: list[dict[str, Any]]) -> list[tuple[int, int]]:
    """The (step, attempt) keys of every tool_called event — for duplicate checks."""
    return [(e["step"], e["attempt"]) for e in events if e["event"] == "tool_called"]


def _write_interrupted_two_steps(run_dir: Path) -> None:
    """Emit a journal that ENDS at tool_result(step 2) with NO run_terminated.

    Simulates a process killed after step 2's tool result was written: a two-step
    plan, both steps executed and observed, but no reasoner decision recorded after
    step 2 and no termination — the single interrupted re-entry point.
    """
    journal = JsonlJournal(run_dir)
    journal.emit(
        "run_started",
        {"alert_id": "ALT-RESUME-1", "config": {"max_steps": None}, "schema_version": 1},
    )
    journal.emit("llm_call", {"purpose": "plan", "model": "fake", "prompt_hash": "h", "tokens": 0})
    journal.emit(
        "plan_created",
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "a"},
                {"tool": "query_logs", "args": {"entity": "alice"}, "rationale": "b"},
            ]
        },
    )
    for step, tool in ((1, "lookup_user"), (2, "query_logs")):
        journal.emit(
            "tool_called", {"step": step, "tool": tool, "args": {"entity": "alice"}, "attempt": 1}
        )
        # Step 1 records a reason between steps; step 2 is the torn re-entry point.
        if step == 1:
            journal.emit(
                "tool_result",
                {"step": step, "attempt": 1, "ok": True, "data": {"status": "benign"}},
            )
            journal.emit(
                "llm_call",
                {"purpose": "reason", "model": "fake", "prompt_hash": "h", "tokens": 0},
            )
        else:
            journal.emit(
                "tool_result",
                {"step": step, "attempt": 1, "ok": True, "data": {"status": "benign"}},
            )
    journal.close()


def _deps(journal: JsonlJournal, llm: FakeLLM, *, gate_approve: bool | None = None) -> TriageDeps:
    """Build deps for a resumed Run; ``gate_approve`` None -> DeferredGate."""
    gate = (
        AutoGate(journal, approve=gate_approve)
        if gate_approve is not None
        else DeferredGate(journal)
    )
    return TriageDeps(
        llm=llm,
        journal=journal,
        registry=ToolRegistry(),
        source=_BenignSource(),
        gate=gate,
        policy=RiskPolicy(),
    )


# --- AC3: kill-after-step-2 -> resume completes without re-executing ---------


def test_resume_interrupted_run_completes_without_re_executing_steps(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-ac3"
    _write_interrupted_two_steps(run_dir)

    # The fixture really simulates a KILL: interrupted, not a graceful error.
    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted() is True
    assert len(reconstructed.observations) == 2
    pairs_before = _tool_pairs(reconstructed.events)
    assert pairs_before == [(1, 1), (2, 1)]
    seq_before = reconstructed.last_seq

    # Reopen and resume: the executor re-fires the reason call (concludes), then the
    # run tail synthesizes a verdict and terminates.
    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([_conclude(), _verdict()]), gate_approve=False)
    result = resume_investigation(_alert(), deps, reconstructed, run_id="run-ac3")
    journal.close()

    assert result.terminated_reason == "completed"
    assert result.verdict.findings
    events = _read_events(run_dir)
    # No recorded Tool Step re-executed: the (step, attempt) pairs are unchanged.
    assert _tool_pairs(events) == [(1, 1), (2, 1)]
    # seq continued strictly monotonic past the interrupted tail (reopen continuity).
    assert events[-1]["seq"] > seq_before
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    assert events[-1]["event"] == "run_terminated"


def test_resume_interrupted_run_continues_to_step_three(tmp_path: Path) -> None:
    # The reasoner re-fire decides `continue`, so the (unexecuted) plan walks on; a
    # genuinely new step runs while the two recorded ones are reused.
    run_dir = tmp_path / "run-ac3b"
    journal0 = JsonlJournal(run_dir)
    journal0.emit("run_started", {"alert_id": "ALT-RESUME-1", "config": {}, "schema_version": 1})
    journal0.emit(
        "plan_created",
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "a"},
                {"tool": "query_logs", "args": {"entity": "alice"}, "rationale": "b"},
                {"tool": "check_reputation", "args": {"entity": "alice"}, "rationale": "c"},
            ]
        },
    )
    for step, tool in ((1, "lookup_user"), (2, "query_logs")):
        journal0.emit(
            "tool_called", {"step": step, "tool": tool, "args": {"entity": "alice"}, "attempt": 1}
        )
        journal0.emit("tool_result", {"step": step, "attempt": 1, "ok": True, "data": {"ok": 1}})
    journal0.close()

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted() is True

    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([_continue(), _conclude(), _verdict()]), gate_approve=False)
    result = resume_investigation(_alert(), deps, reconstructed, run_id="run-ac3b")
    journal.close()

    assert result.terminated_reason == "completed"
    events = _read_events(run_dir)
    # Step 3 (check_reputation) is the only newly executed tool.
    new_calls = [e for e in events if e["event"] == "tool_called" and e["step"] == 3]
    assert len(new_calls) == 1
    assert new_calls[0]["tool"] == "check_reputation"


def test_resume_after_a_transient_retry_does_not_skip_the_next_step(tmp_path: Path) -> None:
    # A transient tool retry records TWO tool_result rows for one executor Step (cf.
    # AC2). The resumed run must collapse them to one Step and NOT inflate the next
    # step index — otherwise the remaining Plan Step is silently dropped. Here step 1
    # retried (attempt 1 failed, attempt 2 ok); the kill happened before step 2.
    run_dir = tmp_path / "run-retry-resume"
    journal0 = JsonlJournal(run_dir)
    journal0.emit("run_started", {"alert_id": "ALT-RESUME-1", "config": {}, "schema_version": 1})
    journal0.emit(
        "plan_created",
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "a"},
                {"tool": "query_logs", "args": {"entity": "alice"}, "rationale": "b"},
            ],
        },
    )
    # Step 1 with a transient retry: two tool_result rows, same step, attempts 1 & 2.
    journal0.emit(
        "tool_called",
        {"step": 1, "tool": "lookup_user", "args": {"entity": "alice"}, "attempt": 1},
    )
    journal0.emit("tool_result", {"step": 1, "attempt": 1, "ok": False, "error": "transient"})
    journal0.emit(
        "tool_called",
        {"step": 1, "tool": "lookup_user", "args": {"entity": "alice"}, "attempt": 2},
    )
    journal0.emit("tool_result", {"step": 1, "attempt": 2, "ok": True, "data": {"status": "ok"}})
    journal0.close()

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted() is True
    # The rebuild has TWO observation rows for the one retried Step.
    assert len(reconstructed.observations) == 2
    assert {o.step for o in reconstructed.observations} == {1}

    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([_continue(), _conclude(), _verdict()]), gate_approve=False)
    result = resume_investigation(_alert(), deps, reconstructed, run_id="run-retry-resume")
    journal.close()

    assert result.terminated_reason == "completed"
    events = _read_events(run_dir)
    calls = [e for e in events if e["event"] == "tool_called"]
    # Step 2 (query_logs) was executed on resume — NOT skipped by an inflated index;
    # and it lands at executor step 2 (the collapsed Step count is 1, not 2).
    new_query_calls = [e for e in calls if e["tool"] == "query_logs"]
    assert len(new_query_calls) == 1
    assert new_query_calls[0]["step"] == 2
    # Step 1 (lookup_user) was NOT re-executed: only its recorded attempts remain.
    lookup_calls = [e for e in calls if e["tool"] == "lookup_user"]
    assert [e["attempt"] for e in lookup_calls] == [1, 2]  # the two recorded attempts, none new


# --- AC4: awaiting_approval round-trip ---------------------------------------


def _park_a_run(run_dir: Path) -> None:
    """Run a Run with a high-risk action through the DeferredGate so it parks."""
    journal = JsonlJournal(run_dir)
    deps = _deps(
        journal,
        FakeLLM(
            [
                _plan("lookup_user"),
                _conclude(),
                _verdict(actions=[_block_alice()], finding_entity="alice"),
            ]
        ),
    )
    result = triage(_alert(), deps, run_id=run_dir.name)
    journal.close()
    assert result.terminated_reason == "awaiting_approval"


def test_resume_approve_executes_the_pending_action_exactly_once(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-approve"
    _park_a_run(run_dir)

    parked = rebuild(run_dir / "journal.jsonl")
    assert parked.is_awaiting_approval() is True
    assert parked.gate_decision is None
    assert parked.gate_requested is not None

    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([]))  # no LLM call on the decision path
    result = resume_approve(deps, parked, run_id="run-approve", by="alice@soc")
    journal.close()

    assert result.terminated_reason == "completed"
    assert [d.decision for d in result.gate_decisions] == ["approved"]
    assert [a.name for a in result.executed_actions] == ["block_user"]
    events = _read_events(run_dir)
    names = [e["event"] for e in events]
    # gate_decision then action_executed (exactly once) then run_terminated.
    assert names.count("gate_decision") == 1
    assert names.count("action_executed") == 1
    assert names[-1] == "run_terminated"
    decision = next(e for e in events if e["event"] == "gate_decision")
    assert decision["decision"] == "approved"
    assert decision["by"] == "alice@soc"


def test_resume_deny_records_decision_and_ships_verdict(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-deny"
    _park_a_run(run_dir)
    parked = rebuild(run_dir / "journal.jsonl")

    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([]))
    result = resume_deny(deps, parked, run_id="run-deny", by="bob@soc")
    journal.close()

    assert result.terminated_reason == "completed"
    assert [d.decision for d in result.gate_decisions] == ["denied"]
    assert result.executed_actions == []
    assert result.verdict.findings  # the verdict still ships
    events = _read_events(run_dir)
    names = [e["event"] for e in events]
    assert "action_executed" not in names
    assert names.count("gate_decision") == 1
    assert names[-1] == "run_terminated"


# --- AC6: idempotency — never double-execute --------------------------------


def test_resume_approve_reuses_a_recorded_execution_never_double_executing(tmp_path: Path) -> None:
    # The kill-between-execute-and-record case: a journal where the action was
    # parked, approved, AND already executed+recorded. A second --approve must reuse
    # the recorded result — no second action_executed.
    run_dir = tmp_path / "run-idem"
    _park_a_run(run_dir)
    # Simulate a prior resume that approved and executed before being killed.
    journal0 = JsonlJournal(run_dir)
    journal0.emit("gate_decision", {"decision": "approved", "by": "alice@soc"})
    journal0.emit(
        "action_executed",
        {
            "action": _block_alice(),
            "result": {"action": "block_user", "target": "alice", "status": "blocked"},
        },
    )
    journal0.close()

    parked = rebuild(run_dir / "journal.jsonl")
    # The recorded action_executed is present -> idempotency ledger has it.
    assert [a.kind for a in parked.executed_actions()] == ["action_executed"]

    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([]))
    result = resume_approve(deps, parked, run_id="run-idem", by="alice@soc")
    journal.close()

    # The action is still reported executed (reused), but NOT re-applied.
    assert [a.name for a in result.executed_actions] == ["block_user"]
    events = _read_events(run_dir)
    # Exactly ONE action_executed across the whole journal (the recorded one).
    assert [e["event"] for e in events].count("action_executed") == 1


def test_resume_approve_skips_an_approved_action_with_no_executor(tmp_path: Path) -> None:
    # An untargeted high-risk action (notify_soc defaults to high_risk and is
    # untargeted, so it reaches the gate) has no registered executor: on approve it
    # is recorded action_skipped — never action_executed, never a crash.
    run_dir = tmp_path / "run-skip"
    notify = {"name": "notify_soc", "params": {"channel": "soc"}, "description": "page"}
    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([_plan("lookup_user"), _conclude(), _verdict(actions=[notify])]))
    result0 = triage(_alert(), deps, run_id="run-skip")
    journal.close()
    assert result0.terminated_reason == "awaiting_approval"

    parked = rebuild(run_dir / "journal.jsonl")
    journal2 = JsonlJournal(run_dir)
    resume_deps = _deps(journal2, FakeLLM([]))
    result = resume_approve(resume_deps, parked, run_id="run-skip", by="alice@soc")
    journal2.close()

    assert result.terminated_reason == "completed"
    assert result.executed_actions == []  # nothing executable
    events = _read_events(run_dir)
    names = [e["event"] for e in events]
    assert "action_skipped" in names
    assert "action_executed" not in names


# --- non-pending guard: --approve|--deny on the wrong state mutates nothing --


def test_resume_approve_on_a_completed_run_raises_and_mutates_nothing(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-done"
    # A fully completed Run (gate auto-approved, terminated completed).
    journal = JsonlJournal(run_dir)
    deps = _deps(
        journal,
        FakeLLM(
            [
                _plan("lookup_user"),
                _conclude(),
                _verdict(actions=[_block_alice()], finding_entity="alice"),
            ]
        ),
        gate_approve=True,
    )
    triage(_alert(), deps, run_id="run-done")
    journal.close()
    before = (run_dir / "journal.jsonl").read_text(encoding="utf-8")

    done = rebuild(run_dir / "journal.jsonl")
    assert done.is_awaiting_approval() is False

    journal2 = JsonlJournal(run_dir)
    resume_deps = _deps(journal2, FakeLLM([]))
    with pytest.raises(GateError):
        resume_approve(resume_deps, done, run_id="run-done", by="x")
    journal2.close()

    # No mutation: nothing appended (the reopen wrote nothing on the error path).
    assert (run_dir / "journal.jsonl").read_text(encoding="utf-8") == before


def test_resume_investigation_on_a_terminated_run_raises(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-term"
    journal = JsonlJournal(run_dir)
    deps = _deps(
        journal, FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]), gate_approve=False
    )
    triage(_alert(), deps, run_id="run-term")
    journal.close()

    terminated = rebuild(run_dir / "journal.jsonl")
    assert terminated.is_interrupted() is False

    journal2 = JsonlJournal(run_dir)
    resume_deps = _deps(journal2, FakeLLM([_conclude(), _verdict()]), gate_approve=False)
    with pytest.raises(GateError):
        resume_investigation(_alert(), resume_deps, terminated, run_id="run-term")
    journal2.close()


# --------------------------------------------------------------------------- #
# B2 (M2) — resume-after-revision picks the revised step, not original plan   #
# --------------------------------------------------------------------------- #


def _revise(next_tool: str, next_entity: str = "alice") -> str:
    step = {"tool": next_tool, "args": {"entity": next_entity}, "rationale": "revised"}
    return json.dumps({"decision": "revise_plan", "rationale": "revising", "next_step": step})


def test_resume_after_revision_runs_revised_step_not_original_next(tmp_path: Path) -> None:
    """Kill-after-revision -> resume must execute the REVISED step, not the original plan's next.

    Setup: two-step original plan (lookup_user, query_logs).
    - Step 1 runs (lookup_user); the reasoner revises to check_reputation.
    - The journal records plan_revised with [check_reputation] and then is killed
      before step 2 (the revised check_reputation) executes.
    - Resume must continue from check_reputation (the last revision), NOT from
      query_logs (the original plan's second step).
    """
    run_dir = tmp_path / "run-revision"
    journal0 = JsonlJournal(run_dir)
    journal0.emit("run_started", {"alert_id": "ALT-RESUME-1", "config": {}, "schema_version": 1})
    journal0.emit(
        "plan_created",
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "original 1"},
                {"tool": "query_logs", "args": {"entity": "alice"}, "rationale": "original 2"},
            ]
        },
    )
    # Step 1: lookup_user ran and was observed.
    journal0.emit(
        "tool_called",
        {"step": 1, "tool": "lookup_user", "args": {"entity": "alice"}, "attempt": 1},
    )
    journal0.emit("tool_result", {"step": 1, "attempt": 1, "ok": True, "data": {"status": "ok"}})
    # The reasoner decided to revise: check_reputation replaces query_logs.
    journal0.emit(
        "plan_revised",
        {"steps": [{"tool": "check_reputation", "args": {"entity": "alice"}, "rationale": "rev"}]},
    )
    # Killed here — check_reputation has NOT been executed yet.
    journal0.close()

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted() is True
    assert len(reconstructed.plan_revisions) == 1
    assert reconstructed.plan_revisions[0][0]["tool"] == "check_reputation"

    # Resume: the first reason call should continue (the revised step still pending),
    # then check_reputation executes, then conclude, then verdict.
    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([_continue(), _conclude(), _verdict()]), gate_approve=False)
    result = resume_investigation(_alert(), deps, reconstructed, run_id="run-revision")
    journal.close()

    assert result.terminated_reason == "completed"
    events = _read_events(run_dir)
    new_tool_calls = [e for e in events if e["event"] == "tool_called" and e.get("step", 0) >= 2]
    # check_reputation ran as the next step (not query_logs).
    assert any(e["tool"] == "check_reputation" for e in new_tool_calls), (
        f"expected check_reputation in new tool calls, got: {new_tool_calls}"
    )
    assert not any(e["tool"] == "query_logs" for e in new_tool_calls), (
        f"query_logs (original plan step 2) must NOT run on resume; got: {new_tool_calls}"
    )


# --------------------------------------------------------------------------- #
# B3 — revision at step ≥2: resume must execute the revised step, not drop it #
# --------------------------------------------------------------------------- #


def test_resume_revision_at_step_2_executes_revised_step_not_original(tmp_path: Path) -> None:
    """Revision fires at step 2 (after two tool calls), killed before revised step runs.

    The original plan is (lookup_user, query_logs, check_reputation).  Two steps run
    (lookup_user at step 1, query_logs at step 2), then the reasoner revises to
    get_asset_info at step 3.  The kill happens before get_asset_info executes.

    With the old arithmetic: steps_executed=2, n_revisions=1 -> next_step_index=1 ->
    pending = [get_asset_info][1:] = [] -> revised step silently dropped.

    After the fix: steps_after_last_revision=0 -> next_step_index=0 -> pending =
    [get_asset_info] -> get_asset_info runs; check_reputation (original step 3) does
    not.
    """
    run_dir = tmp_path / "run-late-revision"
    journal0 = JsonlJournal(run_dir)
    journal0.emit("run_started", {"alert_id": "ALT-RESUME-1", "config": {}, "schema_version": 1})
    journal0.emit(
        "plan_created",
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "step-1"},
                {"tool": "query_logs", "args": {"entity": "alice"}, "rationale": "step-2"},
                {"tool": "check_reputation", "args": {"entity": "alice"}, "rationale": "step-3"},
            ]
        },
    )
    # Step 1: lookup_user executed.
    journal0.emit(
        "tool_called",
        {"step": 1, "tool": "lookup_user", "args": {"entity": "alice"}, "attempt": 1},
    )
    journal0.emit("tool_result", {"step": 1, "attempt": 1, "ok": True, "data": {"s": "ok"}})
    # Step 2: query_logs executed; the reasoner then revises to get_asset_info.
    journal0.emit(
        "tool_called",
        {"step": 2, "tool": "query_logs", "args": {"entity": "alice"}, "attempt": 1},
    )
    journal0.emit("tool_result", {"step": 2, "attempt": 1, "ok": True, "data": {"s": "ok"}})
    journal0.emit(
        "plan_revised",
        {"steps": [{"tool": "get_asset_info", "args": {"entity": "alice"}, "rationale": "rev"}]},
    )
    # Killed here — get_asset_info has NOT executed yet.
    journal0.close()

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted() is True
    assert len(reconstructed.plan_revisions) == 1
    assert reconstructed.plan_revisions[0][0]["tool"] == "get_asset_info"
    # steps_after_last_revision must be 0: no tool_result followed the revision.
    assert reconstructed.steps_after_last_revision == 0

    # Resume: reasoner continues (revised step still pending), get_asset_info runs,
    # then conclude, then verdict.
    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([_continue(), _conclude(), _verdict()]), gate_approve=False)
    result = resume_investigation(_alert(), deps, reconstructed, run_id="run-late-revision")
    journal.close()

    assert result.terminated_reason == "completed"
    all_events = _read_events(run_dir)
    new_tool_calls = [
        e for e in all_events if e["event"] == "tool_called" and e.get("step", 0) >= 3
    ]
    # get_asset_info (the revised step) must have run.
    assert any(e["tool"] == "get_asset_info" for e in new_tool_calls), (
        f"expected get_asset_info in new tool calls, got: {new_tool_calls}"
    )
    # check_reputation (the original plan's step 3) must NOT run.
    assert not any(e["tool"] == "check_reputation" for e in new_tool_calls), (
        f"check_reputation (original plan step 3) must NOT run on resume; got: {new_tool_calls}"
    )


# --------------------------------------------------------------------------- #
# B4 — two plan_revised events: resume continues from the LAST revision       #
# --------------------------------------------------------------------------- #


def test_resume_multi_revision_continues_from_last_revision(tmp_path: Path) -> None:
    """Two revisions; killed after the first revised step ran but before the second.

    Original plan: (lookup_user, query_logs).
    - Step 1: lookup_user runs; reasoner revises to check_reputation.
    - Step 2: check_reputation runs (the first revised step); reasoner revises again
      to get_asset_info.
    - Killed before get_asset_info executes.

    steps_after_last_revision must be 0 (no tool_result after the second plan_revised).
    Resume must continue from get_asset_info only — check_reputation and query_logs
    must not re-run.
    """
    run_dir = tmp_path / "run-multi-revision"
    journal0 = JsonlJournal(run_dir)
    journal0.emit("run_started", {"alert_id": "ALT-RESUME-1", "config": {}, "schema_version": 1})
    journal0.emit(
        "plan_created",
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "alice"}, "rationale": "step-1"},
                {"tool": "query_logs", "args": {"entity": "alice"}, "rationale": "step-2"},
            ]
        },
    )
    # Step 1: lookup_user runs; first revision fires.
    journal0.emit(
        "tool_called",
        {"step": 1, "tool": "lookup_user", "args": {"entity": "alice"}, "attempt": 1},
    )
    journal0.emit("tool_result", {"step": 1, "attempt": 1, "ok": True, "data": {"s": "ok"}})
    journal0.emit(
        "plan_revised",
        {
            "steps": [
                {"tool": "check_reputation", "args": {"entity": "alice"}, "rationale": "rev-1"}
            ]
        },
    )
    # Step 2: check_reputation (the first revised step) runs; second revision fires.
    journal0.emit(
        "tool_called",
        {"step": 2, "tool": "check_reputation", "args": {"entity": "alice"}, "attempt": 1},
    )
    journal0.emit("tool_result", {"step": 2, "attempt": 1, "ok": True, "data": {"s": "ok"}})
    journal0.emit(
        "plan_revised",
        {"steps": [{"tool": "get_asset_info", "args": {"entity": "alice"}, "rationale": "rev-2"}]},
    )
    # Killed here — get_asset_info has NOT executed yet.
    journal0.close()

    reconstructed = rebuild(run_dir / "journal.jsonl")
    assert reconstructed.is_interrupted() is True
    assert len(reconstructed.plan_revisions) == 2
    assert reconstructed.plan_revisions[-1][0]["tool"] == "get_asset_info"
    # No tool_result after the second revision: steps_after_last_revision must be 0.
    assert reconstructed.steps_after_last_revision == 0

    # Resume: reasoner continues (last revised step still pending), get_asset_info
    # runs, then conclude, then verdict.
    journal = JsonlJournal(run_dir)
    deps = _deps(journal, FakeLLM([_continue(), _conclude(), _verdict()]), gate_approve=False)
    result = resume_investigation(_alert(), deps, reconstructed, run_id="run-multi-revision")
    journal.close()

    assert result.terminated_reason == "completed"
    all_events = _read_events(run_dir)
    new_tool_calls = [
        e for e in all_events if e["event"] == "tool_called" and e.get("step", 0) >= 3
    ]
    # Only get_asset_info (the last revised step) must run.
    assert any(e["tool"] == "get_asset_info" for e in new_tool_calls), (
        f"expected get_asset_info in new tool calls, got: {new_tool_calls}"
    )
    # query_logs (original step 2) and check_reputation (first revised step) must not re-run.
    assert not any(e["tool"] == "query_logs" for e in new_tool_calls), (
        f"query_logs must NOT re-run on resume; got: {new_tool_calls}"
    )
    assert not any(e["tool"] == "check_reputation" for e in new_tool_calls), (
        f"check_reputation must NOT re-run on resume; got: {new_tool_calls}"
    )
