"""Tests for the Journal port, NoopJournal, and JsonlJournal (triage-conventions §Journal).

Wave 1 shipped the Protocol + NoopJournal; wave 2 adds ``JsonlJournal`` behind
the same ``Journal`` Protocol. The emit signature is the contract every later
wave depends on: the implementation owns seq/event_id/ts; callers pass only the
event name, the payload, and an optional agent override.

The ``JsonlJournal`` tests assert the file *format* contract (every line parses,
the common fields are present and flat, ``seq`` is strictly monotonic from 1,
lines are append-only) plus event coverage of a full end-to-end Run through
``triage`` and the US-0002 AC2 retry-visibility proof — all against a *real*
``journal.jsonl`` file written under ``tmp_path``, never the repo's ``runs/``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from triage.core import TriageDeps, triage
from triage.errors import JournalError, ToolError
from triage.gate import AutoGate, RiskPolicy
from triage.journal import Journal, JsonlJournal, NoopJournal, rebuild
from triage.llm import FakeLLM
from triage.models import Alert
from triage.tools import ToolRegistry

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


def test_noop_journal_satisfies_the_journal_protocol() -> None:
    journal: Journal = NoopJournal()
    assert isinstance(journal, Journal)


def test_noop_emit_accepts_event_and_payload_and_returns_none() -> None:
    journal = NoopJournal()
    result = journal.emit("run_started", {"alert_id": "ALT-1", "schema_version": 1})
    assert result is None


def test_noop_emit_accepts_agent_override() -> None:
    journal = NoopJournal()
    # The threat-intel delegated loop tags its events with a non-default agent.
    journal.emit("llm_call", {"purpose": "plan"}, agent="threat-intel")


def test_noop_emit_accepts_empty_payload() -> None:
    journal = NoopJournal()
    journal.emit("run_terminated", {})


def test_a_plain_object_is_not_a_journal() -> None:
    assert not isinstance(object(), Journal)


# --- JsonlJournal: file format + common-field contract -----------------------


_COMMON_FIELDS = {"seq", "event_id", "ts", "event", "agent"}


def _read_lines(run_dir: Path) -> list[dict[str, Any]]:
    """Parse the real journal.jsonl back into a list of event dicts."""
    text = (run_dir / "journal.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def test_jsonl_journal_satisfies_the_protocol(tmp_path: Path) -> None:
    journal: Journal = JsonlJournal(tmp_path / "run-1")
    assert isinstance(journal, Journal)


def test_jsonl_journal_writes_flat_lines_with_common_and_payload_fields(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    journal = JsonlJournal(run_dir)
    journal.emit("run_started", {"alert_id": "ALT-1", "schema_version": 1})

    [event] = _read_lines(run_dir)
    # Common fields owned by the implementation are present.
    assert set(event) >= _COMMON_FIELDS
    assert event["event"] == "run_started"
    assert event["agent"] == "triage"
    # Payload fields are merged flat at the top level (NOT nested under a key).
    assert event["alert_id"] == "ALT-1"
    assert event["schema_version"] == 1


def test_jsonl_journal_seq_is_strictly_monotonic_from_one(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    journal = JsonlJournal(run_dir)
    for i in range(3):
        journal.emit("llm_call", {"purpose": "reason", "n": i})

    events = _read_lines(run_dir)
    assert [e["seq"] for e in events] == [1, 2, 3]
    # event_id is unique per event (uuid4), and timestamps are ISO-8601.
    assert len({e["event_id"] for e in events}) == 3


def test_jsonl_journal_agent_override_is_recorded(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    journal = JsonlJournal(run_dir)
    journal.emit("llm_call", {"purpose": "plan"}, agent="threat-intel")

    [event] = _read_lines(run_dir)
    assert event["agent"] == "threat-intel"


def test_jsonl_journal_is_append_only_never_rewrites_prior_lines(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    journal = JsonlJournal(run_dir)
    journal.emit("run_started", {"alert_id": "ALT-1"})
    first_snapshot = (run_dir / "journal.jsonl").read_text(encoding="utf-8")
    journal.emit("run_terminated", {"reason": "completed"})
    second_snapshot = (run_dir / "journal.jsonl").read_text(encoding="utf-8")

    # The first line is byte-for-byte unchanged; the second is purely appended.
    assert second_snapshot.startswith(first_snapshot)
    assert len(_read_lines(run_dir)) == 2


def test_jsonl_journal_creates_parent_directory(tmp_path: Path) -> None:
    run_dir = tmp_path / "nested" / "deeper" / "run-1"
    assert not run_dir.exists()
    JsonlJournal(run_dir).emit("run_started", {"alert_id": "ALT-1"})
    assert (run_dir / "journal.jsonl").exists()


def test_jsonl_journal_close_releases_the_handle(tmp_path: Path) -> None:
    journal = JsonlJournal(tmp_path / "run-1")
    journal.emit("run_started", {"alert_id": "ALT-1"})
    journal.close()  # no crash; the run's single writer is done.


def test_jsonl_journal_raises_journal_error_on_unwritable_path(tmp_path: Path) -> None:
    # A file standing where the run directory should be makes mkdir/open fail; the
    # OSError converts to JournalError at this seam (typed-errors rule).
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(JournalError):
        JsonlJournal(blocker / "run-1")


def test_jsonl_journal_raises_journal_error_when_write_fails(tmp_path: Path) -> None:
    # After close, the handle is unusable: a write on it raises ValueError, which
    # emit converts to JournalError (the IO-fault-on-append branch).
    journal = JsonlJournal(tmp_path / "run-1")
    journal.close()
    with pytest.raises(JournalError):
        journal.emit("run_started", {"alert_id": "ALT-1"})


# --- end-to-end event coverage of a full Run through triage ------------------


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-JNL-1",
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


class _BenignSource:
    """A DataSource returning benign, deterministic data for any lookup."""

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        return {"tool": tool, "entity": args.get("entity"), "status": "benign"}


def test_jsonl_journal_covers_a_full_run_end_to_end(tmp_path: Path) -> None:
    # A real end-to-end Run with an approved high-risk action exercises every
    # major event class: run_started -> llm_call/plan_created -> tool pair ->
    # llm_call(reason) -> verdict -> gate_requested/gate_decision ->
    # action_executed -> run_terminated. All written to a real journal.jsonl.
    run_dir = tmp_path / "run-e2e"
    journal = JsonlJournal(run_dir)
    actions = [{"name": "block_user", "params": {"user": "alice"}, "description": "block"}]
    e2e_replies = [
        _plan("lookup_user"),
        _conclude(),
        _verdict(actions=actions, finding_entity="alice"),
    ]
    deps = TriageDeps(
        llm=FakeLLM(e2e_replies),
        journal=journal,
        registry=ToolRegistry(),
        source=_BenignSource(),
        gate=AutoGate(journal, approve=True),
        policy=RiskPolicy(),
    )
    result = triage(_alert(), deps, run_id="run-e2e")
    journal.close()

    events = _read_lines(run_dir)
    names = [e["event"] for e in events]
    for expected in (
        "run_started",
        "llm_call",
        "plan_created",
        "tool_called",
        "tool_result",
        "verdict",
        "gate_requested",
        "gate_decision",
        "action_executed",
        "run_terminated",
    ):
        assert expected in names, f"missing {expected} in {names}"
    # seq across the whole run is strictly monotonic from 1, one step at a time.
    assert [e["seq"] for e in events] == list(range(1, len(events) + 1))
    # run_started is first, run_terminated is last, the verdict shipped.
    assert names[0] == "run_started"
    assert names[-1] == "run_terminated"
    assert result.terminated_reason == "completed"
    # The tool pair shares step + attempt (reconstructable without positional inference).
    called = next(e for e in events if e["event"] == "tool_called")
    tool_result = next(e for e in events if e["event"] == "tool_result")
    assert called["step"] == tool_result["step"]
    assert called["attempt"] == tool_result["attempt"] == 1


# --- US-0002 AC2: transient-failure retry visibility -------------------------


class _TransientThenOkSource:
    """Fails transient on the first attempt, succeeds on the second.

    Proves the retry policy (triage-conventions §Reliability: transient -> exactly
    one retry, 2 attempts total) is journaled as two distinct attempts.
    """

    def __init__(self) -> None:
        self.attempts = 0

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        self.attempts += 1
        if self.attempts == 1:
            msg = "transient upstream timeout"
            raise ToolError(msg, transient=True)
        return {"tool": tool, "entity": args.get("entity"), "status": "benign"}


def test_jsonl_journal_shows_transient_retry_as_two_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # AC2: a transient tool failure shows attempt 1 (error) + attempt 2 (retry) as
    # four separate journal lines (tool_called/tool_result x2) sharing `step`,
    # differing `attempt` — proved through a real JsonlJournal file. Patch the
    # tool backoff so the test never actually sleeps.
    monkeypatch.setattr("triage.tools.base._backoff", lambda: None)
    run_dir = tmp_path / "run-retry"
    journal = JsonlJournal(run_dir)
    source = _TransientThenOkSource()
    deps = TriageDeps(
        llm=FakeLLM([_plan("lookup_user"), _conclude(), _verdict()]),
        journal=journal,
        registry=ToolRegistry(),
        source=source,
        gate=AutoGate(journal, approve=False),
        policy=RiskPolicy(),
    )
    triage(_alert(), deps, run_id="run-retry")
    journal.close()

    events = _read_lines(run_dir)
    called = [e for e in events if e["event"] == "tool_called"]
    results = [e for e in events if e["event"] == "tool_result"]
    # Exactly two attempts each — the transient failure was retried once.
    assert source.attempts == 2
    assert [e["attempt"] for e in called] == [1, 2]
    assert [e["attempt"] for e in results] == [1, 2]
    # Both attempts share the same executor step.
    assert {e["step"] for e in called} == {e["step"] for e in results} == {called[0]["step"]}
    # Attempt 1 is the error; attempt 2 is the recovered success.
    assert results[0]["ok"] is False
    assert "error" in results[0]
    assert results[1]["ok"] is True
    assert "data" in results[1]


# --- Resume rebuild: typed state reconstruction ------------------------------


def test_rebuild_reconstructs_views_from_a_full_run(tmp_path: Path) -> None:
    # A real end-to-end Run, then rebuild its journal and assert every view.
    run_dir = tmp_path / "run-rebuild"
    journal = JsonlJournal(run_dir)
    actions = [{"name": "block_user", "params": {"user": "alice"}, "description": "block"}]
    rebuild_replies = [
        _plan("lookup_user"),
        _conclude(),
        _verdict(actions=actions, finding_entity="alice"),
    ]
    deps = TriageDeps(
        llm=FakeLLM(rebuild_replies),
        journal=journal,
        registry=ToolRegistry(),
        source=_BenignSource(),
        gate=AutoGate(journal, approve=True),
        policy=RiskPolicy(),
    )
    triage(_alert(), deps, run_id="run-rebuild")
    journal.close()

    run = rebuild(run_dir / "journal.jsonl")
    assert run.alert_id == "ALT-JNL-1"
    assert run.config == {"max_steps": None}
    assert run.schema_version == 1
    assert [s["tool"] for s in run.plan_steps] == ["lookup_user"]
    # One completed Tool Step, reused from record (step/attempt pair reconstructed).
    assert len(run.observations) == 1
    assert run.observations[0].tool == "lookup_user"
    assert run.observations[0].ok is True
    # llm_call purposes are the audit trail; the reasoner verb is NOT recorded.
    assert run.llm_purposes == ["plan", "reason", "verdict"]
    assert run.gate_decision is not None
    assert run.gate_decision["decision"] == "approved"
    assert [a.kind for a in run.executed_actions()] == ["action_executed"]
    assert run.verdict is not None
    assert run.terminated_reason == "completed"
    assert run.is_interrupted() is False
    assert run.is_awaiting_approval() is False
    assert run.last_seq == run.events[-1]["seq"]


def test_rebuild_missing_file_raises_journal_error(tmp_path: Path) -> None:
    with pytest.raises(JournalError):
        rebuild(tmp_path / "nope" / "journal.jsonl")


def test_rebuild_tolerates_a_torn_trailing_line(tmp_path: Path) -> None:
    # A clean kill leaves the last in-flight write torn (no trailing newline). The
    # torn trailing line is skipped; the good prefix rebuilds intact.
    path = tmp_path / "journal.jsonl"
    good = json.dumps({"seq": 1, "event": "run_started", "alert_id": "ALT-1"})
    torn = '{"seq": 2, "event": "llm_call", "purpos'  # cut off mid-write
    path.write_text(good + "\n" + torn, encoding="utf-8")

    run = rebuild(path)
    assert run.alert_id == "ALT-1"
    assert run.last_seq == 1  # only the good line counted
    assert [e["event"] for e in run.events] == ["run_started"]


def test_rebuild_malformed_non_trailing_line_raises_journal_error(tmp_path: Path) -> None:
    # Corruption mid-file (not the in-flight tail) is NOT the crash contract — it is
    # a broken audit record, so rebuild refuses it.
    path = tmp_path / "journal.jsonl"
    good = json.dumps({"seq": 1, "event": "run_started"})
    tail = json.dumps({"seq": 2, "event": "run_terminated", "reason": "completed"})
    path.write_text(good + "\n" + "{ not json\n" + tail + "\n", encoding="utf-8")

    with pytest.raises(JournalError):
        rebuild(path)


def test_rebuild_non_object_line_raises_journal_error(tmp_path: Path) -> None:
    # A JSON value that is not an object is corruption, not an event.
    path = tmp_path / "journal.jsonl"
    path.write_text('[1, 2, 3]\n{"seq": 2, "event": "x"}\n', encoding="utf-8")
    with pytest.raises(JournalError):
        rebuild(path)


def test_rebuild_blank_non_trailing_line_raises_journal_error(tmp_path: Path) -> None:
    # A blank line mid-file is corruption; only a blank trailing remnant is tolerated.
    path = tmp_path / "journal.jsonl"
    path.write_text('{"seq": 1, "event": "a"}\n\n{"seq": 2, "event": "b"}\n', encoding="utf-8")
    with pytest.raises(JournalError):
        rebuild(path)


def test_rebuild_tolerates_blank_trailing_line(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_text('{"seq": 1, "event": "run_started", "alert_id": "ALT-1"}\n\n', encoding="utf-8")
    run = rebuild(path)
    assert run.alert_id == "ALT-1"
    assert run.last_seq == 1


def test_rebuild_captures_plan_revisions_in_order(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    lines = [
        {"seq": 1, "event": "run_started", "alert_id": "ALT-1"},
        {"seq": 2, "event": "plan_created", "steps": [{"tool": "lookup_user"}]},
        {"seq": 3, "event": "plan_revised", "steps": [{"tool": "query_logs"}]},
        {"seq": 4, "event": "plan_revised", "steps": [{"tool": "check_reputation"}]},
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")
    run = rebuild(path)
    assert run.plan_steps == [{"tool": "lookup_user"}]
    assert run.plan_revisions == [[{"tool": "query_logs"}], [{"tool": "check_reputation"}]]


def test_rebuild_ignores_an_llm_call_without_a_purpose(tmp_path: Path) -> None:
    # A malformed/old llm_call missing `purpose` contributes no purpose entry.
    path = tmp_path / "journal.jsonl"
    lines = [
        {"seq": 1, "event": "llm_call", "purpose": "plan"},
        {"seq": 2, "event": "llm_call"},  # no purpose key
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")
    run = rebuild(path)
    assert run.llm_purposes == ["plan"]


def test_rebuild_steps_after_last_revision_counts_steps_not_attempts(tmp_path: Path) -> None:
    # A transient retry after a revision records TWO tool_result events for the same
    # step (attempt 1 fails, attempt 2 succeeds).  steps_after_last_revision must
    # count that as ONE step, not two, so resume does not inflate next_step_index and
    # accidentally skip the revised step.
    path = tmp_path / "journal.jsonl"
    lines = [
        {"seq": 1, "event": "run_started", "alert_id": "ALT-1"},
        {"seq": 2, "event": "plan_created", "steps": [{"tool": "lookup_user"}]},
        # Step 1 runs before the revision.
        {"seq": 3, "event": "tool_called", "step": 1, "attempt": 1, "tool": "lookup_user"},
        {"seq": 4, "event": "tool_result", "step": 1, "attempt": 1, "ok": True},
        # Revision fires; the revised step would be step 2.
        {"seq": 5, "event": "plan_revised", "steps": [{"tool": "check_reputation"}]},
        # Step 2: attempt 1 fails (transient), attempt 2 recovers.
        {"seq": 6, "event": "tool_called", "step": 2, "attempt": 1, "tool": "check_reputation"},
        {"seq": 7, "event": "tool_result", "step": 2, "attempt": 1, "ok": False, "error": "t/o"},
        {"seq": 8, "event": "tool_called", "step": 2, "attempt": 2, "tool": "check_reputation"},
        {"seq": 9, "event": "tool_result", "step": 2, "attempt": 2, "ok": True, "data": {}},
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")
    run = rebuild(path)
    # The retry must count as 1 step, not 2.
    assert run.steps_after_last_revision == 1


def test_rebuild_event_without_seq_does_not_advance_last_seq(tmp_path: Path) -> None:
    # A line lacking a numeric `seq` does not advance last_seq (the isinstance
    # guard), but the scan still continues to the following line.
    path = tmp_path / "journal.jsonl"
    lines = [
        {"event": "run_started", "alert_id": "ALT-1"},  # no seq
        {"seq": 5, "event": "run_terminated", "reason": "completed"},
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")
    run = rebuild(path)
    assert run.alert_id == "ALT-1"
    assert run.terminated_reason == "completed"
    assert run.last_seq == 5  # advanced by the second line, not the seqless first


def test_rebuild_unreadable_journal_raises_journal_error(tmp_path: Path) -> None:
    # The journal path exists but is a directory: read_text raises OSError, which
    # converts to JournalError at the scan seam.
    bogus = tmp_path / "journal.jsonl"
    bogus.mkdir()
    with pytest.raises(JournalError):
        rebuild(bogus)


def test_rebuild_unknown_event_is_kept_but_folds_no_view(tmp_path: Path) -> None:
    # Forward compatibility: a future event type stays in the raw trail but updates
    # no view, so older fields still rebuild.
    path = tmp_path / "journal.jsonl"
    lines = [
        {"seq": 1, "event": "run_started", "alert_id": "ALT-1"},
        {"seq": 2, "event": "future_event", "whatever": True},
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")
    run = rebuild(path)
    assert run.alert_id == "ALT-1"
    assert len(run.events) == 2


# --- Resume reopen: seq continuity + torn-line truncation --------------------


def test_reopen_continues_seq_strictly_monotonic(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-reopen"
    first = JsonlJournal(run_dir)
    first.emit("run_started", {"alert_id": "ALT-1"})
    first.emit("llm_call", {"purpose": "plan"})
    first.close()

    second = JsonlJournal(run_dir)  # reopen the same run dir
    second.emit("run_terminated", {"reason": "completed"})
    second.close()

    events = _read_lines(run_dir)
    assert [e["seq"] for e in events] == [1, 2, 3]
    assert events[-1]["event"] == "run_terminated"


def test_reopen_truncates_a_torn_trailing_line_before_appending(tmp_path: Path) -> None:
    # Simulate a crash: a complete line + a torn partial line with no newline. On
    # reopen, the torn bytes are physically truncated, and the next emit lands on a
    # CLEAN line with the right seq — never concatenated onto the partial one.
    run_dir = tmp_path / "run-torn"
    run_dir.mkdir()
    path = run_dir / "journal.jsonl"
    good = json.dumps({"seq": 1, "event": "run_started", "alert_id": "ALT-1"})
    torn = '{"seq": 2, "event": "llm_call", "purpos'  # in-flight, no newline
    path.write_text(good + "\n" + torn, encoding="utf-8")

    journal = JsonlJournal(run_dir)  # reopen truncates the torn tail
    journal.emit("run_terminated", {"reason": "completed"})
    journal.close()

    events = _read_lines(run_dir)
    # The torn line is gone; the appended event is whole and seq continues from 1.
    assert [e["event"] for e in events] == ["run_started", "run_terminated"]
    assert [e["seq"] for e in events] == [1, 2]
    # Every line is independently parseable (no concatenation onto the partial).
    raw = path.read_text(encoding="utf-8")
    assert "purpos" not in raw


def test_reopen_fresh_run_dir_starts_at_seq_one(tmp_path: Path) -> None:
    # A run dir with no journal yet behaves exactly like wave 1 (seq from 1).
    run_dir = tmp_path / "run-fresh"
    journal = JsonlJournal(run_dir)
    journal.emit("run_started", {"alert_id": "ALT-1"})
    assert _read_lines(run_dir)[0]["seq"] == 1


# --- US-0005 QA F1/F2: agent-aware rebuild -----------------------------------


def _e(seq: int, event: str, agent: str = "triage", **kw: Any) -> dict[str, Any]:
    """Compact event dict builder for inline journal lines in tests."""
    return {"seq": seq, "event": event, "agent": agent, **kw}


def test_rebuild_threat_intel_inner_rows_excluded_from_observations(tmp_path: Path) -> None:
    # F1: tool_called / tool_result events with agent="threat-intel" must NOT
    # enter the resumable observations — they stay in the raw events audit trail.
    # Only agent="triage" rows produce StepObservations.
    path = tmp_path / "journal.jsonl"
    lines = [
        # Primary-loop TI wrapper (agent="triage") — goes into observations.
        _e(1, "run_started", alert_id="ALT-TI"),
        _e(2, "tool_called", step=1, attempt=1, tool="threat_intel.enrich"),
        # TI mini-loop inner rows (agent="threat-intel") — stay in raw audit only.
        _e(3, "tool_called", "threat-intel", step=1, attempt=1, tool="ti_reputation"),
        _e(4, "tool_result", "threat-intel", step=1, attempt=1, ok=True, data={"s": 0.9}),
        _e(5, "tool_called", "threat-intel", step=2, attempt=1, tool="ti_whois"),
        _e(6, "tool_result", "threat-intel", step=2, attempt=1, ok=True, data={}),
        # Primary-loop TI wrapper result — closes the pair, becomes an observation.
        _e(7, "tool_result", step=1, attempt=1, ok=True, data={"ioc_type": "public_ip"}),
        # Primary executor step (agent="triage").
        _e(8, "tool_called", step=2, attempt=1, tool="lookup_user"),
        _e(9, "tool_result", step=2, attempt=1, ok=True, data={}),
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")

    run = rebuild(path)

    # All 9 events in raw audit trail.
    assert len(run.events) == 9
    # Only 2 observations: the TI wrapper (step=1) + the executor step (step=2).
    # The 4 threat-intel inner rows must NOT be here.
    assert len(run.observations) == 2
    tools = [obs.tool for obs in run.observations]
    assert "threat_intel.enrich" in tools
    assert "ti_reputation" not in tools
    assert "ti_whois" not in tools
    # step numbers match the primary-loop numbering.
    steps = {obs.step for obs in run.observations}
    assert steps == {1, 2}


def test_rebuild_threat_intel_rows_do_not_pollute_pending_calls(tmp_path: Path) -> None:
    # F1: the TI wrapper's pending_call must not be clobbered by inner TI rows
    # sharing the same step number.  The wrapper's tool_result must pair with the
    # wrapper's tool_called, not with an inner result.
    path = tmp_path / "journal.jsonl"
    lines = [
        _e(1, "run_started", alert_id="ALT-TI"),
        # Primary wrapper: step=1, tool=threat_intel.enrich.
        _e(2, "tool_called", step=1, attempt=1, tool="threat_intel.enrich"),
        # Inner TI rows also at step=1 — must be ignored by _pending_calls.
        _e(3, "tool_called", "threat-intel", step=1, attempt=1, tool="ti_rep"),
        _e(4, "tool_result", "threat-intel", step=1, attempt=1, ok=False, error="miss"),
        # Primary wrapper result at step=1 — must pair with seq=2, not seq=3.
        _e(5, "tool_result", step=1, attempt=1, ok=True, data={"ioc_type": "hash"}),
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")

    run = rebuild(path)

    assert len(run.observations) == 1
    obs = run.observations[0]
    # Must reconstruct from the primary wrapper pair, not the inner TI pair.
    assert obs.tool == "threat_intel.enrich"
    assert obs.ok is True
    assert obs.data == {"ioc_type": "hash"}


def test_rebuild_steps_after_last_revision_unaffected_by_ti_inner_rows(
    tmp_path: Path,
) -> None:
    # F1: steps_after_last_revision must count primary-loop (agent="triage")
    # tool_result events only; TI inner (agent="threat-intel") rows must be ignored.
    path = tmp_path / "journal.jsonl"
    lines = [
        _e(1, "run_started", alert_id="ALT-TI"),
        _e(2, "plan_created", steps=[{"tool": "lookup_user"}, {"tool": "check_reputation"}]),
        # TI enrichment at step=1 (before plan loop).
        _e(3, "tool_called", step=1, attempt=1, tool="threat_intel.enrich"),
        _e(4, "tool_called", "threat-intel", step=1, attempt=1, tool="ti_rep"),
        _e(5, "tool_result", "threat-intel", step=1, attempt=1, ok=True, data={}),
        _e(6, "tool_result", step=1, attempt=1, ok=True, data={}),
        # Executor step at step=2 (before revision).
        _e(7, "tool_called", step=2, attempt=1, tool="lookup_user"),
        _e(8, "tool_result", step=2, attempt=1, ok=True, data={}),
        # Plan revision fires.
        _e(9, "plan_revised", steps=[{"tool": "check_reputation"}]),
        # Executor step after revision at step=3.
        _e(10, "tool_called", step=3, attempt=1, tool="check_reputation"),
        _e(11, "tool_result", step=3, attempt=1, ok=True, data={}),
    ]
    path.write_text("".join(json.dumps(item) + "\n" for item in lines), encoding="utf-8")

    run = rebuild(path)

    # Only the primary-loop executor step after the revision (step=3) counts.
    # The TI inner rows (step=1) and the TI wrapper (step=1, before revision)
    # must not inflate this counter.
    assert run.steps_after_last_revision == 1


# --------------------------------------------------------------------------- #
# RFC-0003 adjacent hardening: 0o700 permissions on the run dir                #
# --------------------------------------------------------------------------- #


import sys  # noqa: E402 — late import acceptable: test-only, platform guard reads it.


def test_jsonl_journal_creates_run_dir_with_0o700(tmp_path: Path) -> None:
    """JsonlJournal creates runs/ dirs with mode 0o700 (owner-only access).

    Skipped on platforms where directory permissions are not enforced
    (Windows does not honour POSIX mode bits).
    """
    if sys.platform == "win32":
        return  # pragma: no cover  # POSIX permissions not applicable on Windows.
    run_dir = tmp_path / "runs" / "ALT-perm-test"
    journal = JsonlJournal(run_dir)
    journal.emit("run_started", {"alert_id": "ALT-perm-test", "config": {}, "schema_version": 1})
    journal._handle.close()  # noqa: SLF001 — close file handle for stat to reflect final state.
    mode = run_dir.stat().st_mode & 0o777
    # 0o700 or more restrictive (umask may tighten further — never looser for owner bits).
    assert mode & 0o700 == 0o700, f"expected 0o700 bits set, got {oct(mode)}"
    assert mode & 0o077 == 0, f"expected no group/other bits, got {oct(mode)}"
