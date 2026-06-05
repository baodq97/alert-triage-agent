"""Tests for the Journal port and NoopJournal (triage-conventions §Journal).

Wave 1 ships only the Protocol + NoopJournal; JsonlJournal arrives in wave 2.
The emit signature is the contract every later wave depends on, so it is the
behaviour pinned here: the implementation owns seq/event_id/ts; callers pass
only the event name, the payload, and an optional agent override.
"""

from triage.journal import Journal, NoopJournal


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
