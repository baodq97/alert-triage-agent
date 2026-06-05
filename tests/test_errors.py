"""Tests for the typed error hierarchy (ADR-0004 / triage-conventions)."""

import pytest

from triage.errors import (
    ConfigError,
    GateError,
    JournalError,
    LLMError,
    ToolError,
    TriageError,
)


@pytest.mark.parametrize(
    "subclass",
    [LLMError, ToolError, GateError, JournalError, ConfigError],
)
def test_every_error_is_a_triage_error(subclass: type[TriageError]) -> None:
    assert issubclass(subclass, TriageError)


def test_triage_error_is_an_exception() -> None:
    assert issubclass(TriageError, Exception)


def test_tool_error_transient() -> None:
    error = ToolError("connection reset", transient=True)
    assert error.transient is True
    assert "connection reset" in str(error)


def test_tool_error_permanent_is_the_default() -> None:
    error = ToolError("schema mismatch")
    assert error.transient is False


def test_tool_error_can_be_raised_and_caught_as_triage_error() -> None:
    error = ToolError("boom", transient=True)
    with pytest.raises(TriageError):
        raise error
