"""Typed error hierarchy (ADR-0004 / triage-conventions §Reliability).

Errors are raised only inside the module that owns the failure and converted at
every seam (tool failure -> ``ToolResult(ok=False)``; exhausted LLM retries ->
partial Verdict + ``run_terminated(error)``). No exception crosses two module
boundaries — these types are the vocabulary for that conversion.
"""


class TriageError(Exception):
    """Base for every error raised inside the triage agent."""


class LLMError(TriageError):
    """An LLM call failed after retries and the repair attempt were exhausted."""


class ToolError(TriageError):
    """An investigation tool failed.

    ``transient`` errors (timeout / 5xx / connection reset) are retried once;
    ``permanent`` errors (schema / not-found / auth) are not. The distinction is
    carried on the instance so the executor's retry policy can read it.
    """

    def __init__(self, message: str, *, transient: bool = False) -> None:
        """Record the failure message and whether a retry is warranted."""
        super().__init__(message)
        self.transient = transient


class GateError(TriageError):
    """The Approval Gate could not reach or record a decision."""


class JournalError(TriageError):
    """A Journal event could not be appended or the Journal could not be read."""


class ConfigError(TriageError):
    """Configuration (env vars, Risk Policy file) was missing or invalid."""
