"""Tool + DataSource ports and the tool-execution runner (RFC-0001 §Tools).

A **Tool** is a read-only investigation capability the planner/reasoner sees as
``name`` + ``description`` + a JSON-serializable ``args_schema``; it executes
against a **DataSource**, the swappable backend (the shipped one is the Fixture
World; real connectors are roadmap). Both are Protocols so wave-1 lays the seam
and later waves swap implementations only.

Reliability seam (triage-conventions §Reliability). Tool errors **never escape
as exceptions past this package** — they surface as ``ToolResult(ok=False)``.
The retry decision needs ``ToolError.transient``, which only exists on the
exception instance, so the retry loop *must* live here, not in the executor: the
executor would otherwise need the exception to cross the seam to read it. The
runner, ``execute_tool``, is the single conversion point:

* transient (timeout / 5xx / connection reset) -> exactly one retry, 2 attempts
  total, with a short backoff between them;
* permanent (schema / not-found / auth) -> no retry;
* every outcome -> ``ToolResult`` (``ok=True`` on success, ``ok=False`` with
  ``error`` on failure).

``tools`` is a leaf and must not import ``journal`` (dependency direction). The
executor owns the Journal, so per-attempt observability crosses the seam via
optional callbacks: ``before_attempt(attempt)`` lets the caller emit
``tool_called`` and ``after_attempt(attempt, result)`` lets it emit
``tool_result`` — including for a failed transient attempt, so each attempt is
journaled with a shared ``step`` + ``attempt``. The backoff between attempts is
``_backoff`` — a module-level seam tests monkeypatch so they never really wait.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from triage.errors import ToolError
from triage.models import ToolResult

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_MAX_ATTEMPTS = 2
_BACKOFF_SECONDS = 0.2


def _backoff() -> None:
    """Wait the short backoff between retry attempts (tests monkeypatch this)."""
    time.sleep(_BACKOFF_SECONDS)


@runtime_checkable
class DataSource(Protocol):
    """The swappable backend a Tool reads from (Fixture World ships in wave 1)."""

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        """Return the raw data for one tool call against this source.

        Args:
            tool: The investigation tool name (e.g. ``"lookup_user"``).
            args: The tool's arguments.

        Returns:
            The benign, deterministic data for the looked-up Entity.

        Raises:
            ToolError: The lookup failed — ``transient`` for retryable transport
                faults, otherwise permanent (e.g. an unknown Entity, which is a
                not-found permanent error, never a crash).
        """
        ...  # pragma: no cover  # Protocol signature, never executed.


@runtime_checkable
class Tool(Protocol):
    """A read-only investigation capability the planner/reasoner can call."""

    name: str
    description: str
    args_schema: dict[str, Any]
    risk_tier: str

    def execute(self, args: Mapping[str, Any], source: DataSource) -> dict[str, Any]:
        """Run one call against ``source`` and return its raw data.

        ``execute`` lets ``ToolError`` propagate; ``execute_tool`` is the
        boundary that converts it to a ``ToolResult`` — keeping one conversion
        point for full branch coverage.
        """
        ...  # pragma: no cover  # Protocol signature, never executed.


class InvestigationTool:
    """The shipped ``Tool`` impl: a declared capability that defers to a source.

    Investigation tools are read-only, so they all share one ``risk_tier`` —
    ``"read_only"``. The Risk Policy classifies Response Actions on
    ``Action.name``, never tools, so this tier is descriptive metadata for the
    planner, not a gate input (RFC-0001 §Tools lists ``risk_tier`` on ``Tool``).
    """

    risk_tier = "read_only"

    def __init__(self, name: str, description: str, args_schema: dict[str, Any]) -> None:
        """Declare the tool's name, description, and JSON-serializable schema."""
        self.name = name
        self.description = description
        self.args_schema = args_schema

    def execute(self, args: Mapping[str, Any], source: DataSource) -> dict[str, Any]:
        """Delegate to the source under this tool's name; let ToolError escape."""
        return source.fetch(self.name, args)


def execute_tool(
    tool: Tool,
    args: Mapping[str, Any],
    source: DataSource,
    *,
    before_attempt: Callable[[int], None] | None = None,
    after_attempt: Callable[[int, ToolResult], None] | None = None,
) -> ToolResult:
    """Run a tool with the retry policy, converting every outcome to a ToolResult.

    The single seam past which a tool failure is never an exception. Transient
    failures get one retry (2 attempts total) with a short backoff; permanent
    failures get none. ``attempt`` is 1-based so it matches the journal directly.

    Args:
        tool: The investigation tool to run.
        args: The tool's arguments.
        source: The backend to read from.
        before_attempt: Called with the 1-based attempt number before each try —
            the caller emits ``tool_called`` here.
        after_attempt: Called with the attempt number and its ``ToolResult`` after
            each try (success or failure) — the caller emits ``tool_result``.

    Returns:
        The last attempt's ``ToolResult`` (``ok=True`` on success).
    """
    result = ToolResult(tool=tool.name, ok=False, error="not attempted")
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        if before_attempt is not None:
            before_attempt(attempt)
        try:
            data = tool.execute(args, source)
        except ToolError as exc:
            result = ToolResult(tool=tool.name, ok=False, error=str(exc))
            retry = exc.transient and attempt < _MAX_ATTEMPTS
        else:
            result = ToolResult(tool=tool.name, ok=True, data=data)
            retry = False
        if after_attempt is not None:
            after_attempt(attempt, result)
        if not retry:
            return result
        _backoff()
    return result  # pragma: no cover  # loop always returns; defensive only.
