"""The Journal port and its no-op implementation (triage-conventions §Journal).

The Journal is the append-only, event-sourced record of one Run. Wave 1 lays the
seam — the executor, planner, and gate emit events from day one — and ships only
``NoopJournal``; wave 2 adds ``JsonlJournal`` behind the same ``Journal``
Protocol, so callers are never refactored.

``emit`` is the contract. The *implementation* owns ``seq`` (monotonic),
``event_id`` (uuid), and ``ts`` (ISO-8601) — callers never supply them, so they
cannot drift. Callers pass only the event name, its payload, and an optional
``agent`` override (``"triage"`` by default; ``"threat-intel"`` for the
delegated loop). One generic method, never per-event-type methods — mirroring
the "never branch on event_type" rule.
"""

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Journal(Protocol):
    """Append-one-Journal-Event-per-call port consumed across the agent."""

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        """Append one Journal Event.

        Args:
            event: The event name (e.g. ``"run_started"``, ``"tool_called"``).
            payload: The event's payload fields, per the journal event schema.
            agent: Which loop emitted it — ``"triage"`` or ``"threat-intel"``.
        """
        ...  # pragma: no cover  # Protocol signature, never executed.


class NoopJournal:
    """A Journal that records nothing — the default seam for tests and CI."""

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        """Discard the event; the no-op keeps emit calls free of branching."""
