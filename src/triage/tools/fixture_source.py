"""The Fixture World DataSource (RFC-0001 §Tools, Ubiquitous Language).

The shipped ``DataSource``: a benign, deterministic dataset where the same Entity
tells the same story across every tool. Each investigation tool reads one
Entity-keyed JSON file under ``fixtures/`` — never keyed by ``event_type`` — so
both shipped alerts get meaningful results for the Entities they reference, and
any unknown Entity returns a not-found **permanent** ``ToolError`` (converted to
``ToolResult(ok=False)`` at the ``execute_tool`` seam — never a crash).

A scriptable failing source for the retry-semantics tests does NOT live here; it
belongs in the test module, which drives ``ToolError(transient=...)`` directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from triage.errors import ToolError

if TYPE_CHECKING:
    from collections.abc import Mapping

_FIXTURE_DIR = Path(__file__).parent / "fixtures"

# Each read-only tool maps to one Entity-keyed fixture file. The key is always an
# Entity value (never event_type), so the same Entity resolves the same way.
_TOOL_FIXTURES = {
    "lookup_user": "users.json",
    "query_logs": "logs.json",
    "check_reputation": "reputation.json",
    "get_asset_info": "assets.json",
}


def _load(filename: str) -> dict[str, dict[str, Any]]:
    """Read and parse one Entity-keyed fixture file."""
    return json.loads((_FIXTURE_DIR / filename).read_text(encoding="utf-8"))


class FixtureDataSource:
    """A read-only ``DataSource`` backed by the bundled Entity-keyed fixtures."""

    def __init__(self) -> None:
        """Load every tool's fixture dataset once at construction."""
        self._data = {tool: _load(name) for tool, name in _TOOL_FIXTURES.items()}

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve one tool call to its benign fixture record for the Entity.

        Raises:
            ToolError: permanent (``transient=False``) when the tool is unknown
                (a schema fault) or the Entity is not in the Fixture World (a
                not-found fault). Neither is retried; both surface as an
                ``Observation`` the agent adapts to.
        """
        dataset = self._data.get(tool)
        if dataset is None:
            msg = f"unknown investigation tool: {tool!r}"
            raise ToolError(msg, transient=False)
        entity = args.get("entity")
        record = dataset.get(entity) if isinstance(entity, str) else None
        if record is None:
            msg = f"no fixture record for entity {entity!r} via {tool}"
            raise ToolError(msg, transient=False)
        return record
