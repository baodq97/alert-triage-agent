"""The ToolRegistry — read-only investigation tools ONLY (RFC-0001 §Tools).

The registry exposes exactly four tools: ``lookup_user``, ``query_logs``,
``check_reputation``, ``get_asset_info``. No Response Action (``block_user``) is
reachable through it, *by construction* — so the executor can never mutate state
mid-loop, and the eval assertion ``gate_before_high_risk`` holds structurally,
not by prompt discipline (triage-conventions §Investigation tools vs response
actions).

Args schemas are plain JSON-serializable dicts: they flow into the planner
prompt and into the journal ``args`` field, so they stay declarative — no
validation framework lives here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from triage.tools.base import InvestigationTool

if TYPE_CHECKING:
    from triage.tools.base import Tool

_ENTITY_ARG = {
    "type": "object",
    "properties": {"entity": {"type": "string", "description": "The Entity to look up."}},
    "required": ["entity"],
}

_INVESTIGATION_TOOLS: tuple[InvestigationTool, ...] = (
    InvestigationTool(
        name="lookup_user",
        description="Look up a user or service account: status, role, tenure, recent posture.",
        args_schema=_ENTITY_ARG,
    ),
    InvestigationTool(
        name="query_logs",
        description="Query recent activity logs for an Entity (IP, user, endpoint, asset).",
        args_schema=_ENTITY_ARG,
    ),
    InvestigationTool(
        name="check_reputation",
        description="Check the threat reputation of an Entity (typically an IP or domain).",
        args_schema=_ENTITY_ARG,
    ),
    InvestigationTool(
        name="get_asset_info",
        description="Get the inventory record for an asset, endpoint, or cloud resource.",
        args_schema=_ENTITY_ARG,
    ),
)


class ToolRegistry:
    """An immutable lookup of the read-only investigation tools by name."""

    def __init__(self, tools: tuple[InvestigationTool, ...] = _INVESTIGATION_TOOLS) -> None:
        """Index the investigation tools by name (defaults to the shipped four)."""
        self._tools: dict[str, InvestigationTool] = {tool.name: tool for tool in tools}

    def names(self) -> list[str]:
        """Return the registered tool names — the executor's allowed call set."""
        return list(self._tools)

    def get(self, name: str) -> Tool:
        """Return the tool by name.

        Raises:
            KeyError: ``name`` is not a registered investigation tool — which a
                Response Action like ``block_user`` always is, by construction.
        """
        return self._tools[name]

    def specs(self) -> list[dict[str, object]]:
        """Return the planner-facing specs (name, description, args schema)."""
        return [
            {"name": t.name, "description": t.description, "args_schema": t.args_schema}
            for t in self._tools.values()
        ]
