"""TI tool registry and fixture-backed data source (RFC-0002 §Decision).

Mirrors the ``triage.tools`` pattern at TI scale:

* ``TIFixtureDataSource`` — the ``DataSource`` implementation for the TI world,
  backed by ``fixtures/{reputation,passive_dns,threat_feed}.json``.  Each file is
  keyed by IOC value (``"185.220.101.5"``, ``"evil.example.com"``, etc.) so the
  same IOC resolves consistently across all three tools.  A miss raises
  ``ToolError(transient=False)`` — not-found is permanent, matching the primary
  ``FixtureDataSource`` convention.

* ``TIToolRegistry`` — an immutable lookup of the three read-only TI tools.  The
  args schema uses ``"ioc"`` (not ``"entity"``) to distinguish TI calls from primary
  loop calls in the journal trace.

The three TI tools are read-only by construction (RFC-0001 §Investigation tools
vs response actions rule applies here too: the TI mini-loop must never mutate
state mid-loop).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from triage.errors import ToolError
from triage.tools.base import InvestigationTool

if TYPE_CHECKING:
    from collections.abc import Mapping

    from triage.tools.base import Tool

_FIXTURE_DIR = Path(__file__).parent / "fixtures"

# Each TI tool maps to one IOC-keyed fixture file.
_TI_TOOL_FIXTURES: dict[str, str] = {
    "multi_source_reputation": "reputation.json",
    "passive_dns": "passive_dns.json",
    "threat_feed": "threat_feed.json",
}

_IOC_ARG = {
    "type": "object",
    "properties": {
        "ioc": {
            "type": "string",
            "description": "The IOC value to look up (IP, domain, or hash).",
        }
    },
    "required": ["ioc"],
}


def _load(filename: str) -> dict[str, dict[str, Any]]:
    """Read and parse one IOC-keyed fixture file."""
    return json.loads((_FIXTURE_DIR / filename).read_text(encoding="utf-8"))


class TIFixtureDataSource:
    """A read-only ``DataSource`` backed by the bundled TI IOC-keyed fixtures.

    Follows the same pattern as ``FixtureDataSource`` in ``triage.tools``:
    loads all fixture data once at construction; a miss or unknown tool is a
    permanent ``ToolError`` — never a crash.
    """

    def __init__(self) -> None:
        """Load every TI tool's fixture dataset once at construction."""
        self._data = {tool: _load(name) for tool, name in _TI_TOOL_FIXTURES.items()}

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve one TI tool call to its fixture record for the IOC.

        Args:
            tool: The TI tool name (``"multi_source_reputation"``, etc.).
            args: Must contain ``"ioc"`` key with the IOC value to look up.

        Returns:
            The fixture record for the IOC.

        Raises:
            ToolError: permanent (``transient=False``) when the tool is unknown,
                the ``"ioc"`` key is missing, or the IOC has no fixture record.
        """
        dataset = self._data.get(tool)
        if dataset is None:
            msg = f"unknown TI tool: {tool!r}"
            raise ToolError(msg, transient=False)

        ioc = args.get("ioc")
        if not isinstance(ioc, str):
            msg = f"missing or non-string 'ioc' arg for tool {tool!r}"
            raise ToolError(msg, transient=False)

        record = dataset.get(ioc)
        if record is None:
            msg = f"no TI fixture record for IOC {ioc!r} via {tool}"
            raise ToolError(msg, transient=False)

        return record


_TI_TOOLS: tuple[InvestigationTool, ...] = (
    InvestigationTool(
        name="multi_source_reputation",
        description=(
            "Query multi-source reputation for an IOC (IP, domain, or hash): "
            "score, classification, and known-bad tags from aggregated threat feeds."
        ),
        args_schema=_IOC_ARG,
    ),
    InvestigationTool(
        name="passive_dns",
        description=(
            "Look up passive-DNS records for an IOC: historical resolutions, "
            "associated hostnames, and first/last-seen timestamps."
        ),
        args_schema=_IOC_ARG,
    ),
    InvestigationTool(
        name="threat_feed",
        description=(
            "Check one or more curated threat feeds for an IOC: malware family, "
            "tags, and verdict (malicious / benign / unknown)."
        ),
        args_schema=_IOC_ARG,
    ),
)


class TIToolRegistry:
    """An immutable lookup of the three read-only TI tools by name.

    Mirrors ``ToolRegistry`` from ``triage.tools.registry`` at TI scale.
    The three tools are not in the primary ``ToolRegistry`` — they are exposed
    exclusively through the TI mini-loop (RFC-0002 §Decision: delegation is
    additive; TI tools never appear in the primary loop's tool surface).
    """

    def __init__(self, tools: tuple[InvestigationTool, ...] = _TI_TOOLS) -> None:
        """Index the TI tools by name (defaults to the shipped three)."""
        self._tools: dict[str, InvestigationTool] = {tool.name: tool for tool in tools}

    def names(self) -> list[str]:
        """Return the registered TI tool names."""
        return list(self._tools)

    def get(self, name: str) -> Tool:
        """Return the TI tool by name.

        Raises:
            KeyError: ``name`` is not a registered TI tool.
        """
        return self._tools[name]

    def specs(self) -> list[dict[str, object]]:
        """Return the prompt-facing specs (name, description, args schema)."""
        return [
            {"name": t.name, "description": t.description, "args_schema": t.args_schema}
            for t in self._tools.values()
        ]
