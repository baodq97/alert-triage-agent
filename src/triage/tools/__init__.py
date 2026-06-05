"""The tools package — read-only investigation Tools, Response Actions, sources.

Public seam consumed by the executor and the post-Verdict gate flow:

* ``Tool`` / ``DataSource`` Protocols and the ``execute_tool`` retry runner
  (``base``);
* ``ToolRegistry`` — the four read-only investigation tools, by construction the
  only callable set mid-loop (``registry``);
* ``block_user`` + ``block_user_target`` — the post-gate Response Action and its
  target-invariant seam (``actions``);
* ``FixtureDataSource`` — the bundled benign Fixture World (``fixture_source``).
"""

from triage.tools.actions import (
    BLOCK_USER_TARGET_KEY,
    block_user,
    block_user_target,
)
from triage.tools.base import (
    DataSource,
    InvestigationTool,
    Tool,
    execute_tool,
)
from triage.tools.fixture_source import FixtureDataSource
from triage.tools.registry import ToolRegistry

__all__ = [
    "BLOCK_USER_TARGET_KEY",
    "DataSource",
    "FixtureDataSource",
    "InvestigationTool",
    "Tool",
    "ToolRegistry",
    "block_user",
    "block_user_target",
    "execute_tool",
]
