"""Tests for the tools package (RFC-0001 §Tools; triage-conventions §Reliability).

Pinned behaviour, all deterministic and key-free:

* the ``Tool`` / ``DataSource`` Protocols and the planner-facing spec seam;
* the ``execute_tool`` retry policy via a scriptable failing source (transient ->
  one retry / 2 attempts; permanent -> none) with ``_backoff`` monkeypatched so
  backoff is observed without waiting, and per-attempt callbacks for observability;
* the registry exposes EXACTLY the four read-only tools and ``block_user`` is
  unreachable through it (structural soundness of ``gate_before_high_risk``);
* the Fixture World resolves every Entity both shipped alerts reference and
  returns a not-found permanent error for unknowns;
* the ``block_user`` mock action and its target-invariant seam.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from triage.errors import ToolError
from triage.models import Action, Alert, ToolResult
from triage.tools import (
    BLOCK_USER_TARGET_KEY,
    DataSource,
    FixtureDataSource,
    InvestigationTool,
    Tool,
    ToolRegistry,
    base,
    block_user,
    block_user_target,
    execute_tool,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_ALERTS_DIR = Path(__file__).parent.parent / "alerts"
_INVESTIGATION_TOOLS = {"lookup_user", "query_logs", "check_reputation", "get_asset_info"}


@pytest.fixture
def backoffs(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Replace the real backoff with a recorder so retries never actually wait."""
    calls: list[int] = []
    monkeypatch.setattr(base, "_backoff", lambda: calls.append(1))
    return calls


class _ScriptedSource:
    """A DataSource that replays a script of outcomes for the retry tests.

    Each script entry is either a ``ToolError`` to raise or a dict to return,
    popped in order — so a ``[transient, success]`` script proves the one retry.
    """

    def __init__(self, script: list[ToolError | dict[str, Any]]) -> None:
        self._script = list(script)
        self.calls = 0

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:  # noqa: ARG002
        self.calls += 1
        outcome = self._script.pop(0)
        if isinstance(outcome, ToolError):
            raise outcome
        return outcome


def _tool(name: str = "lookup_user") -> InvestigationTool:
    return InvestigationTool(name=name, description="d", args_schema={"type": "object"})


# --- Protocols + InvestigationTool -----------------------------------------


def test_investigation_tool_satisfies_the_tool_protocol() -> None:
    assert isinstance(_tool(), Tool)


def test_fixture_source_satisfies_the_datasource_protocol() -> None:
    assert isinstance(FixtureDataSource(), DataSource)


def test_a_plain_object_is_neither_tool_nor_datasource() -> None:
    assert not isinstance(object(), Tool)
    assert not isinstance(object(), DataSource)


def test_investigation_tools_share_the_read_only_risk_tier() -> None:
    # RFC-0001 §Tools lists risk_tier on Tool; investigation tools are read-only.
    assert _tool().risk_tier == "read_only"


def test_execute_delegates_to_source_under_the_tool_name() -> None:
    source = _ScriptedSource([{"ok": 1}])
    assert _tool("query_logs").execute({"entity": "x"}, source) == {"ok": 1}


# --- execute_tool retry policy ---------------------------------------------


def test_success_on_first_attempt_returns_ok_result() -> None:
    result = execute_tool(_tool(), {"entity": "x"}, _ScriptedSource([{"role": "dev"}]))
    assert result == ToolResult(tool="lookup_user", ok=True, data={"role": "dev"})


def test_transient_failure_retries_exactly_once_then_succeeds(backoffs: list[int]) -> None:
    source = _ScriptedSource([ToolError("timeout", transient=True), {"role": "dev"}])
    result = execute_tool(_tool(), {"entity": "x"}, source)
    assert source.calls == 2
    assert result.ok is True
    assert backoffs == [1]


def test_transient_failure_twice_gives_up_after_two_attempts(backoffs: list[int]) -> None:
    source = _ScriptedSource(
        [ToolError("timeout", transient=True), ToolError("timeout", transient=True)],
    )
    result = execute_tool(_tool(), {"entity": "x"}, source)
    assert source.calls == 2
    assert result.ok is False
    assert result.error == "timeout"
    # One backoff between the two attempts; none after the final give-up.
    assert backoffs == [1]


def test_permanent_failure_is_not_retried(backoffs: list[int]) -> None:
    source = _ScriptedSource([ToolError("not found", transient=False)])
    result = execute_tool(_tool(), {"entity": "x"}, source)
    assert source.calls == 1
    assert result == ToolResult(tool="lookup_user", ok=False, error="not found")
    assert backoffs == []


def test_callbacks_fire_per_attempt_for_journal_observability(backoffs: list[int]) -> None:
    source = _ScriptedSource([ToolError("timeout", transient=True), {"role": "dev"}])
    before: list[int] = []
    after: list[tuple[int, bool]] = []
    execute_tool(
        _tool(),
        {"entity": "x"},
        source,
        before_attempt=before.append,
        after_attempt=lambda n, r: after.append((n, r.ok)),
    )
    assert backoffs == [1]
    # Each attempt is journaled — the failed transient attempt included.
    assert before == [1, 2]
    assert after == [(1, False), (2, True)]


def test_execute_tool_runs_without_callbacks() -> None:
    result = execute_tool(_tool(), {"entity": "x"}, _ScriptedSource([{"a": 1}]))
    assert result.ok is True


def test_backoff_sleeps_the_configured_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    # The real _backoff waits _BACKOFF_SECONDS; patch time.sleep so it returns fast.
    slept: list[float] = []
    monkeypatch.setattr(base.time, "sleep", slept.append)
    base._backoff()  # noqa: SLF001 — exercising the module-level backoff seam directly.
    assert slept == [base._BACKOFF_SECONDS]  # noqa: SLF001 — same module-private seam.


# --- ToolRegistry: read-only by construction -------------------------------


def test_registry_exposes_exactly_the_four_investigation_tools() -> None:
    assert set(ToolRegistry().names()) == _INVESTIGATION_TOOLS


def test_registry_returns_each_investigation_tool() -> None:
    registry = ToolRegistry()
    for name in _INVESTIGATION_TOOLS:
        assert registry.get(name).name == name


def test_block_user_is_unreachable_through_the_registry() -> None:
    # Structural soundness of gate_before_high_risk: no Response Action mid-loop.
    with pytest.raises(KeyError):
        ToolRegistry().get("block_user")


def test_registry_specs_carry_name_description_and_schema() -> None:
    specs = ToolRegistry().specs()
    assert {s["name"] for s in specs} == _INVESTIGATION_TOOLS
    assert all(s["description"] and s["args_schema"] for s in specs)


def test_registry_accepts_a_custom_tool_set() -> None:
    registry = ToolRegistry((_tool("only_one"),))
    assert registry.names() == ["only_one"]


# --- Fixture World ----------------------------------------------------------


def _alert_entities(filename: str) -> list[str]:
    payload = json.loads((_ALERTS_DIR / filename).read_text(encoding="utf-8"))
    return list(payload["entities"].values())


def test_fixture_world_resolves_a_known_user() -> None:
    source = FixtureDataSource()
    record = source.fetch("lookup_user", {"entity": "svc-deploy-prod"})
    assert record["entity"] == "svc-deploy-prod"
    assert record["kind"] == "service_account"


@pytest.mark.parametrize(
    ("alert_file", "tool", "entity"),
    [
        ("ALT-2026-04-7821-data-exfiltration.json", "lookup_user", "svc-deploy-prod"),
        ("ALT-2026-04-7821-data-exfiltration.json", "query_logs", "10.200.3.47"),
        ("ALT-2026-04-7821-data-exfiltration.json", "check_reputation", "10.200.3.47"),
        ("ALT-2026-04-7821-data-exfiltration.json", "get_asset_info", "user-management-api"),
        ("ALT-2026-04-7835-privilege-escalation.json", "lookup_user", "dev-intern-jpark"),
        ("ALT-2026-04-7835-privilege-escalation.json", "query_logs", "203.0.113.22"),
        ("ALT-2026-04-7835-privilege-escalation.json", "check_reputation", "203.0.113.22"),
    ],
)
def test_fixture_world_gives_each_alert_meaningful_results(
    alert_file: str,
    tool: str,
    entity: str,
) -> None:
    # Same-entity-same-story: every Entity the shipped alerts reference resolves.
    assert entity in _alert_entities(alert_file)
    record = FixtureDataSource().fetch(tool, {"entity": entity})
    assert record["entity"] == entity


def test_unknown_entity_raises_permanent_not_found() -> None:
    with pytest.raises(ToolError) as exc:
        FixtureDataSource().fetch("lookup_user", {"entity": "ghost"})
    assert exc.value.transient is False


def test_missing_entity_arg_raises_permanent_not_found() -> None:
    with pytest.raises(ToolError) as exc:
        FixtureDataSource().fetch("lookup_user", {})
    assert exc.value.transient is False


def test_unknown_tool_raises_permanent_schema_error() -> None:
    with pytest.raises(ToolError) as exc:
        FixtureDataSource().fetch("delete_everything", {"entity": "x"})
    assert exc.value.transient is False


def test_unknown_entity_surfaces_as_not_ok_observation_not_a_crash() -> None:
    # End-to-end through the seam: a not-found never escapes as an exception.
    result = execute_tool(
        ToolRegistry().get("lookup_user"),
        {"entity": "ghost"},
        FixtureDataSource(),
    )
    assert result.ok is False
    assert result.tool == "lookup_user"


# --- block_user Response Action + target invariant seam --------------------


def test_block_user_mock_records_the_blocked_target() -> None:
    action = Action(name="block_user", params={BLOCK_USER_TARGET_KEY: "svc-deploy-prod"})
    assert block_user(action) == {
        "action": "block_user",
        "target": "svc-deploy-prod",
        "status": "blocked",
        "mock": True,
    }


def test_block_user_target_reads_the_target_entity() -> None:
    action = Action(name="block_user", params={BLOCK_USER_TARGET_KEY: "dev-intern-jpark"})
    assert block_user_target(action) == "dev-intern-jpark"


def test_block_user_target_is_none_when_absent() -> None:
    assert block_user_target(Action(name="block_user")) is None


def test_block_user_target_is_none_when_not_a_string() -> None:
    action = Action(name="block_user", params={BLOCK_USER_TARGET_KEY: 123})
    assert block_user_target(action) is None


def test_target_invariant_seam_supports_gate_validation() -> None:
    # The seam the gate/core flow consumes: target must be an alert Entity value.
    alert = Alert.model_validate(
        json.loads(
            (_ALERTS_DIR / "ALT-2026-04-7821-data-exfiltration.json").read_text(encoding="utf-8"),
        ),
    )
    valid = Action(name="block_user", params={BLOCK_USER_TARGET_KEY: "svc-deploy-prod"})
    invalid = Action(name="block_user", params={BLOCK_USER_TARGET_KEY: "someone-else"})
    assert block_user_target(valid) in alert.entities.values()
    assert block_user_target(invalid) not in alert.entities.values()
