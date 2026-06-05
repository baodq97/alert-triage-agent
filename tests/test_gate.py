"""Tests for the Risk Policy and the Approval Gate (RFC-0001 HITL gate).

Structural / deterministic assertions only — the gate is enforced in code, never
delegated to LLM judgment:

* ``RiskPolicy`` classifies on exact ``Action.name``; an unlisted name defaults
  to ``high_risk``; a missing / malformed / wrong-shape policy file -> ConfigError;
  the ``RISK_POLICY_PATH`` env var overrides the default location.
* ONE gate per Run, after the Verdict: all High-risk Actions are batched into a
  single ``gate_requested`` (before asking) followed by a single ``gate_decision``
  (after) — in that order. The gate returns the Gate Decision; it never executes.
* Zero-touch: no High-risk Action -> ``None`` and an empty Journal (no gate
  events at all).
* ``AutoGate`` is default-deny but configurable so both branches are covered;
  ``CLIGate`` reads the decision off monkeypatched ``input`` (default-deny on any
  unrecognized reply), so the interactive path is fully exercised without pragmas.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from triage.errors import ConfigError
from triage.gate import ApprovalGate, AutoGate, CLIGate, RiskPolicy
from triage.models import Action, GateDecision

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class RecordingJournal:
    """A Journal that captures every emitted event for in-order assertions."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any], str]] = []

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        self.events.append((event, dict(payload), agent))


def _policy_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "risk_policy.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _high_risk_policy(tmp_path: Path) -> RiskPolicy:
    path = _policy_file(tmp_path, "actions:\n  block_user: high_risk\n  notify: low_risk\n")
    return RiskPolicy(path)


# --------------------------------------------------------------------------- #
# RiskPolicy                                                                   #
# --------------------------------------------------------------------------- #


def test_ships_a_default_policy_classifying_block_user_high_risk() -> None:
    # The shipped config/risk_policy.yaml loads and classifies the one action.
    policy = RiskPolicy()
    assert policy.is_high_risk(Action(name="block_user")) is True


def test_listed_low_risk_action_is_not_high_risk(tmp_path: Path) -> None:
    policy = _high_risk_policy(tmp_path)
    assert policy.is_high_risk(Action(name="notify")) is False


def test_listed_high_risk_action_is_high_risk(tmp_path: Path) -> None:
    policy = _high_risk_policy(tmp_path)
    assert policy.is_high_risk(Action(name="block_user")) is True


def test_unlisted_action_defaults_to_high_risk(tmp_path: Path) -> None:
    policy = _high_risk_policy(tmp_path)
    # Unknown name -> the safe default, so a new action cannot skip the gate.
    assert policy.is_high_risk(Action(name="rm_rf_everything")) is True


def test_high_risk_filters_the_batch_preserving_order(tmp_path: Path) -> None:
    policy = _high_risk_policy(tmp_path)
    actions = [
        Action(name="notify"),
        Action(name="block_user", params={"user": "alice"}),
        Action(name="rotate_key"),
    ]
    batch = policy.high_risk(actions)
    assert [a.name for a in batch] == ["block_user", "rotate_key"]


def test_missing_policy_file_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        RiskPolicy(tmp_path / "does_not_exist.yaml")


def test_malformed_yaml_raises_config_error(tmp_path: Path) -> None:
    path = _policy_file(tmp_path, "actions: [unclosed\n")
    with pytest.raises(ConfigError):
        RiskPolicy(path)


def test_non_mapping_policy_raises_config_error(tmp_path: Path) -> None:
    path = _policy_file(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ConfigError):
        RiskPolicy(path)


def test_missing_actions_key_raises_config_error(tmp_path: Path) -> None:
    path = _policy_file(tmp_path, "other: value\n")
    with pytest.raises(ConfigError):
        RiskPolicy(path)


def test_actions_not_a_mapping_raises_config_error(tmp_path: Path) -> None:
    path = _policy_file(tmp_path, "actions:\n  - block_user\n")
    with pytest.raises(ConfigError):
        RiskPolicy(path)


def test_unknown_tier_value_raises_config_error(tmp_path: Path) -> None:
    path = _policy_file(tmp_path, "actions:\n  block_user: catastrophic\n")
    with pytest.raises(ConfigError):
        RiskPolicy(path)


def test_non_string_tier_value_raises_config_error(tmp_path: Path) -> None:
    path = _policy_file(tmp_path, "actions:\n  block_user: 7\n")
    with pytest.raises(ConfigError):
        RiskPolicy(path)


def test_env_override_selects_the_policy_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _policy_file(tmp_path, "actions:\n  custom_action: high_risk\n")
    monkeypatch.setenv("RISK_POLICY_PATH", str(path))
    policy = RiskPolicy()
    assert policy.is_high_risk(Action(name="custom_action")) is True
    # An action from the default file is now only high-risk via the default rule.
    assert policy.is_high_risk(Action(name="notify")) is True


# --------------------------------------------------------------------------- #
# AutoGate                                                                     #
# --------------------------------------------------------------------------- #


def test_auto_gate_satisfies_the_approval_gate_protocol() -> None:
    gate: ApprovalGate = AutoGate(RecordingJournal())
    assert isinstance(gate, ApprovalGate)


def test_auto_gate_zero_touch_returns_none_and_emits_nothing(tmp_path: Path) -> None:
    journal = RecordingJournal()
    gate = AutoGate(journal)
    policy = _high_risk_policy(tmp_path)

    decision = gate.request([Action(name="notify")], policy)

    assert decision is None
    assert journal.events == []


def test_auto_gate_no_actions_at_all_is_zero_touch(tmp_path: Path) -> None:
    journal = RecordingJournal()
    gate = AutoGate(journal)
    policy = _high_risk_policy(tmp_path)

    assert gate.request([], policy) is None
    assert journal.events == []


def test_auto_gate_default_denies_and_emits_request_then_decision(tmp_path: Path) -> None:
    journal = RecordingJournal()
    gate = AutoGate(journal)  # default-deny
    policy = _high_risk_policy(tmp_path)

    decision = gate.request([Action(name="block_user", params={"user": "alice"})], policy)

    assert decision == GateDecision(decision="denied", by="auto")
    names = [event for event, _, _ in journal.events]
    assert names == ["gate_requested", "gate_decision"]


def test_auto_gate_can_approve_when_configured(tmp_path: Path) -> None:
    journal = RecordingJournal()
    gate = AutoGate(journal, approve=True)
    policy = _high_risk_policy(tmp_path)

    decision = gate.request([Action(name="block_user", params={"user": "alice"})], policy)

    assert decision == GateDecision(decision="approved", by="auto")


def test_auto_gate_batches_all_high_risk_into_one_request(tmp_path: Path) -> None:
    journal = RecordingJournal()
    gate = AutoGate(journal)
    policy = _high_risk_policy(tmp_path)
    actions = [
        Action(name="notify"),
        Action(name="block_user", params={"user": "alice"}),
        Action(name="rotate_key"),
    ]

    gate.request(actions, policy)

    requests = [payload for event, payload, _ in journal.events if event == "gate_requested"]
    decisions = [payload for event, payload, _ in journal.events if event == "gate_decision"]
    assert len(requests) == 1
    assert len(decisions) == 1
    # Both high-risk actions batched; the low-risk one excluded.
    batched = [a["name"] for a in requests[0]["actions"]]
    assert batched == ["block_user", "rotate_key"]
    assert requests[0]["risk"] == "high_risk"


def test_auto_gate_decision_payload_carries_decision_and_by(tmp_path: Path) -> None:
    journal = RecordingJournal()
    gate = AutoGate(journal)
    policy = _high_risk_policy(tmp_path)

    gate.request([Action(name="block_user")], policy)

    decision_payload = next(p for e, p, _ in journal.events if e == "gate_decision")
    assert decision_payload["decision"] == "denied"
    assert decision_payload["by"] == "auto"


# --------------------------------------------------------------------------- #
# CLIGate                                                                      #
# --------------------------------------------------------------------------- #


def test_cli_gate_satisfies_the_approval_gate_protocol() -> None:
    gate: ApprovalGate = CLIGate(RecordingJournal())
    assert isinstance(gate, ApprovalGate)


def test_cli_gate_zero_touch_returns_none_and_emits_nothing(tmp_path: Path) -> None:
    journal = RecordingJournal()
    gate = CLIGate(journal)
    policy = _high_risk_policy(tmp_path)

    assert gate.request([Action(name="notify")], policy) is None
    assert journal.events == []


def test_cli_gate_approves_on_yes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal = RecordingJournal()
    gate = CLIGate(journal)
    policy = _high_risk_policy(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")

    decision = gate.request([Action(name="block_user")], policy)

    assert decision == GateDecision(decision="approved", by="cli")
    names = [event for event, _, _ in journal.events]
    assert names == ["gate_requested", "gate_decision"]


def test_cli_gate_denies_on_no(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal = RecordingJournal()
    gate = CLIGate(journal)
    policy = _high_risk_policy(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")

    decision = gate.request([Action(name="block_user")], policy)

    assert decision == GateDecision(decision="denied", by="cli")


def test_cli_gate_default_denies_on_unrecognized_reply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = RecordingJournal()
    gate = CLIGate(journal)
    policy = _high_risk_policy(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "maybe later")

    decision = gate.request([Action(name="block_user")], policy)

    # Default-deny mirrors AutoGate: anything not an explicit yes is denied.
    assert decision == GateDecision(decision="denied", by="cli")


def test_cli_gate_accepts_whitespace_and_case_insensitive_yes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = RecordingJournal()
    gate = CLIGate(journal)
    policy = _high_risk_policy(tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "  YES  ")

    decision = gate.request([Action(name="block_user")], policy)

    assert decision == GateDecision(decision="approved", by="cli")


def test_a_plain_object_is_not_an_approval_gate() -> None:
    assert not isinstance(object(), ApprovalGate)
