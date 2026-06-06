"""Tests pinning the ``{{END_OF_STABLE}}`` sentinel invariant in prompt files (F3).

Every prompt template that is split into two messages MUST contain exactly one
occurrence of the sentinel string ``{{END_OF_STABLE}}\n`` (followed immediately by
a newline), and the corresponding renderer MUST return exactly two messages with:

* the alert/task payload in the DYNAMIC message (planner: DYNAMIC; reasoner and
  verdict: DYNAMIC);
* the STABLE message never containing the per-run payload.

These tests load the REAL prompt files and instantiate the REAL renderers with
canned FakeLLM output, so they catch prompt-file edits that break the invariant
without running any network call.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from triage.executor import Executor
from triage.llm import FakeLLM
from triage.models import Alert, InvestigationPlan, PlanStep, ToolResult
from triage.planner import Planner
from triage.tools import FixtureDataSource, ToolRegistry
from triage.verdict import VerdictSynthesizer

_PROMPTS_DIR = Path(__file__).resolve().parents[1] / "prompts"
_SENTINEL = "{{END_OF_STABLE}}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-sentinel-test",
        "timestamp": "2026-06-06T00:00:00Z",
        "source": "test",
        "severity_hint": "low",
        "event_type": "sentinel_test",
        "description": "Sentinel invariant test alert.",
        "entities": {"user": "testuser"},
        "context": {},
    }
    return Alert.model_validate({**base, **overrides})


class _RecordingJournal:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any], str]] = []

    def emit(self, event: str, payload: Any, *, agent: str = "triage") -> None:
        self.events.append((event, dict(payload), agent))


# ---------------------------------------------------------------------------
# Sentinel structure tests (file-level, no renderer)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["planner.md", "reasoner.md", "verdict.md"])
def test_prompt_file_contains_exactly_one_sentinel(name: str) -> None:
    """Each prompt file has exactly one ``{{END_OF_STABLE}}`` occurrence."""
    text = (_PROMPTS_DIR / name).read_text(encoding="utf-8")
    count = text.count(_SENTINEL)
    assert count == 1, f"{name}: expected 1 sentinel, found {count}"


@pytest.mark.parametrize("name", ["planner.md", "reasoner.md", "verdict.md"])
def test_prompt_sentinel_is_followed_by_newline(name: str) -> None:
    """``{{END_OF_STABLE}}`` is immediately followed by ``\\n`` in every prompt."""
    text = (_PROMPTS_DIR / name).read_text(encoding="utf-8")
    idx = text.index(_SENTINEL)
    # The sentinel must be the last thing on its line; the char right after is \\n.
    assert text[idx + len(_SENTINEL)] == "\n", (
        f"{name}: sentinel not followed by newline at position {idx}"
    )


# ---------------------------------------------------------------------------
# Renderer split tests (two messages, payload in the right part)
# ---------------------------------------------------------------------------


def test_planner_renderer_produces_two_messages_with_alert_in_dynamic() -> None:
    """Planner splits on the sentinel; the alert payload lands in the dynamic message."""
    planner_json = json.dumps(
        {"steps": [{"tool": "lookup_user", "args": {"entity": "testuser"}, "rationale": "check"}]}
    )
    llm = FakeLLM([planner_json])
    planner = Planner(
        llm=llm,
        journal=_RecordingJournal(),
        tool_specs=[{"name": "lookup_user", "description": "x", "risk_tier": "read_only"}],
    )
    planner.plan(_alert())

    messages = llm.last_messages
    # Sentinel split always yields exactly 2 messages when the sentinel is present.
    assert len(messages) == 2, f"expected 2 messages, got {len(messages)}"
    # Alert payload (description, entities) is in the DYNAMIC (second) message.
    dynamic = messages[1]["content"]
    assert "Sentinel invariant test alert." in dynamic
    # The STABLE (first) message must NOT contain per-run alert data.
    stable = messages[0]["content"]
    assert "Sentinel invariant test alert." not in stable


def test_reasoner_renderer_produces_two_messages_with_alert_in_dynamic() -> None:
    """Executor (reasoner) splits on the sentinel; alert payload lands in dynamic."""
    conclude_json = json.dumps({"decision": "conclude", "rationale": "done"})
    registry = ToolRegistry()
    source = FixtureDataSource()

    # With a non-empty plan the executor calls the reasoner after the tool step.
    llm2 = FakeLLM([conclude_json])
    executor2 = Executor(
        llm=llm2,
        journal=_RecordingJournal(),
        registry=registry,
        source=source,
        max_steps=2,
    )
    plan2 = InvestigationPlan(
        steps=[PlanStep(tool="lookup_user", args={"entity": "testuser"}, rationale="r")]
    )
    executor2.run(_alert(), plan2)

    messages = llm2.last_messages
    assert len(messages) == 2, f"expected 2 messages, got {len(messages)}"
    # In the reasoner prompt, the alert payload appears BEFORE the sentinel — it is
    # part of the stable (cacheable) context so repeated reasoner calls within one
    # run do not re-send the same per-alert data as a new dynamic payload.
    stable = messages[0]["content"]
    assert "Sentinel invariant test alert." in stable
    dynamic = messages[1]["content"]
    # The dynamic part carries per-step data (observations, remaining steps).
    assert "observation" in dynamic or "remaining" in dynamic.lower()
    assert "Sentinel invariant test alert." not in dynamic


def test_verdict_renderer_produces_two_messages_with_alert_in_stable() -> None:
    """VerdictSynthesizer splits on the sentinel; alert payload lands in stable message.

    The verdict prompt places the alert payload BEFORE the sentinel so the
    instructions + alert context are the stable (cacheable) prefix; only the
    per-run observations and findings are in the dynamic part.
    """
    verdict_json = json.dumps(
        {
            "severity": "low",
            "findings": [],
            "recommended_actions": [],
            "confidence": 0.5,
        }
    )
    llm = FakeLLM([verdict_json])
    synth = VerdictSynthesizer(llm=llm, journal=_RecordingJournal())
    synth.synthesize(
        _alert(),
        observations=[ToolResult(tool="lookup_user", ok=True, data={"status": "ok"})],
    )

    messages = llm.last_messages
    assert len(messages) == 2, f"expected 2 messages, got {len(messages)}"
    # Alert payload is in the STABLE (first) message.
    stable = messages[0]["content"]
    assert "Sentinel invariant test alert." in stable
    dynamic = messages[1]["content"]
    assert "Sentinel invariant test alert." not in dynamic
