"""Tests for the planner (RFC-0001 §Core loop / planner; ADR-0005).

Structural assertions only — "plans sensibly" is wave-3 eval territory:

* one structured LLM call produces a valid ``InvestigationPlan``;
* the ``llm_call`` (purpose ``"plan"``) and ``plan_created`` events fire in that
  order, carrying the Completion metadata and the dumped steps;
* the rendered prompt delimits the untrusted alert payload in an
  ``<alert_payload>`` block (ADR-0005 property 1) and is event-type-agnostic;
* Recall, when provided, renders its own labeled untrusted block with source
  run-id + confidence; when absent, no recall block renders (the wave-1 seam);
* an ``LLMError`` propagates — the planner never swallows it, and emits nothing.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from triage.errors import LLMError
from triage.llm import FakeLLM
from triage.models import Alert, InvestigationPlan
from triage.planner import Planner
from triage.tools import ToolRegistry

if TYPE_CHECKING:
    from collections.abc import Mapping


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


_PLAN_JSON = json.dumps(
    {
        "steps": [
            {
                "tool": "lookup_user",
                "args": {"entity": "alice"},
                "rationale": "Confirm the account status of the flagged user.",
            },
        ],
    },
)


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-1",
        "timestamp": "2026-06-05T00:00:00Z",
        "source": "edr",
        "severity_hint": "medium",
        "event_type": "data_exfiltration",
        "description": "Large outbound transfer from alice's host.",
        "entities": {"user": "alice", "ip": "10.0.0.9"},
        "context": {"bytes": 5_000_000},
    }
    return Alert.model_validate({**base, **overrides})


def _specs() -> list[dict[str, object]]:
    return ToolRegistry().specs()


def test_plan_returns_valid_investigation_plan() -> None:
    planner = Planner(llm=FakeLLM([_PLAN_JSON]), journal=RecordingJournal(), tool_specs=_specs())

    plan = planner.plan(_alert())

    assert isinstance(plan, InvestigationPlan)
    assert plan.steps[0].tool == "lookup_user"


def test_plan_emits_llm_call_then_plan_created_in_order() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_PLAN_JSON], model="m1", tokens=42)
    planner = Planner(llm=llm, journal=journal, tool_specs=_specs())

    plan = planner.plan(_alert())

    names = [event for event, _, _ in journal.events]
    assert names == ["llm_call", "plan_created"]

    llm_call_payload = journal.events[0][1]
    assert llm_call_payload["purpose"] == "plan"
    assert llm_call_payload["model"] == "m1"
    assert llm_call_payload["tokens"] == 42
    assert "prompt_hash" in llm_call_payload
    assert "latency_ms" in llm_call_payload

    plan_created_payload = journal.events[1][1]
    assert plan_created_payload["steps"] == plan.model_dump()["steps"]


def test_rendered_prompt_delimits_untrusted_alert_payload() -> None:
    llm = FakeLLM([_PLAN_JSON])
    planner = Planner(llm=llm, journal=RecordingJournal(), tool_specs=_specs())

    planner.plan(_alert())

    rendered = "\n".join(message["content"] for message in llm.last_messages)
    assert "<alert_payload>" in rendered
    assert "</alert_payload>" in rendered
    # The full envelope (incl. the injection-vector ``description``) lands inside
    # the labeled block, not interpolated into the instructions.
    assert "Large outbound transfer from alice's host." in rendered
    # Event-type-agnostic: the template never branches on the event type value.
    assert "data_exfiltration" in rendered


def test_rendered_prompt_presents_the_available_tools() -> None:
    llm = FakeLLM([_PLAN_JSON])
    planner = Planner(llm=llm, journal=RecordingJournal(), tool_specs=_specs())

    planner.plan(_alert())

    rendered = "\n".join(message["content"] for message in llm.last_messages)
    for name in ToolRegistry().names():
        assert name in rendered


def test_no_recall_renders_no_recall_block() -> None:
    llm = FakeLLM([_PLAN_JSON])
    planner = Planner(llm=llm, journal=RecordingJournal(), tool_specs=_specs())

    planner.plan(_alert())

    rendered = "\n".join(message["content"] for message in llm.last_messages)
    assert "<recalled_memory>" not in rendered


def test_recall_renders_labeled_untrusted_block_with_run_id_and_confidence() -> None:
    llm = FakeLLM([_PLAN_JSON])
    planner = Planner(llm=llm, journal=RecordingJournal(), tool_specs=_specs())
    recall = [
        {
            "run_id": "ALT-0-run",
            "confidence": 0.8,
            "content": "10.0.0.9 was a repeat offender last week.",
        },
    ]

    planner.plan(_alert(), recall=recall)

    rendered = "\n".join(message["content"] for message in llm.last_messages)
    assert "<recalled_memory>" in rendered
    assert "</recalled_memory>" in rendered
    assert "ALT-0-run" in rendered
    assert "0.8" in rendered
    assert "10.0.0.9 was a repeat offender last week." in rendered


def test_empty_recall_renders_no_recall_block() -> None:
    llm = FakeLLM([_PLAN_JSON])
    planner = Planner(llm=llm, journal=RecordingJournal(), tool_specs=_specs())

    planner.plan(_alert(), recall=[])

    rendered = "\n".join(message["content"] for message in llm.last_messages)
    assert "<recalled_memory>" not in rendered


def test_render_falls_back_to_single_message_when_sentinel_absent() -> None:
    """If the template has no {{END_OF_STABLE}}, a single message is returned."""
    llm = FakeLLM([_PLAN_JSON])
    planner = Planner(llm=llm, journal=RecordingJournal(), tool_specs=_specs())
    planner._template = "No sentinel here. {{TOOLS}} {{ALERT_PAYLOAD}} {{RECALL}}"  # noqa: SLF001

    planner.plan(_alert())

    assert len(llm.last_messages) == 1


def test_llm_error_propagates_and_emits_nothing_except_repair() -> None:
    """On a double-malformed plan reply (repair also fails), only llm_repair fires.

    The planner emits llm_repair when the repair re-prompt is attempted, but never
    emits llm_call (no Completion exists) and never emits plan_created.  The
    LLMError still propagates (the caller degrades to a partial verdict).
    """
    journal = RecordingJournal()
    # A malformed reply, repeated, exhausts the one repair attempt -> LLMError.
    planner = Planner(
        llm=FakeLLM(["not json", "still not json"]),
        journal=journal,
        tool_specs=_specs(),
    )

    with pytest.raises(LLMError):
        planner.plan(_alert())

    names = [event for event, _, _ in journal.events]
    # The repair was attempted: llm_repair emitted; llm_call and plan_created NOT.
    assert "llm_repair" in names
    assert "llm_call" not in names
    assert "plan_created" not in names


def test_repair_fires_llm_repair_event() -> None:
    """On a malformed first reply, the planner emits llm_repair before llm_call."""
    journal = RecordingJournal()
    planner = Planner(
        llm=FakeLLM(["not json", _PLAN_JSON]),
        journal=journal,
        tool_specs=_specs(),
    )

    planner.plan(_alert())

    names = [event for event, _, _ in journal.events]
    assert "llm_repair" in names
    assert names.index("llm_repair") < names.index("llm_call")
    repair_payload = next(p for e, p, _ in journal.events if e == "llm_repair")
    assert repair_payload["purpose"] == "plan"
    assert "error" in repair_payload
