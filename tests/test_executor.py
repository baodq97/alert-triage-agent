"""Tests for the executor — the ReAct loop (RFC-0001 §Core loop; ADR-0005).

Structural assertions only — "reasons sensibly" is wave-3 eval territory:

* the loop terminates and gathers Observations as a trajectory;
* journal events fire in order with a shared ``step`` + ``attempt`` on the
  ``tool_called`` / ``tool_result`` pair, and ``llm_call`` (purpose ``"reason"``)
  per Reasoner call;
* the ``conclude`` / ``continue`` / ``revise_plan`` branches behave as designed,
  ``revise_plan`` emitting ``plan_revised`` and replacing the remaining plan;
* the ``MAX_STEPS`` guard stops the run with ``terminated_reason="max_steps"``;
* the repeat-call guard never re-executes an identical call and forces a course
  change without polluting the evidence trajectory;
* a tool error and a hallucinated tool name both arrive as ``ok=False``
  Observations — the run never crashes;
* an ``LLMError`` mid-loop stops with ``terminated_reason="error"`` and emits no
  ``llm_call`` on that path.

The executor never calls the planner: tests build the ``InvestigationPlan``
directly and script only Reasoner replies on the ``FakeLLM``. A tiny fake
``DataSource`` drives the tool success / error branches deterministically.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from triage.errors import ToolError
from triage.executor import (
    _OBSERVATION_DATA_MAX_CHARS,
    ExecutionResult,
    Executor,
    ObservationEntry,
)
from triage.llm import FakeLLM
from triage.models import Alert, InvestigationPlan, PlanStep, ToolResult
from triage.tools import ToolRegistry

if TYPE_CHECKING:
    from collections.abc import Mapping

    import pytest


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

    def names(self) -> list[str]:
        return [event for event, _, _ in self.events]


class FixtureSource:
    """A tiny deterministic DataSource: known entities resolve, others fail.

    ``raise_for`` maps an entity value to the ``ToolError`` it should raise, so a
    test drives the tool-error-as-observation branch (transient and permanent)
    without the full Fixture World.
    """

    def __init__(self, raise_for: dict[str, ToolError] | None = None) -> None:
        self._raise_for = raise_for or {}

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        entity = args.get("entity")
        if isinstance(entity, str) and entity in self._raise_for:
            raise self._raise_for[entity]
        return {"tool": tool, "entity": entity, "status": "benign"}


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


def _step(tool: str = "lookup_user", entity: str = "alice") -> PlanStep:
    return PlanStep(tool=tool, args={"entity": entity}, rationale=f"Inspect {entity}.")


def _plan(*steps: PlanStep) -> InvestigationPlan:
    return InvestigationPlan(steps=list(steps) or [_step()])


def _decision(verb: str, *, next_step: PlanStep | None = None) -> str:
    payload: dict[str, Any] = {"decision": verb, "rationale": f"{verb} for a reason."}
    if next_step is not None:
        payload["next_step"] = next_step.model_dump()
    return json.dumps(payload)


def _executor(
    *,
    llm: FakeLLM,
    journal: RecordingJournal,
    source: FixtureSource | None = None,
    max_steps: int | None = None,
) -> Executor:
    return Executor(
        llm=llm,
        journal=journal,
        registry=ToolRegistry(),
        source=source or FixtureSource(),
        max_steps=max_steps,
    )


def test_conclude_on_first_step_terminates_completed() -> None:
    journal = RecordingJournal()
    executor = _executor(llm=FakeLLM([_decision("conclude")]), journal=journal)

    result = executor.run(_alert(), _plan(_step()))

    assert isinstance(result, ExecutionResult)
    assert result.terminated_reason == "completed"
    assert result.final_rationale == "conclude for a reason."
    assert [o.tool for o in result.observations] == ["lookup_user"]
    assert isinstance(result.observations[0], ObservationEntry)


def test_tool_called_then_tool_result_share_step_and_attempt() -> None:
    journal = RecordingJournal()
    executor = _executor(llm=FakeLLM([_decision("conclude")]), journal=journal)

    executor.run(_alert(), _plan(_step()))

    assert journal.names() == ["tool_called", "tool_result", "llm_call"]
    called = journal.events[0][1]
    res = journal.events[1][1]
    assert called["step"] == res["step"] == 1
    assert called["attempt"] == res["attempt"] == 1
    assert called["tool"] == "lookup_user"
    assert res["ok"] is True
    assert "data" in res


def test_llm_call_carries_reason_purpose_and_metadata() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_decision("conclude")], model="m1", tokens=7)
    executor = _executor(llm=llm, journal=journal)

    executor.run(_alert(), _plan(_step()))

    llm_call = next(p for e, p, _ in journal.events if e == "llm_call")
    assert llm_call["purpose"] == "reason"
    assert llm_call["model"] == "m1"
    assert llm_call["tokens"] == 7
    assert "prompt_hash" in llm_call
    assert "latency_ms" in llm_call


def test_continue_walks_the_next_planned_step() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_decision("continue"), _decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(
        _alert(),
        _plan(_step(entity="alice"), _step(tool="query_logs", entity="10.0.0.9")),
    )

    assert result.terminated_reason == "completed"
    assert [o.tool for o in result.observations] == ["lookup_user", "query_logs"]
    assert [o.step for o in result.observations] == [1, 2]


def test_revise_plan_replaces_remaining_plan_and_emits_plan_revised() -> None:
    journal = RecordingJournal()
    revised = _step(tool="check_reputation", entity="10.0.0.9")
    llm = FakeLLM([_decision("revise_plan", next_step=revised), _decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    # The original plan's second step must NOT run — the revision replaces it.
    result = executor.run(
        _alert(),
        _plan(_step(entity="alice"), _step(tool="query_logs", entity="ignored")),
    )

    assert result.terminated_reason == "completed"
    assert [o.tool for o in result.observations] == ["lookup_user", "check_reputation"]
    assert "plan_revised" in journal.names()
    revised_event = next(p for e, p, _ in journal.events if e == "plan_revised")
    assert revised_event["steps"] == [revised.model_dump()]


def test_revise_plan_without_next_step_terminates_completed() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_decision("revise_plan")])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(_alert(), _plan(_step()))

    assert result.terminated_reason == "completed"
    assert result.final_rationale == "revise_plan for a reason."
    assert "plan_revised" not in journal.names()
    assert [o.tool for o in result.observations] == ["lookup_user"]


def test_plan_exhausted_without_conclude_terminates_completed() -> None:
    journal = RecordingJournal()
    # Two steps, both ``continue`` — the plan runs out before a ``conclude``.
    llm = FakeLLM([_decision("continue"), _decision("continue")])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(
        _alert(),
        _plan(_step(entity="alice"), _step(tool="query_logs", entity="10.0.0.9")),
    )

    assert result.terminated_reason == "completed"
    assert result.final_rationale is None
    assert [o.step for o in result.observations] == [1, 2]


def test_empty_plan_terminates_completed_without_calling_the_reasoner() -> None:
    journal = RecordingJournal()
    # An empty plan can arrive from ``{"steps": []}``: the loop never enters, so
    # no tool runs and the reasoner is never consulted.
    llm = FakeLLM([])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(_alert(), InvestigationPlan(steps=[]))

    assert result.terminated_reason == "completed"
    assert result.observations == []
    assert journal.events == []
    assert llm.calls == 0


def test_max_steps_guard_terminates_with_max_steps() -> None:
    journal = RecordingJournal()
    # Always ``revise_plan`` to a fresh call so the plan never empties; the guard
    # is the only thing that stops it.
    script = [
        _decision("revise_plan", next_step=_step(tool="query_logs", entity=f"e{i}"))
        for i in range(5)
    ]
    llm = FakeLLM(script)
    executor = _executor(llm=llm, journal=journal, max_steps=2)

    result = executor.run(_alert(), _plan(_step(entity="seed")))

    assert result.terminated_reason == "max_steps"
    assert len(result.observations) == 2  # exactly MAX_STEPS Steps ran
    assert result.final_rationale is None


def test_repeat_call_guard_never_re_executes_and_forces_course_change() -> None:
    journal = RecordingJournal()
    dup = _step(entity="alice")
    # Step 1 runs lookup_user(alice); the reasoner revises back to the SAME call;
    # step 2 is guarded (not executed); the reasoner then concludes.
    llm = FakeLLM([_decision("revise_plan", next_step=dup), _decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(_alert(), _plan(dup))

    assert result.terminated_reason == "completed"
    # Only ONE Observation — the duplicate never produced one.
    assert [o.tool for o in result.observations] == ["lookup_user"]
    # Exactly one tool_called/tool_result pair: the guarded call emitted none.
    assert journal.names().count("tool_called") == 1
    assert journal.names().count("tool_result") == 1


def test_repeat_call_guard_surfaces_note_to_the_reasoner() -> None:
    journal = RecordingJournal()
    dup = _step(entity="alice")
    llm = FakeLLM([_decision("revise_plan", next_step=dup), _decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    executor.run(_alert(), _plan(dup))

    # The second reasoner call's prompt carries the guard note.
    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert "refused to repeat the identical call" in rendered


def test_permanent_tool_error_arrives_as_observation_not_crash() -> None:
    journal = RecordingJournal()
    source = FixtureSource(raise_for={"ghost": ToolError("entity not found")})
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=source)

    result = executor.run(_alert(), _plan(_step(entity="ghost")))

    assert result.terminated_reason == "completed"
    obs = result.observations[0]
    assert obs.result.ok is False
    assert obs.result.error == "entity not found"
    # Permanent error: a single attempt, no retry.
    assert journal.names().count("tool_called") == 1


def test_transient_tool_error_retries_then_arrives_as_observation() -> None:
    journal = RecordingJournal()
    source = FixtureSource(raise_for={"flaky": ToolError("timeout", transient=True)})
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=source)

    result = executor.run(_alert(), _plan(_step(entity="flaky")))

    assert result.observations[0].result.ok is False
    # Transient: two attempts, both journaled with the shared step.
    called = [p for e, p, _ in journal.events if e == "tool_called"]
    assert [c["attempt"] for c in called] == [1, 2]
    assert {c["step"] for c in called} == {1}


def test_unknown_tool_name_arrives_as_observation_not_crash() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(_alert(), _plan(PlanStep(tool="nmap", args={}, rationale="scan")))

    assert result.terminated_reason == "completed"
    obs = result.observations[0]
    assert obs.result.ok is False
    assert "unknown tool" in (obs.result.error or "")
    res_event = next(p for e, p, _ in journal.events if e == "tool_result")
    assert res_event["ok"] is False
    assert "error" in res_event


def test_llm_error_mid_loop_terminates_error_and_emits_no_llm_call() -> None:
    journal = RecordingJournal()
    # A malformed reply, repeated, exhausts the single repair attempt -> LLMError.
    llm = FakeLLM(["not json", "still not json"])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(_alert(), _plan(_step()))

    assert result.terminated_reason == "error"
    # The tool ran (its events emitted) but the reasoner failed: no llm_call.
    assert "llm_call" not in journal.names()
    # llm_repair fires when the repair is attempted (before the second failure).
    assert journal.names() == ["tool_called", "tool_result", "llm_repair"]
    # The gathered Observation is still returned for the degraded verdict.
    assert [o.tool for o in result.observations] == ["lookup_user"]


def test_rendered_prompt_delimits_alert_and_observations_as_untrusted() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    executor.run(_alert(), _plan(_step()))

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert "<alert_payload>" in rendered
    assert "</alert_payload>" in rendered
    assert "<observations>" in rendered
    assert "</observations>" in rendered
    assert "<remaining_steps>" in rendered
    assert "</remaining_steps>" in rendered
    # The alert's injection-vector description lands inside the labeled block.
    assert "Large outbound transfer from alice's host." in rendered
    # Event-type-agnostic.
    assert "data_exfiltration" in rendered


def test_rendered_prompt_shows_remaining_steps_then_empty_when_exhausted() -> None:
    # Two-step plan: first reason call sees the second step pending; second call sees none.
    llm = FakeLLM([_decision("continue"), _decision("conclude")])
    journal = RecordingJournal()
    executor = _executor(llm=llm, journal=journal)
    first_step = _step(entity="alice")
    second_step = _step(tool="query_logs", entity="alice")

    executor.run(_alert(), _plan(first_step, second_step))

    # First reason call: second step still pending in remaining_steps block.
    first_rendered = "\n".join(m["content"] for m in llm.messages_by_call[0])
    assert "query_logs" in first_rendered
    # Second reason call: no further steps pending.
    second_rendered = "\n".join(m["content"] for m in llm.messages_by_call[1])
    assert "no further steps are planned" in second_rendered


def test_rendered_prompt_presents_the_available_tools() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    executor.run(_alert(), _plan(_step()))

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    for name in ToolRegistry().names():
        assert name in rendered


def test_render_falls_back_to_single_message_when_sentinel_absent() -> None:
    """If the template has no {{END_OF_STABLE}}, a single message is returned."""
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=RecordingJournal())
    t = "No sentinel. {{TOOLS}} {{ALERT_PAYLOAD}} {{OBSERVATIONS}} {{REMAINING_STEPS}}"
    executor._template = t  # noqa: SLF001

    executor.run(_alert(), _plan(_step()))

    assert len(llm.last_messages) == 1


def test_max_steps_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_STEPS", "1")
    journal = RecordingJournal()
    llm = FakeLLM(
        [_decision("revise_plan", next_step=_step(tool="query_logs", entity="x"))],
    )
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(_alert(), _plan(_step(entity="seed")))

    assert result.terminated_reason == "max_steps"
    assert len(result.observations) == 1


def test_max_steps_env_malformed_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_STEPS", "not-a-number")
    journal = RecordingJournal()
    executor = _executor(llm=FakeLLM([_decision("conclude")]), journal=journal)

    # Default 15 governs: a single-step conclude completes well under it.
    result = executor.run(_alert(), _plan(_step()))

    assert result.terminated_reason == "completed"
    assert executor._max_steps == 15  # noqa: SLF001 — assert the resolved guard.


def test_max_steps_unset_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MAX_STEPS", raising=False)
    journal = RecordingJournal()
    executor = _executor(llm=FakeLLM([_decision("conclude")]), journal=journal)

    executor.run(_alert(), _plan(_step()))

    assert executor._max_steps == 15  # noqa: SLF001 — assert the resolved guard.


# --------------------------------------------------------------------------- #
# resume — reason-first re-entry (US-0002 AC3)                                 #
# --------------------------------------------------------------------------- #


def _obs(step: int, tool: str = "lookup_user", entity: str = "alice") -> ObservationEntry:
    """A rebuilt-from-journal Observation seeding the resume entry."""
    return ObservationEntry(
        step=step,
        tool=tool,
        args={"entity": entity},
        result=ToolResult(tool=tool, ok=True, data={"entity": entity, "status": "benign"}),
    )


def test_resume_reasons_first_before_executing_any_new_step() -> None:
    # The causality contract (advisor trap #1): resume must REASON over the rebuilt
    # Observations before executing step 3 — the reason call authorizes the next
    # step. So the FIRST journal line a resume writes is llm_call(reason), never
    # tool_called. Here the reason concludes immediately, so no new tool runs.
    journal = RecordingJournal()
    executor = _executor(llm=FakeLLM([_decision("conclude")]), journal=journal)
    plan = _plan(_step(entity="a"), _step(entity="b"), _step(entity="c"))
    pre = [_obs(1, entity="a"), _obs(2, entity="b")]

    result = executor.resume(_alert(), plan, pre_observations=pre, next_step_index=2)

    assert journal.names()[0] == "llm_call"  # reason FIRST, not tool_called
    assert journal.names() == ["llm_call"]  # conclude -> no further tool ran
    assert result.terminated_reason == "completed"
    # The rebuilt Observations are carried through; none re-executed.
    assert [o.step for o in result.observations] == [1, 2]


def test_resume_continues_from_the_next_step_without_replaying_recorded_ones() -> None:
    # continue -> the executor runs ONLY the remaining (step 3) plan step; the two
    # recorded steps are reused, never re-executed (no duplicate step/attempt pairs).
    journal = RecordingJournal()
    executor = _executor(
        llm=FakeLLM([_decision("continue"), _decision("conclude")]),
        journal=journal,
    )
    plan = _plan(_step(entity="a"), _step(entity="b"), _step(entity="c"))
    pre = [_obs(1, entity="a"), _obs(2, entity="b")]

    result = executor.resume(_alert(), plan, pre_observations=pre, next_step_index=2)

    # First a reason over the rebuilt obs, THEN step 3 executes (called/result/reason).
    assert journal.names() == ["llm_call", "tool_called", "tool_result", "llm_call"]
    # Only one NEW tool_called — step 3 — at executor step 3.
    called = journal.events[1][1]
    assert called["step"] == 3
    assert called["args"] == {"entity": "c"}
    # Trajectory: the two reused + the one freshly executed.
    assert [o.step for o in result.observations] == [1, 2, 3]
    assert result.terminated_reason == "completed"


def test_resume_revise_replaces_the_remaining_plan() -> None:
    journal = RecordingJournal()
    new_step = _step(tool="query_logs", entity="z")
    executor = _executor(
        llm=FakeLLM([_decision("revise_plan", next_step=new_step), _decision("conclude")]),
        journal=journal,
    )
    plan = _plan(_step(entity="a"), _step(entity="b"))
    pre = [_obs(1, entity="a")]

    result = executor.resume(_alert(), plan, pre_observations=pre, next_step_index=1)

    # revise emits plan_revised, then the revised step runs.
    assert "plan_revised" in journal.names()
    assert result.observations[-1].tool == "query_logs"
    assert result.terminated_reason == "completed"


def test_resume_llm_error_on_the_first_reason_terminates_error() -> None:
    # The reason re-fire fails: resume returns terminated_reason="error" with the
    # rebuilt Observations intact — never crashing, no new tool ran.
    journal = RecordingJournal()
    executor = _executor(llm=FakeLLM([]), journal=journal)  # exhausted script -> LLMError
    plan = _plan(_step(entity="a"), _step(entity="b"))
    pre = [_obs(1, entity="a")]

    result = executor.resume(_alert(), plan, pre_observations=pre, next_step_index=1)

    assert result.terminated_reason == "error"
    assert [o.step for o in result.observations] == [1]
    assert journal.events == []  # no llm_call metadata on the error path


# --------------------------------------------------------------------------- #
# Rendering helpers: truncation, XML tag shape, compact JSON (A3/A4)          #
# --------------------------------------------------------------------------- #


class _BigSource(FixtureSource):
    """A FixtureSource subclass that stuffs an oversized payload into every result."""

    def fetch(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        result = super().fetch(tool, args)
        result["big"] = "x" * (_OBSERVATION_DATA_MAX_CHARS + 500)
        return result


def test_oversized_observation_data_is_truncated_in_render() -> None:
    """An observation whose data serializes to > 4000 chars is truncated in render."""
    journal = RecordingJournal()
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=_BigSource())

    executor.run(_alert(), _plan(_step()))

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert "truncated" in rendered


def test_render_observations_uses_xml_observation_tags() -> None:
    """Each observation renders as an <observation ...>...</observation> XML tag."""
    journal = RecordingJournal()
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    executor.run(_alert(), _plan(_step()))

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert '<observation step="1" tool="lookup_user"' in rendered
    assert "</observation>" in rendered


def test_render_observations_ok_false_shows_false_attribute() -> None:
    """A failed observation renders with ok="false" in the XML tag."""
    journal = RecordingJournal()
    source = FixtureSource(raise_for={"ghost": ToolError("not found")})
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=source)

    executor.run(_alert(), _plan(_step(entity="ghost")))

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert 'ok="false"' in rendered


def test_adapt_note_appended_on_tool_miss() -> None:
    """A failed ok=False observation appends a guard_note to the rendered prompt."""
    journal = RecordingJournal()
    source = FixtureSource(raise_for={"ghost": ToolError("not found")})
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=source)

    executor.run(_alert(), _plan(_step(entity="ghost")))

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert "<guard_note>" in rendered
    assert "Adapt:" in rendered


def test_consecutive_miss_escalates_note_message() -> None:
    """Two consecutive ok=False observations produce the stronger escalation note."""
    journal = RecordingJournal()
    source = FixtureSource(
        raise_for={
            "ghost1": ToolError("not found"),
            "ghost2": ToolError("not found"),
        }
    )
    # Two failing steps then conclude.
    llm = FakeLLM([_decision("continue"), _decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=source)

    executor.run(
        _alert(),
        _plan(_step(entity="ghost1"), _step(entity="ghost2")),
    )

    # The second reason call should carry the escalated message.
    second_rendered = "\n".join(m["content"] for m in llm.messages_by_call[1])
    assert "consecutive failure" in second_rendered
    assert "Conclude only when no relevant untried tool/entity remains" in second_rendered


def test_miss_count_resets_on_ok_true() -> None:
    """A successful ok=True step resets the consecutive-miss counter."""
    journal = RecordingJournal()
    # ghost fails, alice succeeds, ghost2 fails -> only 1 consecutive miss at step 3.
    source = FixtureSource(
        raise_for={
            "ghost": ToolError("not found"),
            "ghost2": ToolError("not found"),
        }
    )
    # Three-step plan: ghost (fail), alice (ok), ghost2 (fail).
    llm = FakeLLM([_decision("continue"), _decision("continue"), _decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=source)

    executor.run(
        _alert(),
        _plan(
            _step(entity="ghost"),
            _step(entity="alice"),
            _step(entity="ghost2"),
        ),
    )

    # After the success at step 2, consecutive_miss_count resets to 0.
    # Step 3 is the 1st consecutive miss again (not 3rd).
    third_rendered = "\n".join(m["content"] for m in llm.messages_by_call[2])
    # Should contain "Adapt:" (1st miss message) not "consecutive failure" (2nd+).
    assert "Adapt:" in third_rendered
    assert "consecutive failure" not in third_rendered


def test_adapt_note_not_in_observations() -> None:
    """Adapt notes must NOT enter the observations list."""
    journal = RecordingJournal()
    source = FixtureSource(raise_for={"ghost": ToolError("not found")})
    llm = FakeLLM([_decision("conclude")])
    executor = _executor(llm=llm, journal=journal, source=source)

    result = executor.run(_alert(), _plan(_step(entity="ghost")))

    # The one observation is the tool result, not the adapt note.
    assert len(result.observations) == 1
    assert result.observations[0].tool == "lookup_user"


# --------------------------------------------------------------------------- #
# B1 (M1) — llm_repair event wired through the reasoner                       #
# --------------------------------------------------------------------------- #


def test_reasoner_repair_emits_llm_repair_event_before_llm_call() -> None:
    """When the reasoner's first reply is malformed, llm_repair fires before llm_call."""
    journal = RecordingJournal()
    # Two malformed then one good: first triggers repair (one more malformed), then
    # second call uses the second entry as repair response, then the concludes.
    llm = FakeLLM(["not json", _decision("conclude")])
    executor = _executor(llm=llm, journal=journal)

    result = executor.run(_alert(), _plan(_step()))

    assert result.terminated_reason == "completed"
    names = journal.names()
    assert "llm_repair" in names
    assert names.index("llm_repair") < names.index("llm_call")
    repair_payload = next(p for e, p, _ in journal.events if e == "llm_repair")
    assert repair_payload["purpose"] == "reason"
    assert "error" in repair_payload


# --------------------------------------------------------------------------- #
# T1 (H3) — resume repeat-guard rebuilds attempted from pre-observations       #
# --------------------------------------------------------------------------- #


def test_resume_repeat_guard_rebuilds_attempted_from_pre_observations() -> None:
    """On resume, the repeat-call guard is seeded from the pre-resume observations.

    A tool+args pair that was already executed in the pre-resume trajectory must be
    refused on resume if the Reasoner proposes it again — no second tool_called
    event must appear for the duplicate, but a guard note must reach the Reasoner.
    """
    journal = RecordingJournal()
    # step 1 was lookup_user(alice) — present in pre_observations.
    # The resume Reasoner first proposes that SAME call (a duplicate); after the
    # guard refuses it the Reasoner is told to change course and concludes.
    dup_step = _step(entity="alice")  # identical to the pre-observation
    llm = FakeLLM(
        [
            # First reason call (over rebuilt obs): revise to the duplicate step.
            _decision("revise_plan", next_step=dup_step),
            # Second reason call (after guard refused the dup): conclude.
            _decision("conclude"),
        ]
    )
    executor = _executor(llm=llm, journal=journal)
    plan = _plan(_step(entity="alice"), _step(entity="bob"))
    pre = [_obs(1, entity="alice")]

    result = executor.resume(_alert(), plan, pre_observations=pre, next_step_index=1)

    assert result.terminated_reason == "completed"
    # The duplicate was refused: no second tool_called for lookup_user(alice).
    called_events = [p for e, p, _ in journal.events if e == "tool_called"]
    assert len(called_events) == 0  # the dup was refused; no new tool ran before conclude
    # Guard note must be present in the second Reasoner call's prompt.
    second_rendered = "\n".join(m["content"] for m in llm.messages_by_call[1])
    assert "refused to repeat" in second_rendered
