"""Tests for verdict synthesis (RFC-0001 §Core loop / §Verdict; ADR-0005; US-0001).

Structural assertions only — "concludes sensibly" is wave-3 eval territory:

* one structured LLM call produces a valid ``Verdict``;
* the ``llm_call`` (purpose ``"verdict"``) and ``verdict`` events fire in that
  order on the happy path, carrying the Completion metadata and the verdict dump;
* the rendered prompt delimits the untrusted alert payload, the untrusted tool
  observations, and the untrusted carried findings in labeled blocks apart from
  the instructions (ADR-0005), and is event-type-agnostic;
* ``terminated_reason`` is code-owned: it is set from the upstream parameter on
  the synthesized verdict (overriding whatever the LLM emitted) and on the
  degraded verdict;
* the DEGRADED PATH (US-0001 AC) never crashes: when the LLM raises ``LLMError``
  after its internal repair attempt, a deterministic partial ``Verdict`` is built
  from the gathered material — conservative ``high`` severity, the input findings
  carried through verbatim, no recommended actions, low confidence — and the
  ``verdict`` event still fires (and only that event: no ``llm_call``).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from triage.llm import FakeLLM
from triage.models import Action, Alert, Finding, ToolResult, Verdict
from triage.verdict import (
    DEGRADED_CONFIDENCE,
    DEGRADED_SEVERITY,
    VerdictSynthesizer,
)

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


_VERDICT_JSON = json.dumps(
    {
        "severity": "high",
        "findings": [
            {
                "statement": "alice's host exfiltrated 5 MB to a known-bad IP.",
                "evidence": "query_logs returned an outbound transfer to 203.0.113.7.",
            },
        ],
        "recommended_actions": [
            {"name": "block_user", "params": {"user": "alice"}},
        ],
        "confidence": 0.82,
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


def _observations() -> list[ToolResult]:
    return [
        ToolResult(
            tool="query_logs",
            ok=True,
            data={"transfer": "outbound to 203.0.113.7"},
        ),
        ToolResult(tool="lookup_user", ok=False, error="user not found"),
    ]


def _findings() -> list[Finding]:
    return [
        Finding(
            statement="The flagged IP 10.0.0.9 resolves to alice's workstation.",
            evidence="get_asset_info linked 10.0.0.9 to asset WS-ALICE.",
        ),
    ]


def test_synthesize_returns_valid_verdict() -> None:
    synth = VerdictSynthesizer(llm=FakeLLM([_VERDICT_JSON]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), observations=_observations(), findings=_findings())

    assert isinstance(verdict, Verdict)
    assert verdict.severity == "high"
    assert verdict.findings[0].statement.startswith("alice's host")
    assert verdict.recommended_actions[0].name == "block_user"


def test_synthesize_emits_llm_call_then_verdict_in_order() -> None:
    journal = RecordingJournal()
    llm = FakeLLM([_VERDICT_JSON], model="m1", tokens=99)
    synth = VerdictSynthesizer(llm=llm, journal=journal)

    verdict = synth.synthesize(_alert(), observations=_observations())

    names = [event for event, _, _ in journal.events]
    assert names == ["llm_call", "verdict"]

    llm_call_payload = journal.events[0][1]
    assert llm_call_payload["purpose"] == "verdict"
    assert llm_call_payload["model"] == "m1"
    assert llm_call_payload["tokens"] == 99
    assert "prompt_hash" in llm_call_payload
    assert "latency_ms" in llm_call_payload

    verdict_payload = journal.events[1][1]
    assert verdict_payload["verdict"] == verdict.model_dump()


def test_synthesized_verdict_carries_terminated_reason_from_parameter() -> None:
    # terminated_reason is an upstream fact, not LLM judgment: the param overrides
    # whatever the model emitted (the scripted JSON omits it entirely).
    synth = VerdictSynthesizer(llm=FakeLLM([_VERDICT_JSON]), journal=RecordingJournal())

    verdict = synth.synthesize(
        _alert(),
        observations=_observations(),
        terminated_reason="max_steps",
    )

    assert verdict.terminated_reason == "max_steps"


def test_synthesized_verdict_terminated_reason_param_overrides_llm_value() -> None:
    # terminated_reason is code-owned and always wins: even when the model emits
    # a value, the upstream parameter overrides it (a clean run whose model
    # hallucinated "max_steps" must end up None — guards a fill-if-None refactor).
    hallucinated = json.dumps(
        {
            "severity": "low",
            "findings": [],
            "recommended_actions": [],
            "confidence": 0.5,
            "terminated_reason": "max_steps",
        },
    )
    synth = VerdictSynthesizer(llm=FakeLLM([hallucinated]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), terminated_reason=None)

    assert verdict.terminated_reason is None


def test_synthesized_verdict_terminated_reason_defaults_to_none() -> None:
    synth = VerdictSynthesizer(llm=FakeLLM([_VERDICT_JSON]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), observations=_observations())

    assert verdict.terminated_reason is None


def test_rendered_prompt_delimits_untrusted_alert_observations_and_findings() -> None:
    llm = FakeLLM([_VERDICT_JSON])
    synth = VerdictSynthesizer(llm=llm, journal=RecordingJournal())

    synth.synthesize(_alert(), observations=_observations(), findings=_findings())

    rendered = "\n".join(message["content"] for message in llm.last_messages)
    assert "<alert_payload>" in rendered
    assert "</alert_payload>" in rendered
    assert "<observations>" in rendered
    assert "</observations>" in rendered
    assert "<findings>" in rendered
    assert "</findings>" in rendered
    # The injection-vector description and the observation/finding text all land
    # inside their labeled blocks, never interpolated into the instructions.
    assert "Large outbound transfer from alice's host." in rendered
    assert "outbound to 203.0.113.7" in rendered
    assert "WS-ALICE" in rendered
    # Event-type-agnostic: the value is rendered as data, never branched on.
    assert "data_exfiltration" in rendered


def test_rendered_prompt_handles_empty_observations_and_findings() -> None:
    llm = FakeLLM([_VERDICT_JSON])
    synth = VerdictSynthesizer(llm=llm, journal=RecordingJournal())

    synth.synthesize(_alert())

    rendered = "\n".join(message["content"] for message in llm.last_messages)
    # The labeled blocks still render (event-type-agnostic, fixed structure) even
    # when no material was gathered — the model is told there is none.
    assert "<observations>" in rendered
    assert "<findings>" in rendered


def test_degraded_path_builds_partial_verdict_without_crashing() -> None:
    journal = RecordingJournal()
    # A malformed reply, repeated, exhausts the one repair attempt -> LLMError.
    synth = VerdictSynthesizer(
        llm=FakeLLM(["not json", "still not json"]),
        journal=journal,
    )

    verdict = synth.synthesize(
        _alert(),
        observations=_observations(),
        findings=_findings(),
        terminated_reason="error",
    )

    assert isinstance(verdict, Verdict)
    # Conservative deterministic severity + low confidence (documented constants).
    assert verdict.severity == DEGRADED_SEVERITY
    assert verdict.confidence == DEGRADED_CONFIDENCE
    # Input findings carried through verbatim; no new actions recommended.
    assert verdict.findings == _findings()
    assert verdict.recommended_actions == []
    # The upstream termination reason is carried into the partial verdict.
    assert verdict.terminated_reason == "error"


def test_degraded_path_emits_only_the_verdict_event() -> None:
    journal = RecordingJournal()
    synth = VerdictSynthesizer(
        llm=FakeLLM(["not json", "still not json"]),
        journal=journal,
    )

    verdict = synth.synthesize(_alert(), findings=_findings())

    # No Completion means no llm_call metadata to journal; only ``verdict`` fires.
    names = [event for event, _, _ in journal.events]
    assert names == ["verdict"]
    assert journal.events[0][1]["verdict"] == verdict.model_dump()


def test_degraded_path_with_no_gathered_material_still_ships_a_verdict() -> None:
    journal = RecordingJournal()
    synth = VerdictSynthesizer(
        llm=FakeLLM(["not json", "still not json"]),
        journal=journal,
    )

    verdict = synth.synthesize(_alert())

    assert verdict.severity == DEGRADED_SEVERITY
    assert verdict.findings == []
    assert verdict.recommended_actions == []
    assert verdict.terminated_reason is None


def test_degraded_verdict_findings_are_independent_of_recommended_actions() -> None:
    # Findings carried; actions empty even though the alert names a blockable user.
    journal = RecordingJournal()
    synth = VerdictSynthesizer(
        llm=FakeLLM(["not json", "still not json"]),
        journal=journal,
    )

    verdict = synth.synthesize(_alert(), findings=_findings())

    assert verdict.findings == _findings()
    assert not any(isinstance(action, Action) for action in verdict.recommended_actions)
