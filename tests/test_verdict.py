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
    _OBSERVATION_DATA_MAX_CHARS,
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


def test_render_falls_back_to_single_message_when_sentinel_absent() -> None:
    """If the template has no {{END_OF_STABLE}}, a single message is returned."""
    llm = FakeLLM([_VERDICT_JSON])
    synth = VerdictSynthesizer(llm=llm, journal=RecordingJournal())
    synth._template = "No sentinel. {{ALERT_PAYLOAD}} {{OBSERVATIONS}} {{FINDINGS}}"  # noqa: SLF001

    synth.synthesize(_alert())

    assert len(llm.last_messages) == 1


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

    names = [event for event, _, _ in journal.events]
    # The repair fires before the second attempt; when both fail, llm_repair is
    # emitted (the repair was attempted) but llm_call is NOT (no Completion exists).
    # The final event is always verdict (RFC: "never exit without a verdict").
    assert "llm_call" not in names
    assert names[-1] == "verdict"
    verdict_event = next(p for e, p, _ in journal.events if e == "verdict")
    assert verdict_event["verdict"] == verdict.model_dump()


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


# ---------------------------------------------------------------------------
# _clamp_by_evidence: evidence-proportional confidence ceiling (Fix 1)
# ---------------------------------------------------------------------------

_OVERCONFIDENT_JSON = json.dumps(
    {
        "severity": "critical",
        "findings": [
            {
                "statement": "Suspicious activity detected for user alice.",
                "evidence": "check_reputation returned risk score 95 for alice.",
            },
        ],
        "recommended_actions": [
            {"name": "block_user", "params": {"user": "alice"}},
        ],
        "confidence": 0.95,
    },
)


_UNDERCONFIDENT_JSON = json.dumps(
    {
        "severity": "low",
        "findings": [
            {
                "statement": "No tool data available.",
                "evidence": "All investigation tools returned not-found.",
            },
        ],
        "recommended_actions": [],
        "confidence": 0.25,
    },
)


def test_confidence_floor_zero_ok() -> None:
    """0 ok=true + LLM returns confidence < 0.30: floor raises it to 0.30."""
    no_ok_observations = [
        ToolResult(tool="lookup_user", ok=False, error="not found"),
    ]
    synth = VerdictSynthesizer(llm=FakeLLM([_UNDERCONFIDENT_JSON]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), observations=no_ok_observations)

    assert verdict.confidence == 0.30


def test_confidence_clamped_zero_ok() -> None:
    """0 ok=true observations: confidence clamped to exactly 0.40 and actions stripped.

    T3 (L2): the ceiling is == 0.40, not merely <= 0.40. This pins the exact
    clamp constant so a refactor that accidentally changes it (e.g. to 0.5) is
    caught immediately. ``_OVERCONFIDENT_JSON`` has confidence 0.95 which is above
    the ceiling and must be clamped down to the boundary value exactly.
    """
    # All observations are ok=False — zero positive evidence.
    no_ok_observations = [
        ToolResult(tool="lookup_user", ok=False, error="timeout"),
        ToolResult(tool="query_logs", ok=False, error="service unavailable"),
    ]
    synth = VerdictSynthesizer(llm=FakeLLM([_OVERCONFIDENT_JSON]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), observations=no_ok_observations)

    # T3: pin the exact ceiling constant, not just an upper bound.
    assert verdict.confidence == 0.40
    assert verdict.recommended_actions == []


def test_confidence_in_range_zero_ok_actions_stripped() -> None:
    """0 ok=true, confidence already in [0.30, 0.40]: actions stripped, confidence preserved."""
    in_range_json = json.dumps(
        {
            "severity": "low",
            "findings": [{"statement": "No data.", "evidence": "No tool data."}],
            "recommended_actions": [{"name": "block_user", "params": {"user": "alice"}}],
            "confidence": 0.35,
        },
    )
    no_ok_observations = [ToolResult(tool="lookup_user", ok=False, error="not found")]
    synth = VerdictSynthesizer(llm=FakeLLM([in_range_json]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), observations=no_ok_observations)

    assert verdict.confidence == 0.35
    assert verdict.recommended_actions == []


def test_confidence_unclamped_one_ok() -> None:
    """1 ok=true observation: LLM confidence preserved — clamp only applies at ok_count == 0."""
    one_ok_observations = [
        ToolResult(tool="check_reputation", ok=True, data={"risk": 95}),
        ToolResult(tool="lookup_user", ok=False, error="not found"),
    ]
    synth = VerdictSynthesizer(llm=FakeLLM([_OVERCONFIDENT_JSON]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), observations=one_ok_observations)

    # One positive result: LLM value 0.95 must be preserved exactly.
    assert verdict.confidence == 0.95
    # Actions are NOT stripped when there is positive evidence.
    assert len(verdict.recommended_actions) >= 1


def test_oversized_observation_data_is_truncated_in_render() -> None:
    """An observation whose data serializes to > 4000 chars is truncated in render."""
    llm = FakeLLM([_VERDICT_JSON])
    synth = VerdictSynthesizer(llm=llm, journal=RecordingJournal())
    big_obs = ToolResult(
        tool="query_logs",
        ok=True,
        data={"big": "x" * (_OBSERVATION_DATA_MAX_CHARS + 500)},
    )

    synth.synthesize(_alert(), observations=[big_obs])

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert "truncated" in rendered


def test_render_observations_uses_xml_observation_tags() -> None:
    """Each observation renders as an <observation ...>...</observation> XML tag."""
    llm = FakeLLM([_VERDICT_JSON])
    synth = VerdictSynthesizer(llm=llm, journal=RecordingJournal())

    synth.synthesize(_alert(), observations=_observations())

    rendered = "\n".join(m["content"] for m in llm.last_messages)
    assert '<observation step="1" tool="query_logs"' in rendered
    assert "</observation>" in rendered
    assert 'ok="true"' in rendered
    assert 'ok="false"' in rendered


def test_confidence_unclamped_three_ok() -> None:
    """3 ok=true observations: LLM confidence preserved (no ceiling applies)."""
    three_ok_json = json.dumps(
        {
            "severity": "high",
            "findings": [
                {
                    "statement": "Confirmed malicious exfiltration by alice.",
                    "evidence": "Three tools confirmed alice's activity.",
                },
            ],
            "recommended_actions": [
                {"name": "block_user", "params": {"user": "alice"}},
            ],
            "confidence": 0.91,
        },
    )
    three_ok_observations = [
        ToolResult(tool="query_logs", ok=True, data={"transfer": "5 MB"}),
        ToolResult(tool="check_reputation", ok=True, data={"risk": 98}),
        ToolResult(tool="get_asset_info", ok=True, data={"asset": "WS-ALICE"}),
    ]
    synth = VerdictSynthesizer(llm=FakeLLM([three_ok_json]), journal=RecordingJournal())

    verdict = synth.synthesize(_alert(), observations=three_ok_observations)

    # Three positive results: the LLM value 0.91 must be preserved exactly.
    assert verdict.confidence == 0.91
    assert verdict.recommended_actions[0].name == "block_user"


# --------------------------------------------------------------------------- #
# B1 (M1) — llm_repair event wired in verdict synthesizer                     #
# --------------------------------------------------------------------------- #


def test_verdict_repair_emits_llm_repair_before_degraded_path() -> None:
    """On a malformed first verdict reply, llm_repair fires before the verdict event.

    The degraded path fires after the second malformed reply; on the repair path
    (first bad, second good) llm_repair precedes llm_call and verdict.
    """
    journal = RecordingJournal()
    synth = VerdictSynthesizer(
        llm=FakeLLM(["not json", _VERDICT_JSON]),
        journal=journal,
    )

    synth.synthesize(_alert())

    names = [event for event, _, _ in journal.events]
    assert "llm_repair" in names
    assert names.index("llm_repair") < names.index("llm_call")
    repair_payload = next(p for e, p, _ in journal.events if e == "llm_repair")
    assert repair_payload["purpose"] == "verdict"
    assert "error" in repair_payload


def test_verdict_repair_not_emitted_on_clean_parse() -> None:
    """No llm_repair event when the first verdict reply parses cleanly."""
    journal = RecordingJournal()
    synth = VerdictSynthesizer(llm=FakeLLM([_VERDICT_JSON]), journal=journal)

    synth.synthesize(_alert())

    names = [event for event, _, _ in journal.events]
    assert "llm_repair" not in names


# --------------------------------------------------------------------------- #
# F5 — action traceability backstop (re-homed to core._conclude_run, RFC-0003) #
# --------------------------------------------------------------------------- #
# The traceability filter moved from verdict.synthesize to core._conclude_run.
# The tests below verify that synthesize() now PASSES actions through unchanged
# (no filtering at the verdict layer), consistent with RFC-0003 §Module seams.
# The end-to-end traceability behavior is tested in test_core.py.
# --------------------------------------------------------------------------- #


def _one_ok_obs() -> list[ToolResult]:
    """One ok=True observation so the traceability path is active (ok_count >= 1)."""
    return [ToolResult(tool="query_logs", ok=True, data={"transfer": "alice to 203.0.113.7"})]


def _traceable_verdict_json(*, extra_action: dict[str, Any] | None = None) -> str:
    """Verdict whose action's 'user' param value 'alice' appears in the finding."""
    actions = [{"name": "block_user", "params": {"user": "alice"}}]
    if extra_action:
        actions.append(extra_action)
    return json.dumps(
        {
            "severity": "high",
            "findings": [
                {
                    "statement": "alice exfiltrated data to 203.0.113.7.",
                    "evidence": "query_logs shows outbound from alice.",
                }
            ],
            "recommended_actions": actions,
            "confidence": 0.85,
        }
    )


def _untraceable_verdict_json() -> str:
    """Verdict whose action param value 'mallory' does NOT appear in the finding."""
    return json.dumps(
        {
            "severity": "high",
            "findings": [
                {
                    "statement": "alice exfiltrated data.",
                    "evidence": "query_logs shows alice.",
                }
            ],
            "recommended_actions": [{"name": "block_user", "params": {"user": "mallory"}}],
            "confidence": 0.85,
        }
    )


def test_synthesize_passes_through_actions_unfiltered() -> None:
    """synthesize() no longer filters actions — traceability is enforced at core level.

    RFC-0003 §Module seams: the verify hook (core._conclude_run) is the canonical
    enforcement point for action traceability.  synthesize() passes through all
    LLM-returned actions unchanged; filtering happens in the core degrade path.
    """
    journal = RecordingJournal()
    synth = VerdictSynthesizer(llm=FakeLLM([_untraceable_verdict_json()]), journal=journal)

    verdict = synth.synthesize(_alert(), observations=_one_ok_obs())

    # Untraceable action passes through synthesize unchanged.
    assert len(verdict.recommended_actions) == 1
    assert verdict.recommended_actions[0].name == "block_user"
    # No drop event emitted from synthesize.
    assert "action_dropped_untraceable" not in [e for e, _, _ in journal.events]


def test_synthesize_passes_through_traceable_action() -> None:
    """A traceable action is still passed through by synthesize (no regression)."""
    journal = RecordingJournal()
    synth = VerdictSynthesizer(llm=FakeLLM([_traceable_verdict_json()]), journal=journal)

    verdict = synth.synthesize(_alert(), observations=_one_ok_obs())

    assert len(verdict.recommended_actions) == 1
    assert verdict.recommended_actions[0].name == "block_user"
    assert "action_dropped_untraceable" not in [e for e, _, _ in journal.events]


def test_synthesize_passes_through_untargeted_action() -> None:
    """An untargeted advisory action is passed through by synthesize."""
    advisory_json = json.dumps(
        {
            "severity": "low",
            "findings": [],
            "recommended_actions": [{"name": "notify_soc", "params": {"channel": "#soc"}}],
            "confidence": 0.5,
        }
    )
    journal = RecordingJournal()
    synth = VerdictSynthesizer(llm=FakeLLM([advisory_json]), journal=journal)

    verdict = synth.synthesize(_alert(), observations=_one_ok_obs())

    assert len(verdict.recommended_actions) == 1
    assert verdict.recommended_actions[0].name == "notify_soc"
    assert "action_dropped_untraceable" not in [e for e, _, _ in journal.events]


def test_zero_ok_actions_stripped_by_clamp_not_traceability() -> None:
    """On zero-ok, _clamp_by_evidence strips all actions (not traceability filter).

    synthesize() no longer has traceability filtering. _clamp_by_evidence still
    strips actions on the ok_count == 0 path, independent of traceability.
    """
    no_ok = [ToolResult(tool="lookup_user", ok=False, error="not found")]
    journal = RecordingJournal()
    synth = VerdictSynthesizer(llm=FakeLLM([_OVERCONFIDENT_JSON]), journal=journal)

    verdict = synth.synthesize(_alert(), observations=no_ok)

    # Actions stripped by _clamp_by_evidence; no traceability event.
    assert verdict.recommended_actions == []
    assert "action_dropped_untraceable" not in [e for e, _, _ in journal.events]
