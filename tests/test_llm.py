"""Tests for the LLM boundary (RFC-0001 §LLM boundary / ADR-0002).

Tier A only: every test runs against ``FakeLLM`` or a mocked ``openai`` transport
— no network, no key. The load-bearing behaviours pinned here:

* ``complete`` returns a ``Completion`` wrapper (validated instance + the
  ``llm_call`` metadata the caller journals), never a bare instance.
* ``prompt_hash`` is a model-agnostic sha256 over the rendered message list, so
  ``llm_call`` events and Replay Mode key on the same value.
* The repair path is real and shared by both impls: first malformed structured
  output triggers exactly one repair re-prompt; a second malformed output raises
  ``LLMError`` (US-0001 AC — caller-visible failure for a degraded verdict).
* The ``openai`` transport retries 3x with backoff and converts every failure to
  ``LLMError`` at this seam — no other exception escapes.
"""

from typing import Any

import pytest
from pydantic import BaseModel

from triage.errors import ConfigError, LLMError
from triage.llm import (
    LLM,
    Completion,
    FakeLLM,
    Message,
    OpenAICompatibleLLM,
    prompt_hash,
)
from triage.models import Verdict


class _Reply(BaseModel):
    """A minimal structured response model used to exercise the seam."""

    verdict: str
    confidence: float


_MESSAGES: list[Message] = [
    {"role": "system", "content": "You are a triage agent."},
    {"role": "user", "content": "Investigate ALT-1."},
]


def _valid_json() -> str:
    return '{"verdict": "benign", "confidence": 0.9}'


# --------------------------------------------------------------------------- #
# prompt_hash                                                                  #
# --------------------------------------------------------------------------- #


def test_prompt_hash_is_a_64_char_hex_sha256() -> None:
    digest = prompt_hash(_MESSAGES)
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_prompt_hash_is_deterministic_for_equal_messages() -> None:
    assert prompt_hash(_MESSAGES) == prompt_hash(list(_MESSAGES))


def test_prompt_hash_changes_with_message_content() -> None:
    other: list[Message] = [{"role": "user", "content": "different"}]
    assert prompt_hash(_MESSAGES) != prompt_hash(other)


def test_prompt_hash_is_order_sensitive() -> None:
    reversed_messages = list(reversed(_MESSAGES))
    assert prompt_hash(_MESSAGES) != prompt_hash(reversed_messages)


def test_prompt_hash_is_model_agnostic() -> None:
    # The hash keys Replay Mode; it must not depend on which model answers.
    fake_a = FakeLLM([_valid_json()], model="model-a")
    fake_b = FakeLLM([_valid_json()], model="model-b")
    result_a = fake_a.complete(_MESSAGES, _Reply)
    result_b = fake_b.complete(_MESSAGES, _Reply)
    assert result_a.prompt_hash == result_b.prompt_hash


# --------------------------------------------------------------------------- #
# FakeLLM — the shared completion + repair semantics                          #
# --------------------------------------------------------------------------- #


def test_fake_llm_satisfies_the_llm_protocol() -> None:
    llm: LLM = FakeLLM([_valid_json()])
    assert isinstance(llm, LLM)


def test_a_plain_object_is_not_an_llm() -> None:
    assert not isinstance(object(), LLM)


def test_complete_returns_a_validated_instance_in_a_completion() -> None:
    llm = FakeLLM([_valid_json()])
    result = llm.complete(_MESSAGES, _Reply)
    assert isinstance(result, Completion)
    assert isinstance(result.value, _Reply)
    assert result.value.verdict == "benign"
    assert result.value.confidence == 0.9


def test_completion_carries_the_llm_call_metadata() -> None:
    llm = FakeLLM([_valid_json()], model="canned-model", tokens=42)
    result = llm.complete(_MESSAGES, _Reply)
    assert result.model == "canned-model"
    assert result.tokens == 42
    assert result.latency_ms >= 0
    assert result.prompt_hash == prompt_hash(_MESSAGES)


def test_fake_llm_scripts_responses_per_call() -> None:
    llm = FakeLLM(['{"verdict": "a", "confidence": 0.1}', '{"verdict": "b", "confidence": 0.2}'])
    first = llm.complete(_MESSAGES, _Reply)
    second = llm.complete(_MESSAGES, _Reply)
    assert first.value.verdict == "a"
    assert second.value.verdict == "b"


def test_fake_llm_raises_when_the_script_is_exhausted() -> None:
    llm = FakeLLM([_valid_json()])
    llm.complete(_MESSAGES, _Reply)
    with pytest.raises(LLMError):
        llm.complete(_MESSAGES, _Reply)


def test_first_malformed_output_triggers_one_repair_then_succeeds() -> None:
    # US-0001 AC: first malformed -> exactly one repair re-prompt -> success.
    llm = FakeLLM(["this is not json", _valid_json()])
    result = llm.complete(_MESSAGES, _Reply)
    assert result.value.verdict == "benign"
    assert llm.calls == 2  # original + one repair


def test_schema_valid_json_that_violates_the_model_also_repairs() -> None:
    # Well-formed JSON that fails Pydantic validation is malformed for our purpose.
    llm = FakeLLM(['{"verdict": "benign"}', _valid_json()])
    result = llm.complete(_MESSAGES, _Reply)
    assert result.value.confidence == 0.9
    assert llm.calls == 2


def test_second_malformed_output_raises_llm_error() -> None:
    # US-0001 AC: second malformed -> caller-visible failure (degraded verdict).
    llm = FakeLLM(["still not json", "also not json"])
    with pytest.raises(LLMError):
        llm.complete(_MESSAGES, _Reply)
    assert llm.calls == 2  # original + exactly one repair, no more


# --------------------------------------------------------------------------- #
# Repair path against a real contract model (Verdict) — the regression that    #
# strict+forbid on LLM-output models introduced. Benign drift must NOT burn the #
# single repair attempt; only genuinely-malformed output may.                   #
# --------------------------------------------------------------------------- #


_VERDICT_BENIGN_DRIFT = (
    '{"severity": "high", "findings": [{"statement": "s", "evidence": "e", '
    '"source_run": "r-1"}], "recommended_actions": [{"name": "block_user"}], '
    '"confidence": "0.9", "reasoning": "hallucinated field"}'
)
"""A Verdict reply carrying an extra key AND a quoted (str) confidence — the two
commonest small-model drifts on the no-``response_format`` path."""


def test_verdict_extra_key_and_quoted_confidence_validate_without_repair() -> None:
    # Script exactly ONE reply: if the model were still strict, the benign drift
    # would trigger a repair, the script would exhaust, and complete() would
    # raise. It validating in a single call proves no repair attempt was burned.
    llm = FakeLLM([_VERDICT_BENIGN_DRIFT])
    result = llm.complete(_MESSAGES, Verdict)
    assert isinstance(result.value, Verdict)
    assert result.value.severity == "high"
    assert result.value.confidence == pytest.approx(0.9)
    assert llm.calls == 1  # no repair re-prompt — the load-bearing assertion.


def test_genuinely_malformed_verdict_repairs_exactly_once_then_succeeds() -> None:
    # An invalid severity Literal is genuinely malformed (a semantic constraint,
    # not benign drift) — it must still trigger exactly one repair.
    bad = (
        '{"severity": "catastrophic", "findings": [], "recommended_actions": [], "confidence": 0.5}'
    )
    good = '{"severity": "low", "findings": [], "recommended_actions": [], "confidence": 0.5}'
    llm = FakeLLM([bad, good])
    result = llm.complete(_MESSAGES, Verdict)
    assert result.value.severity == "low"
    assert llm.calls == 2  # original + exactly one repair.


def test_genuinely_malformed_verdict_twice_raises_after_one_repair() -> None:
    bad = (
        '{"severity": "catastrophic", "findings": [], "recommended_actions": [], "confidence": 0.5}'
    )
    llm = FakeLLM([bad, bad])
    with pytest.raises(LLMError):
        llm.complete(_MESSAGES, Verdict)
    assert llm.calls == 2  # original + exactly one repair, no more.


def test_repair_reprompt_is_visible_in_the_sent_messages() -> None:
    llm = FakeLLM(["not json", _valid_json()])
    llm.complete(_MESSAGES, _Reply)
    # The repair attempt re-sends with an appended corrective nudge.
    assert len(llm.last_messages) == len(_MESSAGES) + 1
    assert llm.last_messages[-1]["role"] == "user"


# --------------------------------------------------------------------------- #
# OpenAICompatibleLLM — transport, retries, response_format                   #
# --------------------------------------------------------------------------- #


class _Message:
    def __init__(self, content: str | None) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str | None) -> None:
        self.message = _Message(content)


class _Usage:
    def __init__(self, total_tokens: int) -> None:
        self.total_tokens = total_tokens


class _Response:
    def __init__(
        self,
        content: str | None,
        *,
        total_tokens: int = 7,
        model: str = "wire-model",
    ) -> None:
        self.choices = [_Choice(content)]
        self.usage: _Usage | None = _Usage(total_tokens)
        self.model = model


class _FakeCompletions:
    """A stand-in for ``client.chat.completions`` recording the calls it sees."""

    def __init__(self, script: list[Any]) -> None:
        self._script = list(script)
        self.requests: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:  # noqa: ANN401 — mirrors the SDK signature
        self.requests.append(kwargs)
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _FakeClient:
    def __init__(self, script: list[Any]) -> None:
        self.chat = type("_Chat", (), {"completions": _FakeCompletions(script)})()


def _make_llm(
    script: list[Any],
    *,
    supports_json_schema: bool = True,
) -> tuple[OpenAICompatibleLLM, _FakeCompletions]:
    client = _FakeClient(script)
    llm = OpenAICompatibleLLM(
        client=client,
        model="wire-model",
        supports_json_schema=supports_json_schema,
    )
    return llm, client.chat.completions


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    # Backoff must not slow the suite; we never assert on real wall-clock waits.
    monkeypatch.setattr("triage.llm.time.sleep", lambda _seconds: None)


def test_openai_llm_returns_a_completion_from_the_wire_response() -> None:
    llm, _ = _make_llm([_Response(_valid_json(), total_tokens=11)])
    result = llm.complete(_MESSAGES, _Reply)
    assert result.value.verdict == "benign"
    assert result.tokens == 11
    assert result.model == "wire-model"
    assert result.prompt_hash == prompt_hash(_MESSAGES)


def test_openai_llm_requests_response_format_when_supported() -> None:
    llm, completions = _make_llm([_Response(_valid_json())], supports_json_schema=True)
    llm.complete(_MESSAGES, _Reply)
    assert "response_format" in completions.requests[0]
    assert completions.requests[0]["response_format"]["type"] == "json_schema"


def test_openai_llm_omits_response_format_when_unsupported() -> None:
    # Ollama / some vLLM lack json_schema — the prompt-instructed path carries it.
    llm, completions = _make_llm([_Response(_valid_json())], supports_json_schema=False)
    llm.complete(_MESSAGES, _Reply)
    sent = completions.requests[0]
    assert "response_format" not in sent
    # The schema instruction is the load-bearing fallback — it must be present.
    assert any("JSON schema" in m["content"] for m in sent["messages"])


def test_openai_llm_always_prompt_instructs_json_even_when_supported() -> None:
    # RFC-0001: prompt-instructed JSON is ALWAYS sent; response_format only adds to it.
    llm, completions = _make_llm([_Response(_valid_json())], supports_json_schema=True)
    llm.complete(_MESSAGES, _Reply)
    sent = completions.requests[0]
    assert "response_format" in sent
    assert any("JSON schema" in m["content"] for m in sent["messages"])


def test_openai_llm_retries_transport_errors_then_succeeds() -> None:
    llm, completions = _make_llm(
        [RuntimeError("connection reset"), RuntimeError("flaky"), _Response(_valid_json())],
    )
    result = llm.complete(_MESSAGES, _Reply)
    assert result.value.verdict == "benign"
    assert len(completions.requests) == 3


def test_openai_llm_raises_llm_error_when_transport_retries_exhaust() -> None:
    llm, completions = _make_llm(
        [RuntimeError("down"), RuntimeError("down"), RuntimeError("down")],
    )
    with pytest.raises(LLMError):
        llm.complete(_MESSAGES, _Reply)
    assert len(completions.requests) == 3  # exactly three attempts


def test_openai_llm_repairs_one_malformed_wire_response_then_succeeds() -> None:
    llm, completions = _make_llm([_Response("not json"), _Response(_valid_json())])
    result = llm.complete(_MESSAGES, _Reply)
    assert result.value.verdict == "benign"
    # Two logical calls (original + repair), each its own 3x budget — here 1 each.
    assert len(completions.requests) == 2
    # The original call appends the schema instruction (+1); the repair call also
    # appends the corrective nudge ahead of it (+2).
    assert len(completions.requests[0]["messages"]) == len(_MESSAGES) + 1
    assert len(completions.requests[1]["messages"]) == len(_MESSAGES) + 2


def test_openai_llm_raises_llm_error_when_repair_also_malformed() -> None:
    llm, _ = _make_llm([_Response("not json"), _Response("still not json")])
    with pytest.raises(LLMError):
        llm.complete(_MESSAGES, _Reply)


def test_openai_llm_treats_missing_content_as_malformed() -> None:
    # ``content=None`` (no text) is malformed structured output: it flows through
    # the repair path and, when both attempts are empty, raises LLMError.
    first = _Response(_valid_json())
    first.choices[0].message.content = None
    second = _Response(_valid_json())
    second.choices[0].message.content = None
    llm, _ = _make_llm([first, second])
    with pytest.raises(LLMError):
        llm.complete(_MESSAGES, _Reply)


def test_openai_llm_handles_missing_usage_as_zero_tokens() -> None:
    response = _Response(_valid_json())
    response.usage = None
    llm, _ = _make_llm([response])
    result = llm.complete(_MESSAGES, _Reply)
    assert result.tokens == 0


# --------------------------------------------------------------------------- #
# Construction from environment                                               #
# --------------------------------------------------------------------------- #


def test_constructing_from_env_requires_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        OpenAICompatibleLLM()


def test_constructing_from_env_builds_a_client(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _DummyClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    monkeypatch.setattr("triage.llm.OpenAI", _DummyClient)
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("LLM_MODEL", "llama3")
    llm = OpenAICompatibleLLM()
    assert llm.model == "llama3"
    assert captured["api_key"] == "sk-test"
    assert captured["base_url"] == "http://localhost:11434/v1"


def test_constructing_from_env_defaults_model_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    class _DummyClient:
        def __init__(self, **_kwargs: object) -> None: ...

    monkeypatch.setattr("triage.llm.OpenAI", _DummyClient)
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    llm = OpenAICompatibleLLM()
    assert llm.model  # a non-empty default model name is set
