"""The LLM boundary — one port, two implementations (RFC-0001 §LLM boundary / ADR-0002).

The whole agent talks to exactly one seam, the ``LLM`` Protocol: callers pass a
rendered message list plus a Pydantic ``response_model`` and get a validated
instance back, wrapped in a ``Completion`` that also carries the ``llm_call``
journal metadata (``model``, ``prompt_hash``, ``tokens``, ``latency_ms``). The
caller owns ``purpose`` and the ``journal.emit`` call — ``llm.py`` never emits.

Two reliability mechanisms live here and must not tangle:

* **Transport retry 3x** with exponential backoff, inside ``_raw_complete`` — a
  flaky connection to the wire endpoint.
* **One repair re-prompt** on malformed *structured output*, in the shared
  ``complete`` loop — the model answered, but the JSON would not parse or
  validate. The repair attempt is a fresh logical call, so it gets its own 3x
  transport budget. A second malformed answer raises ``LLMError`` (US-0001 AC:
  caller-visible failure for a degraded verdict).

The repair path is **load-bearing**, not a rare corner: Ollama and some vLLM
builds lack ``response_format=json_schema``, so the prompt-instructed-JSON +
parse + repair fallback is how the local-model bonus works. The two JSON-format
strings below (the schema instruction and the repair nudge) are LLM-protocol
mechanics with no domain content, so they live here as constants rather than in
``prompts/*.md`` (which holds only the planner/reasoner/verdict/judge prompts).

Every failure on the ``complete`` call path converts to ``LLMError`` here — no
other exception crosses this seam. Missing configuration at *construction* time
raises ``ConfigError`` (its dedicated type), which is a build-time fault, not a
call-time one.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, Protocol, TypedDict, TypeVar, runtime_checkable

from openai import OpenAI
from pydantic import BaseModel, ValidationError

from triage.errors import ConfigError, LLMError
from triage.rendering import truncate as _rendering_truncate

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

T = TypeVar("T", bound=BaseModel)

_MAX_TRANSPORT_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 0.5
_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_TIMEOUT_SECONDS = 30.0

# LLM-protocol mechanics (no domain content — deliberately not a prompts/ file).
_JSON_INSTRUCTION = (
    "Respond with a single JSON object that conforms exactly to this JSON schema. "
    "Output only the JSON, with no markdown fences or prose:\n"
    "<output_schema>\n{schema}\n</output_schema>"
)
_REPAIR_NUDGE = (
    "Your previous response could not be parsed as JSON matching the required "
    "schema. Reply again with only a single valid JSON object conforming to it. "
    "Error: {error}"
)
_REPAIR_ERROR_MAX_CHARS = 500


def _truncate_error(error: str) -> str:
    """Truncate error strings in repair nudges to avoid leaking oversized payloads.

    Delegates to ``rendering.truncate`` — the single implementation shared across
    the codebase.  The ``"…"`` marker (no ``{n}`` count) is the repair-nudge
    convention: the error is already a summary; recording how many chars were
    dropped adds no value for the repair re-prompt.
    """
    return _rendering_truncate(error, _REPAIR_ERROR_MAX_CHARS, marker_template="…")


class Message(TypedDict):
    """One rendered chat message — the on-the-wire shape callers pass in."""

    role: str
    content: str


@dataclass(frozen=True)
class Completion(Generic[T]):
    """A validated response plus the metadata the caller journals as ``llm_call``.

    The fields are exactly the ``llm_call`` payload minus ``purpose`` (which the
    caller owns), so a caller emits the event without reaching into ``llm.py``.
    """

    value: T
    model: str
    prompt_hash: str
    tokens: int
    latency_ms: int


@runtime_checkable
class LLM(Protocol):
    """The single structured-output port the whole agent talks to."""

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Callable[[str, int, str], None] | None = None,
        on_repair: Callable[[str, str], None] | None = None,
    ) -> Completion[T]:
        """Render, call, parse, and validate — returning a wrapped instance.

        Args:
            messages: The already-rendered chat messages (prompts are rendered by
                the caller; this seam adds no domain content).
            response_model: The Pydantic model the reply must validate against.
            on_transport_retry: Optional callback invoked when a transport attempt
                fails and will be retried.  Receives ``(purpose, attempt, error)``
                — but because ``LLM`` is purpose-unaware, callers bind purpose in
                their own closure and can ignore it here.  The callback signature
                is ``(purpose: str, attempt: int, error: str) -> None``; a caller
                that does not need all three args ignores them in its closure.
                ``llm.py`` never emits journal events — this callback lets the
                caller do so (mirrors ``before_attempt`` in tools/base.py).
            on_repair: Optional callback invoked when the repair re-prompt fires.
                Receives ``(purpose, error)`` for the same reason.

        Returns:
            A ``Completion`` carrying the validated instance and ``llm_call``
            metadata.

        Raises:
            LLMError: The reply was malformed after one repair re-prompt, or the
                transport failed after its retries.
        """
        ...  # pragma: no cover  # Protocol signature, never executed.


def prompt_hash(messages: Sequence[Message]) -> str:
    """Return a model-agnostic sha256 over the full rendered message list.

    Keys ``llm_call`` journal events and the Replay Mode cache, so it depends
    only on the messages — never on which model answers.
    """
    canonical = json.dumps(
        [{"role": m["role"], "content": m["content"]} for m in messages],
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_into(text: str | None, response_model: type[T]) -> T:
    """Parse ``text`` as JSON and validate it into ``response_model``.

    Raises:
        LLMError: The text was missing, not JSON, or failed model validation —
            i.e. malformed structured output, which the repair loop catches.
    """
    if text is None:
        msg = "the model returned no content"
        raise LLMError(msg)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"the model reply was not valid JSON: {exc}"
        raise LLMError(msg) from exc
    try:
        return response_model.model_validate(data)
    except ValidationError as exc:
        msg = f"the model reply did not match the schema: {exc}"
        raise LLMError(msg) from exc


class _BaseLLM:
    """Shared completion loop: hash, call, parse, and the one repair re-prompt.

    Subclasses implement only ``_raw_complete`` — the wire transport. The repair
    semantics live here so both impls exercise the exact same path, keeping
    ``FakeLLM`` honest about the behaviour ``OpenAICompatibleLLM`` ships.
    """

    model: str

    def _raw_complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Callable[[str, int, str], None] | None = None,
    ) -> tuple[str | None, int, str]:
        """Make one logical wire call; return ``(content, tokens, model)``.

        Implementations own their own transport retries; this method represents a
        single *logical* completion, which the repair loop may invoke twice.
        The ``on_transport_retry`` callback, if supplied, is forwarded so that the
        real impl can fire it on each failed attempt before sleeping.
        """
        raise NotImplementedError  # pragma: no cover  # overridden by every impl.

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Callable[[str, int, str], None] | None = None,
        on_repair: Callable[[str, str], None] | None = None,
    ) -> Completion[T]:
        """Render, call, parse, validate, and repair once on malformed output.

        Args:
            messages: The already-rendered chat messages.
            response_model: The Pydantic model the reply must validate against.
            on_transport_retry: Optional callback fired when a transport attempt
                fails and will be retried; receives ``(purpose, attempt, error)``.
                ``llm.py`` is purpose-unaware — callers bind purpose in their
                closure (mirrors ``before_attempt`` / ``after_attempt`` in
                tools/base.py).
            on_repair: Optional callback fired when the repair re-prompt fires;
                receives ``(purpose, error)``.
        """
        started = time.monotonic()
        digest = prompt_hash(messages)
        content, tokens, model = self._raw_complete(
            messages, response_model, on_transport_retry=on_transport_retry
        )
        try:
            value = _parse_into(content, response_model)
        except LLMError as first_error:
            truncated = _truncate_error(str(first_error))
            if on_repair is not None:
                on_repair("", truncated)
            repair_messages = [
                *messages,
                Message(role="user", content=_REPAIR_NUDGE.format(error=truncated)),
            ]
            content, tokens, model = self._raw_complete(
                repair_messages, response_model, on_transport_retry=on_transport_retry
            )
            value = _parse_into(content, response_model)
        latency_ms = int((time.monotonic() - started) * 1000)
        return Completion(
            value=value,
            model=model,
            prompt_hash=digest,
            tokens=tokens,
            latency_ms=latency_ms,
        )


class OpenAICompatibleLLM(_BaseLLM):
    """The real impl over the ``openai`` SDK wire format (ADR-0002).

    Provider, endpoint, and model are env config (``LLM_API_KEY``,
    ``LLM_BASE_URL``, ``LLM_MODEL``); the client is injectable so Tier A tests
    drive a mock transport with no network and no key. ``supports_json_schema``
    gates the native ``response_format`` — off for Ollama/vLLM, which fall back
    to the prompt-instructed + repair path.
    """

    def __init__(
        self,
        *,
        client: Any = None,  # noqa: ANN401 — any openai-compatible client (real or mock).
        model: str | None = None,
        supports_json_schema: bool = True,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Build from an injected client, or from env when none is supplied."""
        if client is None:
            client, model = self._client_from_env(timeout)
        self._client = client
        self.model = model or os.environ.get("LLM_MODEL") or _DEFAULT_MODEL
        self._supports_json_schema = supports_json_schema

    @staticmethod
    def _client_from_env(timeout: float) -> tuple[OpenAI, str]:
        """Construct an ``OpenAI`` client from env, or fail with ``ConfigError``."""
        api_key = os.environ.get("LLM_API_KEY")
        if not api_key:
            msg = "LLM_API_KEY is not set — cannot construct the LLM client"
            raise ConfigError(msg)
        client = OpenAI(
            api_key=api_key,
            base_url=os.environ.get("LLM_BASE_URL") or None,
            timeout=timeout,
        )
        return client, os.environ.get("LLM_MODEL") or _DEFAULT_MODEL

    def _raw_complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Callable[[str, int, str], None] | None = None,
    ) -> tuple[str | None, int, str]:
        """One logical completion with 3x transport retry + exponential backoff.

        When a transport attempt fails and another will be made,
        ``on_transport_retry("", attempt, error)`` is called before the sleep so
        the caller can journal a ``llm_transport_retry`` event.  ``purpose`` is
        always the empty string here because ``_raw_complete`` is purpose-unaware;
        callers bind the real purpose string in their closure.
        """
        schema = response_model.model_json_schema()
        # ALWAYS prompt-instruct the JSON (RFC-0001): native ``response_format`` is
        # an optimisation on top, absent on Ollama/some vLLM, and weakly honoured
        # by others — the instruction is the load-bearing floor that always holds.
        instruction = Message(
            role="system",
            content=_JSON_INSTRUCTION.format(schema=json.dumps(schema)),
        )
        request: dict[str, Any] = {
            "model": self.model,
            "messages": [*messages, instruction],
        }
        if self._supports_json_schema:
            request["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": response_model.__name__, "schema": schema},
            }
        last_error: Exception | None = None
        for attempt in range(_MAX_TRANSPORT_ATTEMPTS):
            try:
                response = self._client.chat.completions.create(**request)
            except Exception as exc:  # noqa: BLE001 — every transport failure converts here.
                last_error = exc
                if attempt < _MAX_TRANSPORT_ATTEMPTS - 1:
                    if on_transport_retry is not None:
                        on_transport_retry("", attempt + 1, str(exc))
                    time.sleep(_BACKOFF_BASE_SECONDS * (2**attempt))
                continue
            usage = getattr(response, "usage", None)
            tokens = getattr(usage, "total_tokens", 0) if usage is not None else 0
            return response.choices[0].message.content, tokens, response.model
        msg = f"LLM transport failed after {_MAX_TRANSPORT_ATTEMPTS} attempts: {last_error}"
        raise LLMError(msg) from last_error


class FakeLLM(_BaseLLM):
    """Test impl: scripted raw replies driving the real shared completion loop.

    Each entry in ``script`` is a raw reply string the model would return; pass a
    malformed string to exercise the repair path deterministically (US-0001 AC).
    The shared ``_BaseLLM.complete`` does the parse/repair, so ``FakeLLM`` proves
    the same behaviour the real impl ships — they cannot drift.
    """

    def __init__(
        self,
        script: Sequence[str],
        *,
        model: str = "fake-model",
        tokens: int = 0,
    ) -> None:
        """Queue the scripted raw replies and the canned metadata to report."""
        self._script = list(script)
        self.model = model
        self._tokens = tokens
        self.calls = 0
        self.last_messages: list[Message] = []
        self.messages_by_call: list[list[Message]] = []

    def _raw_complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],  # noqa: ARG002 — part of the shared transport signature.
        *,
        on_transport_retry: Callable[[str, int, str], None] | None = None,  # noqa: ARG002 — FakeLLM never retries transport.
    ) -> tuple[str | None, int, str]:
        """Pop the next scripted reply; record the messages it was asked with."""
        self.calls += 1
        self.last_messages = list(messages)
        self.messages_by_call.append(list(messages))
        if not self._script:
            msg = "FakeLLM script exhausted — no scripted reply for this call"
            raise LLMError(msg)
        return self._script.pop(0), self._tokens, self.model
