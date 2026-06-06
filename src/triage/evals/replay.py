"""Replay Mode — record once, re-serve deterministically and key-free (US-0003).

Live mode burns tokens and needs an ``LLM_API_KEY``; Replay Mode re-serves the
LLM responses a prior run produced, keyed by ``prompt_hash`` — so CI and
eval-runner development run with no key and no network, and any external evaluator
re-scores a frozen run deterministically (the ``eval-authoring`` skill: Replay
Mode doubles as the tool-neutral recorded experiment).

**Why a dedicated cache, not the journal (landed-code reconciliation):** the
``llm_call`` journal event carries only metadata (``purpose``, ``model``,
``prompt_hash``, ``tokens``, ``latency_ms``) — never the response content. The
plan and verdict *outputs* are recoverable (``plan_created.steps`` /
``verdict.verdict``), but the executor's per-step ``reason`` decision
(``continue`` / ``revise_plan`` / ``conclude``) is emitted as ``llm_call``
metadata only and never journaled. So the journal alone cannot reconstruct a
replayable Run. The skill says "re-serve from a prior run's journal"; the landed
journal cannot carry reason responses — this is a skill-vs-landed-code conflict,
resolved the way the task sanctions ("journal/**cache**"; "define the on-disk
replay-cache layout … alongside each case") by recording a purpose-built cache.

**On-disk layout** (one cache per Golden Case, alongside it):

    src/triage/evals/cases/<case-name>.yaml
    src/triage/evals/cases/<case-name>.replay.json

The replay file is a single JSON object::

    {
      "schema_version": 1,
      "model": "gpt-4o-mini",
      "entries": { "<prompt_hash>": "<response model_dump_json string>", ... }
    }

The key is ``prompt_hash`` over the caller's *original* rendered messages
(pre-injection — the same hash the planner/executor/verdict compute), so it is
stable across runs and model swaps. The value is the *validated* response
re-serialized with ``model_dump_json`` — it round-trips back through Pydantic
``model_validate_json`` cleanly, so recording never captures raw wire strings and
the repair path is irrelevant to the cache.

A miss (the prompt changed → its hash is absent) raises ``ReplayMiss`` — NOT an
``LLMError``: ``_BaseLLM.complete`` catches ``LLMError`` to trigger its one repair
re-prompt, which would swallow a miss into a doomed retry instead of failing
loudly. ``ReplayMiss`` is a sibling typed error, so a miss surfaces with which
purpose/step is missing (the skill: "a replay miss must fail loudly").
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel, ValidationError

from triage.errors import TriageError
from triage.llm import Completion, prompt_hash

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from triage.llm import LLM, Message

T = TypeVar("T", bound=BaseModel)

REPLAY_SCHEMA_VERSION = 1
"""The on-disk replay-cache schema version (bump on a breaking layout change)."""

_REPLAY_SUFFIX = ".replay.json"


class ReplayError(TriageError):
    """Base for Replay Mode faults — a sibling of ``LLMError``, never a subclass.

    Subclassing ``LLMError`` would let ``_BaseLLM.complete`` catch a miss and burn
    its one repair attempt instead of failing loudly, so the whole replay error
    family hangs off ``TriageError`` directly.
    """


class ReplayMiss(ReplayError):  # noqa: N818 — "Replay Miss" is the ubiquitous-language term (eval-authoring skill); an "Error" suffix would rename a domain concept.
    """No recorded response for a ``prompt_hash`` — the prompt changed since record.

    Carries the missing hash so the runner can report which purpose/step missed
    (the prompt-change regression workflow: a miss means a prompt edit needs a
    re-record, never a silent fall back to live).
    """

    def __init__(self, digest: str) -> None:
        """Record the missing ``prompt_hash`` for the loud failure message."""
        super().__init__(f"replay cache miss for prompt_hash {digest} — re-record this case")
        self.prompt_hash = digest


class ReplayCacheError(ReplayError):
    """A replay cache file was missing, unreadable, or the wrong shape."""


def replay_path(case_path: Path) -> Path:
    """Return the replay-cache path that sits alongside ``case_path``.

    ``cases/benign.yaml`` -> ``cases/benign.replay.json`` — the one-cache-per-case
    layout the recording command writes and the runner reads.
    """
    return case_path.with_suffix(_REPLAY_SUFFIX)


class ReplayCache:
    """An in-memory ``prompt_hash -> response-JSON`` map, loadable/dumpable to disk."""

    def __init__(self, entries: dict[str, str], *, model: str) -> None:
        """Hold the recorded entries and the model that produced them."""
        self._entries = dict(entries)
        self.model = model

    @classmethod
    def load(cls, path: Path) -> ReplayCache:
        """Load a replay cache from its JSON file.

        Raises:
            ReplayCacheError: The file is missing, not JSON, or the wrong shape.
        """
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"replay cache not found or unreadable: {path}"
            raise ReplayCacheError(msg) from exc
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            msg = f"replay cache is not valid JSON: {path}"
            raise ReplayCacheError(msg) from exc
        entries = document.get("entries") if isinstance(document, dict) else None
        if not isinstance(entries, dict):
            msg = f"replay cache must have an 'entries' object: {path}"
            raise ReplayCacheError(msg)
        model = document.get("model") if isinstance(document, dict) else None
        return cls(
            {str(k): str(v) for k, v in entries.items()},
            model=str(model) if isinstance(model, str) else "replay",
        )

    def dump(self, path: Path) -> None:
        """Write the cache to ``path`` as the documented single-object JSON file."""
        document = {
            "schema_version": REPLAY_SCHEMA_VERSION,
            "model": self.model,
            "entries": self._entries,
        }
        path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    def get(self, digest: str) -> str:
        """Return the recorded response JSON for ``digest``.

        Raises:
            ReplayMiss: No entry for ``digest`` — the prompt changed since record.
        """
        try:
            return self._entries[digest]
        except KeyError as exc:
            raise ReplayMiss(digest) from exc

    def put(self, digest: str, response_json: str) -> None:
        """Record (or overwrite) the response JSON for ``digest``."""
        self._entries[digest] = response_json

    def __len__(self) -> int:
        """Return how many distinct prompts the cache has recorded."""
        return len(self._entries)


class RecordingLLM:
    """Decorates any ``LLM``, capturing each ``prompt_hash -> response`` into a cache.

    Wrap the real ``OpenAICompatibleLLM`` (integration recording) or a scripted
    ``FakeLLM`` (the tests-only synthetic fixture) — every ``complete`` delegates to
    the inner LLM, then records the *validated* response (``model_dump_json``) under
    the ``prompt_hash`` of the caller's original messages, so the resulting cache
    drives ``ReplayLLM`` with no further live calls.
    """

    def __init__(self, inner: LLM, cache: ReplayCache) -> None:
        """Bind the inner LLM and the cache to record into."""
        self._inner = inner
        self.cache = cache

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Callable[[str, int, str], None] | None = None,
        on_repair: Callable[[str, str], None] | None = None,
    ) -> Completion[T]:
        """Delegate to the inner LLM and record the validated response by hash."""
        completion = self._inner.complete(
            messages,
            response_model,
            on_transport_retry=on_transport_retry,
            on_repair=on_repair,
        )
        self.cache.put(prompt_hash(messages), completion.value.model_dump_json())
        return completion


class ReplayLLM:
    """Serves recorded responses by ``prompt_hash`` — key-free and deterministic.

    A direct ``LLM`` Protocol impl (not a ``_BaseLLM`` subclass): it owns its own
    ``complete`` so a cache miss raises ``ReplayMiss`` loudly instead of being
    caught by the inherited repair loop. It hashes the caller's *original* messages
    (the same pre-injection hash the recorder used), looks up the recorded response
    JSON, and validates it straight into ``response_model``.
    """

    def __init__(self, cache: ReplayCache) -> None:
        """Bind the replay cache the responses are served from."""
        self._cache = cache
        self.model = cache.model

    @classmethod
    def from_path(cls, path: Path) -> ReplayLLM:
        """Load a replay cache from disk and build a ``ReplayLLM`` over it."""
        return cls(ReplayCache.load(path))

    def complete(
        self,
        messages: Sequence[Message],
        response_model: type[T],
        *,
        on_transport_retry: Callable[[str, int, str], None] | None = None,  # noqa: ARG002 — ReplayLLM never retries transport; callback ignored.
        on_repair: Callable[[str, str], None] | None = None,  # noqa: ARG002 — ReplayLLM never repairs; callback ignored.
    ) -> Completion[T]:
        """Serve the recorded response for these messages, or fail loudly.

        Raises:
            ReplayMiss: No recorded response for this prompt — the prompt changed.
            ReplayError: The recorded response no longer validates against the
                model (a schema drift between record and replay).
        """
        started = time.monotonic()
        digest = prompt_hash(messages)
        raw = self._cache.get(digest)
        try:
            value = response_model.model_validate_json(raw)
        except ValidationError as exc:
            msg = (
                f"recorded response for {digest} no longer validates against "
                f"{response_model.__name__}: {exc}"
            )
            raise ReplayError(msg) from exc
        latency_ms = int((time.monotonic() - started) * 1000)
        return Completion(
            value=value,
            model=self.model,
            prompt_hash=digest,
            tokens=0,
            latency_ms=latency_ms,
        )
