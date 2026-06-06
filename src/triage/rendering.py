"""Shared rendering helpers — a leaf module consumed by planner, executor, and verdict.

All three prompt-rendering modules and the LLM client share the same small set of
text-manipulation primitives.  This leaf centralises them so there is exactly one
implementation of each and callers cannot drift.

Dependency direction: only stdlib + ``triage.llm`` (for ``Message``) at runtime;
``triage.journal.Journal`` is imported under ``TYPE_CHECKING`` only (type hints,
never called at runtime from here).  Nothing in this module emits events or calls
the LLM — it is a pure string-transformation layer.

Callers that use ``journal_llm_callbacks`` must themselves emit the resulting
events; this module hands them the closures but never touches the journal directly.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable

    from triage.journal import Journal


class Message(TypedDict):
    """One rendered chat message — the on-the-wire shape passed to LLM.complete.

    Defined here (in the leaf rendering module) to avoid a circular import with
    ``triage.llm``: both ``triage.llm`` and ``triage.rendering`` need the type, and
    ``rendering`` must not import from ``llm`` (which would close a cycle through
    the callers).  ``triage.llm.Message`` and ``rendering.Message`` are structurally
    identical TypedDicts — any value of one satisfies the other (structural typing).
    """

    role: str
    content: str


_SENTINEL = "{{END_OF_STABLE}}"


def truncate(
    text: str,
    max_chars: int,
    *,
    marker_template: str = "…[truncated {n} chars]",
) -> str:
    """Return ``text`` truncated to ``max_chars``, with a trailing marker if cut.

    Args:
        text: The string to truncate.
        max_chars: Maximum number of characters to retain before the marker.
        marker_template: A format string whose ``{n}`` placeholder receives the
            count of dropped characters.  The default matches the observation-data
            truncation marker.  Pass ``"…"`` for the LLM-error repair marker.

    Returns:
        The original string if it fits; otherwise the first ``max_chars``
        characters followed by the formatted marker.
    """
    if len(text) <= max_chars:
        return text
    dropped = len(text) - max_chars
    marker = marker_template.format(n=dropped) if "{n}" in marker_template else marker_template
    return text[:max_chars] + marker


def dump_compact(obj: Any) -> str:  # noqa: ANN401 — accepts any JSON-serialisable value.
    """Serialise ``obj`` as compact JSON with stable key order.

    ``sort_keys=True`` and ``ensure_ascii=False`` so two calls with the same
    logical data produce the same bytes, and Unicode is preserved verbatim.
    ``separators=(",", ":")`` drops the default whitespace so the output is as
    small as possible — matching the existing per-module JSON dumps exactly.
    """
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def dump_alert(alert: Any) -> str:  # noqa: ANN401 — Alert or any Pydantic model with model_dump.
    """Serialise a Pydantic alert model as compact, stable JSON.

    Calls ``alert.model_dump()`` and passes the result through ``dump_compact`` so
    the rendered bytes are stable across key-insertion-order variations.
    """
    return dump_compact(alert.model_dump())


def split_stable_dynamic(rendered: str) -> list[Message]:
    """Split a rendered prompt template on ``{{END_OF_STABLE}}`` into two messages.

    The stable message (instructions) is identical across calls and can be
    API-cached; the dynamic message carries the per-call data.  If the sentinel is
    absent (e.g. during unit tests with a stripped-down template), the entire
    rendered text is returned as a single message — the fallback that all three
    renderers share.

    The sentinel line is consumed (not included in either message).  Leading and
    trailing whitespace is stripped from the two halves so the rendered messages are
    clean regardless of how the template author placed the sentinel.
    """
    stable, sep, dynamic = rendered.partition(_SENTINEL + "\n")
    if not sep:
        return [Message(role="user", content=rendered)]
    return [
        Message(role="user", content=stable.rstrip()),
        Message(role="user", content=dynamic.lstrip()),
    ]


_TOOL_SAFE_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _sanitize_tool_name(tool: str) -> str:
    """Return ``tool`` with every character outside ``[A-Za-z0-9_-]`` replaced by ``_``.

    The ``tool`` attribute value in ``<observation>`` tags is LLM-authored
    (``PlanStep.tool``), and the planner is steered by attacker-controlled alert
    content (ADR-0005).  A hostile name like ``lookup_user" ok="true`` would forge
    the ``ok`` attribute or inject sibling tags into the evidence block fed to the
    reasoner and verdict synthesizer, undermining the zero-evidence clamp.

    Sanitizing (rather than quoting via ``xml.sax.saxutils.quoteattr``) preserves
    the rendered bytes for all legitimate registry names — ``lookup_user``,
    ``query_logs``, ``get_asset_info``, ``check_reputation`` — so all 30 replay
    caches remain valid.  ``step`` and ``ok`` are int/bool-derived and are never
    interpolated as raw strings.
    """
    return "".join(c if c in _TOOL_SAFE_CHARS else "_" for c in tool)


def observation_tag(step: int, tool: str, ok: bool, body: str) -> str:
    """Render one ``<observation>`` XML tag with step, tool, ok, and body.

    Used by executor and verdict renderers to produce byte-identical observation
    markup — a single source of truth for the tag format so the two renderers
    cannot drift.

    The ``tool`` attribute value is sanitized via ``_sanitize_tool_name`` before
    interpolation: every character outside ``[A-Za-z0-9_-]`` is replaced by ``_``.
    This prevents an LLM-hallucinated tool name from injecting attribute-forging
    or sibling-tag payloads into the evidence block (ADR-0005 threat).  ``step``
    is an ``int`` and ``ok`` is bool-derived — neither carries interpolation risk.

    Args:
        step: The executor step number (from the ``ObservationEntry`` or the
            journal's ``tool_called`` event).
        tool: The tool name (sanitized before rendering).
        ok: Whether the tool call succeeded.
        body: The compact-JSON body to embed inside the tag.

    Returns:
        A single-line ``<observation step="N" tool="T" ok="B">body</observation>``
        string.
    """
    ok_str = "true" if ok else "false"
    safe_tool = _sanitize_tool_name(tool)
    return f'<observation step="{step}" tool="{safe_tool}" ok="{ok_str}">{body}</observation>'


def journal_llm_callbacks(
    journal: Journal,
    purpose: str,
) -> tuple[Callable[[str, int, str], None], Callable[[str, str], None]]:
    """Return the ``(on_transport_retry, on_repair)`` closure pair for an LLM call.

    Every structured-output call in planner, executor, and verdict passes these two
    callbacks to ``llm.complete`` so retry and repair events appear in the journal.
    The closures capture ``journal`` and ``purpose``; ``llm.py`` calls them with an
    empty-string purpose (it is purpose-unaware) so the closures use the captured
    value instead.

    Returns:
        A ``(on_transport_retry, on_repair)`` tuple ready to be unpacked into
        ``llm.complete(messages, model, on_transport_retry=..., on_repair=...)``.
    """

    def on_transport_retry(_p: str, attempt: int, error: str) -> None:
        journal.emit(
            "llm_transport_retry",
            {"purpose": purpose, "attempt": attempt, "error": error},
        )

    def on_repair(_p: str, error: str) -> None:
        journal.emit("llm_repair", {"purpose": purpose, "error": error})

    return on_transport_retry, on_repair
