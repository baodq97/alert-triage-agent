"""The TI mini-loop: ``enrich(ioc_type, ioc_value, *, llm, journal, registry) -> TIReport | None``.

Architecture (RFC-0002 §Decision — "mini" means no planner/reasoner):

    for each TI tool in the registry (≤ 3 tool calls, fixed cap):
        execute_tool → ToolResult (ok=True or ok=False)
        journal tool_called + tool_result (agent="threat-intel")

    one LLM synthesis call → TIReport (lax Pydantic validation + 1 repair)
    journal llm_call (agent="threat-intel")

The loop is deliberately NOT a full ReAct planner/reasoner — RFC-0002 says
"mini"; three tools and one synthesis call is the v1 design. Over-engineering
is explicitly rejected by the RFC. The retry/repair policy comes free from
``llm.py`` (``_BaseLLM.complete`` handles transport retries and one repair
attempt).

Seam contract for group B (executor integration):

* ``enrich`` returns ``TIReport`` on success (schema-validated Pydantic instance).
* ``enrich`` returns ``None`` on any ``LLMError`` (transport retries + repair
  exhausted). The caller (group B executor integration) maps ``None`` to an
  ``ok=False`` ``ToolResult`` Observation — the primary run never crashes on a
  TI failure.
* Tool failures (``ToolResult(ok=False)``) are passed to the LLM as degraded
  evidence — the LLM synthesis still runs; only an ``LLMError`` returns ``None``.
* Every journal event carries ``agent="threat-intel"`` so the primary run's
  journal shows a readable hierarchical trace (RFC-0002 §Decision).
* The module raises no exception beyond ``LLMError`` — all ``ToolError`` instances
  are caught inside ``execute_tool`` and surface as ``ToolResult(ok=False)``.
  The ``LLMError`` is swallowed here and ``None`` is returned so no exception
  crosses the group-B seam.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from triage.errors import LLMError
from triage.rendering import dump_compact, observation_tag, split_stable_dynamic, truncate
from triage.threat_intel.models import TIReport
from triage.threat_intel.tools import TIFixtureDataSource
from triage.tools.base import execute_tool

if TYPE_CHECKING:
    from triage.journal import Journal
    from triage.llm import LLM
    from triage.models import ToolResult
    from triage.threat_intel.tools import TIToolRegistry

_PROMPT_PATH = Path(__file__).parent.parent.parent.parent / "prompts" / "threat_intel.md"
_OBSERVATION_MAX_CHARS = 4000


def _load_prompt() -> str:
    """Read the TI synthesis prompt from ``prompts/threat_intel.md``."""
    return _PROMPT_PATH.read_text(encoding="utf-8")


def _render_tool_results(results: list[dict[str, Any]]) -> str:
    """Render tool results as observation tags for the synthesis prompt."""
    parts = []
    for i, entry in enumerate(results, start=1):
        tool_name = entry["tool"]
        ok = entry["ok"]
        # Use `ok` as the authoritative branch rather than truthiness of `data`:
        # an ok=True result with data={} (empty but valid) must render as data,
        # not fall through to the error branch (F4 fix — QA finding).
        if ok:
            body_raw = dump_compact(entry.get("data") if entry.get("data") is not None else {})
        else:
            body_raw = dump_compact({"error": entry.get("error", "")})
        body = truncate(body_raw, _OBSERVATION_MAX_CHARS)
        parts.append(observation_tag(i, tool_name, ok, body))
    return "\n".join(parts)


def enrich(
    ioc_type: str,
    ioc_value: str,
    *,
    llm: LLM,
    journal: Journal,
    registry: TIToolRegistry,
) -> TIReport | None:
    """Run the TI mini-loop for one external IOC and return a validated TIReport.

    Calls all registered TI tools (≤3), synthesizes results with one LLM call,
    and returns a schema-validated ``TIReport``.

    All journal events are tagged ``agent="threat-intel"`` (RFC-0002 §Decision).

    Args:
        ioc_type: The classifier-determined IOC type (``"public_ip"`` | ``"domain"``
            | ``"hash"``).  Passed into the prompt; NOT re-classified here.
        ioc_value: The raw IOC string (IP address, domain, or hash).
        llm: The LLM port (same instance as the primary loop uses).
        journal: The run's journal (same instance as the primary loop uses;
            events are distinguished by ``agent="threat-intel"``).
        registry: The TI tool registry (exposes the three read-only TI tools).

    Returns:
        A validated ``TIReport`` on success, or ``None`` when the LLM synthesis
        fails after retries and repair — the caller maps ``None`` to an ``ok=False``
        Observation.
    """
    source = TIFixtureDataSource()
    tool_results: list[dict[str, Any]] = []

    # --- Step 1: call all TI tools (fixed cap = len(registry.names()) ≤ 3) ---
    for step, tool_name in enumerate(registry.names(), start=1):
        tool = registry.get(tool_name)
        args = {"ioc": ioc_value}

        def _before(
            attempt: int,
            _name: str = tool_name,
            _step: int = step,
            _args: dict[str, Any] = args,
        ) -> None:
            journal.emit(
                "tool_called",
                {"step": _step, "tool": _name, "args": _args, "attempt": attempt},
                agent="threat-intel",
            )

        def _after(
            attempt: int,
            result: ToolResult,
            _step: int = step,
        ) -> None:
            payload: dict[str, Any] = {"step": _step, "attempt": attempt, "ok": result.ok}
            if result.ok:
                payload["data"] = result.data
            else:
                payload["error"] = result.error
            journal.emit("tool_result", payload, agent="threat-intel")

        result = execute_tool(tool, args, source, before_attempt=_before, after_attempt=_after)
        tool_results.append(
            {
                "tool": tool_name,
                "ok": result.ok,
                "data": result.data,
                "error": result.error,
            }
        )

    # --- Step 2: one LLM synthesis call ---
    rendered_observations = _render_tool_results(tool_results)

    prompt_template = _load_prompt()
    rendered = (
        prompt_template.replace("{{IOC_TYPE}}", ioc_type)
        .replace("{{IOC_VALUE}}", ioc_value)
        .replace("{{TOOL_RESULTS}}", rendered_observations)
        .replace("{{TOOL_SPECS}}", dump_compact(registry.specs()))
    )

    messages = split_stable_dynamic(rendered)

    # Build agent-tagged callbacks for the LLM port — journal_llm_callbacks
    # emits with the default agent; these closures override to "threat-intel" so
    # every event in the TI mini-loop carries the correct agent tag (RFC-0002).
    def _ti_on_transport_retry(purpose: str, attempt: int, error: str) -> None:
        journal.emit(
            "llm_transport_retry",
            {"purpose": purpose or "threat-intel-synthesis", "attempt": attempt, "error": error},
            agent="threat-intel",
        )

    def _ti_on_repair(purpose: str, error: str) -> None:
        journal.emit(
            "llm_repair",
            {"purpose": purpose or "threat-intel-synthesis", "error": error},
            agent="threat-intel",
        )

    try:
        completion = llm.complete(
            messages,
            TIReport,
            on_transport_retry=_ti_on_transport_retry,
            on_repair=_ti_on_repair,
        )
    except LLMError:
        return None

    journal.emit(
        "llm_call",
        {
            "purpose": "threat-intel-synthesis",
            "model": completion.model,
            "prompt_hash": completion.prompt_hash,
            "tokens": completion.tokens,
            "latency_ms": completion.latency_ms,
        },
        agent="threat-intel",
    )

    return completion.value
