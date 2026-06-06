"""Verdict synthesis — gathered material -> structured Verdict (RFC-0001 §Verdict).

One structured LLM call turns an Alert plus the investigation material (the tool
Observations and any Findings already drawn) into a ``Verdict``: severity,
evidence-backed findings, recommended actions, and a calibrated confidence. This
is the last LLM step of a Run, symmetric with the planner: the caller owns
``purpose`` and the journal emit, so this module emits ``llm_call`` (purpose
``"verdict"``, fields straight off the ``Completion``) and ``verdict`` (the full
verdict dump), in that order, after a successful completion (RFC-0001 §journal
lists ``verdict`` as an event; owning its emit here mirrors the planner emitting
``plan_created``).

Input seam (decoupled from the in-flight executor — this module never imports
``executor``): ``synthesize`` takes the Alert plus the gathered material
expressed only in ``models.py`` types (Observations as ``ToolResult``, carried
Findings as ``Finding``) and the upstream ``terminated_reason``. A later core
group adapts the executor's output into this seam.

``terminated_reason`` is an upstream fact, never an LLM judgment: it is set on
the returned Verdict from the parameter on both paths (overriding whatever the
model emitted on the success path), so a partial Run notes its partiality
deterministically.

**Action traceability (RFC-0003 §Module seams):** The
``_filter_traceable_actions`` backstop was removed from ``synthesize()`` and
re-homed to ``core._conclude_run`` as the canonical enforcement point (the verify
hook runs there).  ``synthesize()`` now passes LLM-returned actions through
unchanged; ``core._conclude_run`` applies the filter after running the verify hook.

DEGRADED PATH (US-0001 AC, load-bearing): if the LLM raises ``LLMError`` after
its internal repair attempt, the Run never crashes. A deterministic partial
``Verdict`` is built without LLM judgment:

* **severity = ``high``** (``DEGRADED_SEVERITY``) — a conservative floor. It is
  the enum (the free-form ``severity_hint`` is deliberately *not* reused: a hint
  is intake input, never the agent's own Severity). ``low``/``medium`` would
  dismiss an alert the agent never assessed; ``critical`` would overstate a
  certainty a failed run lacks. Severity is side-effect-free — it never triggers
  the gate (only a High-risk Action does) and the degraded path recommends no
  actions — so a high floor flags for human attention with no dangerous
  consequence.
* **confidence = ``0.0``** (``DEGRADED_CONFIDENCE``) — confidence measures this
  verdict's reliability, which a synthesis that failed has none of.
* the input **findings are carried through verbatim** (no synthesis from raw
  observations — that is the judgment the LLM was supposed to make);
* **no recommended actions** (proposing a response is judgment too);
* ``terminated_reason`` carried from the parameter.

The ``verdict`` event still fires for the degraded verdict (never exit without a
verdict) — and only that event: with no ``Completion`` there is no ``llm_call``
metadata to journal, exactly as the planner emits nothing on its error path.

Rendering is deterministic ``str.replace`` over labeled sentinels (never
``str.format`` — the payloads are JSON full of literal braces), with
``sort_keys=True`` so the rendered messages — and ``prompt_hash`` — never flap on
key order. ADR-0005: the alert payload, the observations, and the carried
findings are each dumped inside their own labeled untrusted block, apart from the
instructions; the template never branches on ``event_type``. The deterministic
verdict-safety checks (severity enum, Risk Policy allowlist, target-entity
invariant) live in code at the core/gate level, not in this prompt.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from triage.constants import EVT_LLM_CALL, EVT_VERDICT
from triage.errors import LLMError
from triage.models import Alert, Finding, ToolResult, Verdict
from triage.rendering import (
    dump_alert,
    dump_compact,
    journal_llm_callbacks,
    observation_tag,
    split_stable_dynamic,
    truncate,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from triage.journal import Journal
    from triage.llm import LLM, Message
    from triage.models import TerminatedReason

_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "verdict.md"

DEGRADED_SEVERITY = "high"
"""Conservative severity for the degraded verdict — a side-effect-free floor."""

DEGRADED_CONFIDENCE = 0.0
"""Confidence for the degraded verdict — a failed synthesis is unreliable."""

_NO_OBSERVATIONS = "(no observations were gathered)"
_NO_FINDINGS = "(no findings were drawn during the run)"
_OBSERVATION_DATA_MAX_CHARS = 4000


def _truncate_data(serialized: str) -> str:
    """Truncate an oversized serialized observation data field for LLM rendering.

    Delegates to ``rendering.truncate`` — the single implementation shared with
    executor.  The journal retains the full data; this helper affects only the
    LLM-facing render.
    """
    return truncate(serialized, _OBSERVATION_DATA_MAX_CHARS)


# Binary evidence gate: ok_count == 0 gets a hard confidence band and loses its
# recommended actions (no positive evidence to ground a response); ok_count >= 1
# means the LLM calibrates freely — the prompt provides prose guidance, this code
# enforces only the zero-evidence floor.
_ZERO_EVIDENCE_CONFIDENCE_MAX = 0.40
"""Confidence ceiling when no tool returned ok=true — agent has no positive evidence."""
_ZERO_EVIDENCE_CONFIDENCE_MIN = 0.30
"""Confidence floor when no tool returned ok=true — a verdict is still a decision."""


def _clamp_by_evidence(verdict: Verdict, observations: Sequence[ToolResult]) -> Verdict:
    """Enforce evidence-proportional confidence and strip unsupported actions.

    Only the zero-positive-evidence case receives a hard clamp — when every tool
    returned ``ok=False`` the LLM has no positive data to ground any action or
    high confidence. For 1+ positive results the prompt guides calibration freely.

    Rules:
    * ``ok_count >= 1``: no changes — the LLM calibrates based on the evidence.
    * ``ok_count == 0``: confidence clamped to ``[0.30, 0.40]``; all recommended
      actions stripped (there is no positive evidence to ground any response).
    """
    ok_count = sum(1 for obs in observations if obs.ok)
    if ok_count >= 1:
        return verdict
    updates: dict[str, object] = {}
    if verdict.confidence > _ZERO_EVIDENCE_CONFIDENCE_MAX:
        updates["confidence"] = _ZERO_EVIDENCE_CONFIDENCE_MAX
    elif verdict.confidence < _ZERO_EVIDENCE_CONFIDENCE_MIN:
        updates["confidence"] = _ZERO_EVIDENCE_CONFIDENCE_MIN
    if verdict.recommended_actions:
        updates["recommended_actions"] = []
    return verdict.model_copy(update=updates) if updates else verdict


class VerdictSynthesizer:
    """Turns an Alert plus gathered material into a Verdict via one LLM call."""

    def __init__(self, *, llm: LLM, journal: Journal) -> None:
        """Bind the explicit dependencies; the prompt template is loaded once.

        Args:
            llm: The structured-output port the verdict call goes through.
            journal: The port the ``llm_call`` and ``verdict`` events emit to.
        """
        self._llm = llm
        self._journal = journal
        self._template = _PROMPT_PATH.read_text(encoding="utf-8")

    def synthesize(
        self,
        alert: Alert,
        *,
        observations: Sequence[ToolResult] = (),
        observation_steps: Sequence[int] | None = None,
        findings: Sequence[Finding] = (),
        terminated_reason: TerminatedReason | None = None,
    ) -> Verdict:
        """Synthesize the final Verdict, degrading deterministically on LLM failure.

        Args:
            alert: The validated alert under investigation.
            observations: The tool Observations gathered during the run.
            observation_steps: The real executor step numbers corresponding to
                each observation (same length as ``observations``).  When
                provided, ``<observation step="...">`` uses these values so the
                prompt matches the journal's ``tool_called``/``tool_result``
                step numbers exactly — including any gaps caused by guard-refused
                steps.  When ``None`` (the default, and for tests that build
                ``ToolResult`` objects directly), steps are derived by
                ``enumerate(observations, start=1)``, which is byte-identical for
                gap-free runs.
            findings: The Findings already drawn during the run (carried through
                verbatim on the degraded path).
            terminated_reason: Why the run ended early, if it did — carried onto
                the returned Verdict on both paths (an upstream fact, never an LLM
                judgment).

        Returns:
            The structured ``Verdict`` — synthesized by the LLM, or a
            deterministic partial verdict if the LLM call failed. Never raises;
            a ``verdict`` event is always emitted.
        """
        messages = self._render(alert, observations, observation_steps, findings)
        purpose = "verdict"
        on_transport_retry, on_repair = journal_llm_callbacks(self._journal, purpose)
        try:
            completion = self._llm.complete(
                messages,
                Verdict,
                on_transport_retry=on_transport_retry,
                on_repair=on_repair,
            )
        except LLMError:
            verdict = self._degraded_verdict(findings, terminated_reason)
        else:
            self._journal.emit(
                EVT_LLM_CALL,
                {
                    "purpose": purpose,
                    "model": completion.model,
                    "prompt_hash": completion.prompt_hash,
                    "tokens": completion.tokens,
                    "latency_ms": completion.latency_ms,
                },
            )
            # ``terminated_reason`` is code-owned: override any value the model
            # emitted with the upstream fact.
            verdict = completion.value.model_copy(update={"terminated_reason": terminated_reason})
            # Enforce evidence-proportional confidence and action grounding.
            verdict = _clamp_by_evidence(verdict, observations)
        self._journal.emit(EVT_VERDICT, {"verdict": verdict.model_dump()})
        return verdict

    @staticmethod
    def _degraded_verdict(
        findings: Sequence[Finding],
        terminated_reason: TerminatedReason | None,
    ) -> Verdict:
        """Build the deterministic partial Verdict when the LLM call failed."""
        return Verdict(
            severity=DEGRADED_SEVERITY,
            findings=list(findings),
            recommended_actions=[],
            confidence=DEGRADED_CONFIDENCE,
            terminated_reason=terminated_reason,
        )

    def _render(
        self,
        alert: Alert,
        observations: Sequence[ToolResult],
        observation_steps: Sequence[int] | None,
        findings: Sequence[Finding],
    ) -> list[Message]:
        """Render the prompt as two messages: stable prefix + dynamic data.

        The stable message (instructions + calibration rules) is identical across
        all verdict calls, enabling API-level prefix caching. The dynamic message
        carries the per-run alert, observations, findings, and task instruction.
        ``{{END_OF_STABLE}}`` in the template marks the split point.
        """
        rendered = (
            self._template.replace("{{ALERT_PAYLOAD}}", self._render_alert(alert))
            .replace("{{OBSERVATIONS}}", self._render_observations(observations, observation_steps))
            .replace("{{FINDINGS}}", self._render_findings(findings))
        )
        return split_stable_dynamic(rendered)

    @staticmethod
    def _render_alert(alert: Alert) -> str:
        """Dump the whole alert (envelope + payload) as one untrusted JSON blob."""
        return dump_alert(alert)

    @staticmethod
    def _render_observations(
        observations: Sequence[ToolResult],
        observation_steps: Sequence[int] | None,
    ) -> str:
        """Render the gathered Observations as a stable untrusted block.

        Each observation is emitted as a single ``<observation>`` XML tag carrying
        step, tool, and ok as attributes; the rest of the data is compact JSON
        inside the tag body. Oversized data fields are truncated at
        ``_OBSERVATION_DATA_MAX_CHARS``. The journal keeps full data.

        ``observation_steps`` carries the real executor step numbers so the
        prompt's ``step="..."`` attributes match the journal's
        ``tool_called``/``tool_result`` step exactly — including any numbering
        gaps from guard-refused steps.  When ``None``, steps are derived from
        position (``enumerate(..., start=1)``), which is byte-identical for
        gap-free runs where the two methods agree.
        """
        if not observations:
            return _NO_OBSERVATIONS
        blocks: list[str] = []
        steps = (
            observation_steps if observation_steps is not None else range(1, len(observations) + 1)
        )
        for step_num, obs in zip(steps, observations, strict=True):
            inner: dict[str, object] = {}
            if obs.ok:
                raw = dump_compact(obs.data)
                inner["data"] = _truncate_data(raw)
            else:
                inner["error"] = obs.error
            body = dump_compact(inner)
            blocks.append(observation_tag(step_num, obs.tool, obs.ok, body))
        return "\n\n".join(blocks)

    @staticmethod
    def _render_findings(findings: Sequence[Finding]) -> str:
        """Render the carried Findings as a stable untrusted block."""
        if not findings:
            return _NO_FINDINGS
        return "\n\n".join(dump_compact(finding.model_dump()) for finding in findings)
