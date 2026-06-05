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

import json
from pathlib import Path
from typing import TYPE_CHECKING

from triage.errors import LLMError
from triage.llm import Message
from triage.models import Alert, Finding, ToolResult, Verdict

if TYPE_CHECKING:
    from collections.abc import Sequence

    from triage.journal import Journal
    from triage.llm import LLM
    from triage.models import TerminatedReason

_PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "verdict.md"

DEGRADED_SEVERITY = "high"
"""Conservative severity for the degraded verdict — a side-effect-free floor."""

DEGRADED_CONFIDENCE = 0.0
"""Confidence for the degraded verdict — a failed synthesis is unreliable."""

_NO_OBSERVATIONS = "(no observations were gathered)"
_NO_FINDINGS = "(no findings were drawn during the run)"


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
        findings: Sequence[Finding] = (),
        terminated_reason: TerminatedReason | None = None,
    ) -> Verdict:
        """Synthesize the final Verdict, degrading deterministically on LLM failure.

        Args:
            alert: The validated alert under investigation.
            observations: The tool Observations gathered during the run.
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
        messages = self._render(alert, observations, findings)
        try:
            completion = self._llm.complete(messages, Verdict)
        except LLMError:
            verdict = self._degraded_verdict(findings, terminated_reason)
        else:
            self._journal.emit(
                "llm_call",
                {
                    "purpose": "verdict",
                    "model": completion.model,
                    "prompt_hash": completion.prompt_hash,
                    "tokens": completion.tokens,
                    "latency_ms": completion.latency_ms,
                },
            )
            # ``terminated_reason`` is code-owned: override any value the model
            # emitted with the upstream fact.
            verdict = completion.value.model_copy(update={"terminated_reason": terminated_reason})
        self._journal.emit("verdict", {"verdict": verdict.model_dump()})
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
        findings: Sequence[Finding],
    ) -> list[Message]:
        """Render the prompt into the single user message the LLM seam consumes."""
        content = (
            self._template.replace("{{ALERT_PAYLOAD}}", self._render_alert(alert))
            .replace("{{OBSERVATIONS}}", self._render_observations(observations))
            .replace("{{FINDINGS}}", self._render_findings(findings))
        )
        return [Message(role="user", content=content)]

    @staticmethod
    def _render_alert(alert: Alert) -> str:
        """Dump the whole alert (envelope + payload) as one untrusted JSON blob."""
        return json.dumps(alert.model_dump(), sort_keys=True, ensure_ascii=False, indent=2)

    @staticmethod
    def _render_observations(observations: Sequence[ToolResult]) -> str:
        """Render the gathered Observations as a stable untrusted block."""
        if not observations:
            return _NO_OBSERVATIONS
        return "\n\n".join(
            json.dumps(obs.model_dump(), sort_keys=True, ensure_ascii=False, indent=2)
            for obs in observations
        )

    @staticmethod
    def _render_findings(findings: Sequence[Finding]) -> str:
        """Render the carried Findings as a stable untrusted block."""
        if not findings:
            return _NO_FINDINGS
        return "\n\n".join(
            json.dumps(finding.model_dump(), sort_keys=True, ensure_ascii=False, indent=2)
            for finding in findings
        )
