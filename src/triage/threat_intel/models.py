"""Pydantic data contracts for the Threat Intel delegated agent (RFC-0002).

Validation postures follow the same discipline as ``triage.models``:

* ``TIReport`` and ``SourceFinding`` are **lax** (``extra="ignore"``): they are
  LLM-output models produced by the TI synthesis call, so they must tolerate
  hallucinated extra keys and benign coercions (e.g. a quoted float confidence)
  without burning the single repair attempt.  Semantic constraints still bite:
  the ``ioc_type`` enum, the ``confidence`` 0-to-1 range, and all required fields
  reject bad values.

* The ``IOCType`` literal is the exhaustive classification the classifier produces;
  ``TIReport.ioc_type`` is validated against it, giving a hard rejection on any
  value not in {public_ip, domain, hash}.

Neither model is used as an internal-contract record (those stay strict) — the
LLM produces both, so both are lax by convention.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

IOCType = Literal["public_ip", "domain", "hash"]
"""The three external-IOC classes the classifier can produce (RFC-0002)."""


class _LaxModel(BaseModel):
    """Base for LLM-output models: ignore extra fields, allow benign coercions."""

    model_config = ConfigDict(extra="ignore")


class SourceFinding(_LaxModel):
    """One per-source intelligence finding with a citation to its tool result.

    Mirrors the discipline of ``Finding`` in ``triage.models``: every statement
    carries a citation so the synthesizer cannot hallucinate unsupported facts.
    The ``citation`` is a short, human-readable reference to the tool result that
    produced the data (e.g. ``"fixture:reputation/185.220.101.5"``); it is not
    machine-interpreted but is passed through to the primary loop's observation.
    """

    source: str = Field(min_length=1, description="TI tool name that produced this finding.")
    summary: str = Field(min_length=1, description="Brief human-readable finding statement.")
    citation: str = Field(min_length=1, description="Citation referencing the tool result data.")


class TIReport(_LaxModel):
    """The validated Threat Intel enrichment result for one external IOC.

    Produced by ``loop.enrich`` and consumed by the primary loop as a single
    Observation (ADR-0005 property 4: consumed as untrusted context). A ``TIReport``
    is always schema-validated in code before the primary loop sees it — the
    Pydantic model is the contract boundary (RFC-0002 §Decision).

    Fields are kept small and citation-disciplined (mirrors ``Verdict.Finding``):

    * ``ioc_type`` — the deterministic classifier result (never LLM-decided).
    * ``ioc_value`` — the raw IOC string as submitted to the mini-loop.
    * ``source_findings`` — per-source intelligence with citations; may be empty
      when all tools missed (all-miss degradation path).
    * ``overall_assessment`` — one-paragraph synthesis across all sources.
    * ``confidence`` -- quality of gathered evidence (0-1), independent of severity.
    """

    ioc_type: IOCType
    ioc_value: str = Field(min_length=1)
    source_findings: list[SourceFinding]
    overall_assessment: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
