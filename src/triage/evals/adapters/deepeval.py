"""A pure, vendor-free deepeval projection (read-only adapter seam, US-0003).

Projects a Golden Case's tool-neutral ``reference`` block into the dict shape a
deepeval golden / ``ToolCorrectnessMetric`` consumes — WITHOUT importing deepeval.
The harness ships green with no optional dependency; a consumer that wants live
deepeval scoring installs it and binds these projected fields to a real metric.

The mapping (``eval-authoring`` skill):

* ``reference.expected_tools`` (an ordered ``name`` list, optional
  ``input_parameters``) -> ``expected_tools``;
* ``reference.expected_severity`` -> ``expected_output`` material;
* ``reference.expected_actions`` -> ``expected_actions``;
* ``reference.ordered`` -> deepeval ``should_consider_ordering``;
* ``reference.exact`` -> deepeval ``should_exact_match``.

The ``expect`` Tier-1 assertions remain the ONLY gate; this projection is a
convenience for an optional external evaluator and never participates in pass/fail.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from triage.evals.models import GoldenCase


class DeepEvalProjection(BaseModel):
    """The vendor-neutral projection of a case ``reference`` block for deepeval."""

    model_config = ConfigDict(strict=True, extra="forbid")

    name: str
    expected_tools: list[dict[str, object]] = Field(default_factory=list)
    expected_severity: str | None = None
    expected_actions: list[str] = Field(default_factory=list)
    should_consider_ordering: bool = False
    should_exact_match: bool = False


def project_reference(case: GoldenCase) -> DeepEvalProjection:
    """Project ``case.reference`` into the deepeval-shaped, vendor-free dict model."""
    reference = case.reference
    expected_tools: list[dict[str, object]] = []
    for tool in reference.expected_tools:
        entry: dict[str, object] = {"name": tool.name}
        if tool.input_parameters is not None:
            entry["input_parameters"] = tool.input_parameters
        expected_tools.append(entry)
    return DeepEvalProjection(
        name=case.name,
        expected_tools=expected_tools,
        expected_severity=reference.expected_severity,
        expected_actions=list(reference.expected_actions),
        should_consider_ordering=reference.ordered,
        should_exact_match=reference.exact,
    )
