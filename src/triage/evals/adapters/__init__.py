"""The read-only vendor-adapter seam (US-0003 / eval-authoring skill).

External eval tools (deepeval, promptfoo, LangSmith) are OPTIONAL CONSUMERS of the
harness, never dependencies of it. They live here so the rule holds structurally:

* an adapter may import ``triage.evals`` (the case ``reference`` block, the
  ``RunRecord``, the pure ``assert_case`` checks);
* nothing in ``triage.evals`` (``runner``, ``assertions``, ``replay``) ever imports
  ``adapters`` — the dependency arrow points one way only.

The shipped ``DeepEvalProjection`` is a pure, vendor-free projection: it turns a
Golden Case's tool-neutral ``reference`` block into the dict shape a deepeval
``ToolCorrectnessMetric`` / golden expects (``expected_tools``,
``expected_severity``, ``expected_actions``, plus the ``ordered`` / ``exact``
knobs that map to deepeval's ``should_consider_ordering`` /
``should_exact_match``). It imports no vendor package — installing deepeval is the
consumer's choice, so the adapter only *shapes* data; binding it to a live
deepeval metric is a one-liner the consumer writes on top. This keeps the harness
green with zero optional deps while documenting the exact seam a vendor plugs into.
"""

from triage.evals.adapters.deepeval import DeepEvalProjection, project_reference

__all__ = ["DeepEvalProjection", "project_reference"]
