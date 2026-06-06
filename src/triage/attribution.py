"""Entity text-scan helpers — a leaf module (RFC-0003 §Module seams / ADR-0006).

Imports only ``triage.models`` and the stdlib — no journal, no LLM calls, no
other triage modules.  Used by:

* ``verdict.py`` — ``_filter_traceable_actions`` delegates its substring scan here
  (replaces the inline matcher; byte-identical filter behaviour).
* ``verification.py`` (group 2) — the hook's action-traceability and coverage
  checks share the same matcher.
* The ADR-0006 persist path (US-0006) — entity grounding at verdict-persist time
  via ``attribute_finding``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from triage.models import Alert, Finding


def entities_in_text(text: str, known_entities: Iterable[Any]) -> set[str]:
    """Return the subset of ``known_entities`` whose values appear in ``text``.

    Case-insensitive substring scan: an entity value is considered "present" in
    ``text`` when it appears as a case-insensitive substring of ``text``.  Only
    non-empty string values are matched — non-string or empty entities are skipped
    silently (the caller may pass ``alert.entities.values()`` which can contain
    non-string payload values).

    This is the single shared matcher used by:
    - ``verdict._filter_traceable_actions`` (quality backstop — not a security
      boundary; see the security note in ``verdict.py``).
    - ``verification.py`` action-traceability and coverage checks (group 2).
    - The ADR-0006 persist path (US-0006) via ``attribute_finding``.

    Args:
        text: The corpus to search in (e.g. the concatenated finding text).
        known_entities: The candidate entity values to look for.

    Returns:
        The subset of ``known_entities`` (as strings) found in ``text``.
    """
    lower_text = text.lower()
    found: set[str] = set()
    for entity in known_entities:
        if not isinstance(entity, str) or not entity:
            continue
        if entity.lower() in lower_text:
            found.add(entity)
    return found


def _known_entity_values(alert: Alert) -> set[str]:
    """Return the set of known entity values for attribution validation (ADR-0006).

    The known set is the union of:
    - All matchable values from ``alert.entities`` (scalars + str list items,
      mirroring the ``_matchable_entities`` semantics in ``memory/store.py``).
    - Scalar string values of ``alert.context`` (ADR-0006: recorded verdicts
      legitimately name context entities — e.g. a pipeline name — that the
      envelope does not carry; validating against ``entities`` alone would strip
      them as hallucinations).

    Only non-empty strings are included; non-string or empty values are skipped.
    This is the validation universe for ``attribute_finding``'s declared and
    detection paths.
    """
    known: set[str] = set()
    # entities dict: scalars and list items
    for value in alert.entities.values():
        if isinstance(value, str) and value:
            known.add(value)
        elif isinstance(value, list):
            known.update(item for item in value if isinstance(item, str) and item)
    # context dict: scalar string values only
    for value in alert.context.values():
        if isinstance(value, str) and value:
            known.add(value)
    return known


def _entity_type_for(value: str, entities: Mapping[str, Any]) -> str | None:
    """Look up the entity_type for a known entity value from the ``entities`` dict.

    Searches scalars first, then list items.  Returns ``None`` when the value is
    found only in ``alert.context`` (a context-attributed entity has no
    ``entity_type`` key in the envelope; the caller decides what to do — see
    ``attribute_finding`` docstring).
    """
    for etype, eval_ in entities.items():
        if isinstance(eval_, str) and eval_ == value:
            return etype
        if isinstance(eval_, list):
            for item in eval_:
                if isinstance(item, str) and item == value:
                    return etype
    return None


def attribute_finding(finding: Finding, alert: Alert) -> list[str]:
    """Return the alert entity values this finding should be attributed to (ADR-0006).

    Resolution order (deterministic, code-enforced):

    1. **Declared** — ``finding.related_entities`` is not ``None``: each value is
       validated against the alert's known entity values (``entities`` dict values
       union scalar string values of ``context``). Values matching neither are dropped
       (hallucinated entity names never persist). An empty declared list yields an
       empty result immediately (the LLM explicitly said "nothing"; skip detection).

    2. **Detected (fallback)** — ``finding.related_entities`` is ``None``: a
       case-insensitive substring scan of ``(finding.statement + " " +
       finding.evidence)`` against the same known entity values set.

    3. **Unattributed** — neither path yields a match: returns ``[]``.  The caller
       (``memory/store.py``) emits a ``finding_unattributed`` journal event and
       persists no atom for this finding.

    Args:
        finding: The LLM-authored Finding to attribute.
        alert: The Alert whose entity universe defines valid attribution targets.

    Returns:
        A list of entity value strings (possibly empty) that are valid attribution
        targets for this finding, filtered to known entity values.
    """
    known = _known_entity_values(alert)
    if not known:
        return []

    if finding.related_entities is not None:
        # Declared path: validate each declared value against the known set.
        # Empty list is explicit "no attribution" — return immediately.
        if not finding.related_entities:
            return []
        return [v for v in finding.related_entities if v in known]

    # Detection fallback: text-scan statement + evidence.
    corpus = finding.statement + " " + finding.evidence
    return sorted(entities_in_text(corpus, known))
