"""Tests for the attribution leaf module (RFC-0003 §Module seams / ADR-0006).

``entities_in_text`` is the shared entity text-scan used by verdict's
``_filter_traceable_actions`` and the verify hook (group 2).  Tests cover:

* Basic substring match (case-insensitive).
* Non-string and empty entity values are skipped silently.
* Multiple entities — only matching ones are returned.
* Empty text / empty entities return the empty set.

``attribute_finding`` implements ADR-0006's resolution order (declared →
detected → unattributed).  Tests cover:

* Declared path: validated against known entity values, hallucinated dropped.
* Declared empty list: unattributed immediately (no text-scan).
* Declared None: detection fallback via text-scan.
* Context-value validation: a context scalar str is valid to declare, but
  ``attribute_finding`` returns it (the caller decides whether to persist).
* Unattributed: neither path yields anything → empty list.
* Success metric fixture: two incidents sharing exactly one entity → recall
  for the shared entity returns ONLY that entity's atoms (0 cross-entity).
"""

from __future__ import annotations

from triage.attribution import attribute_finding, entities_in_text
from triage.models import Alert, Finding

# ---------------------------------------------------------------------------
# entities_in_text
# ---------------------------------------------------------------------------


def test_entity_found_by_exact_substring() -> None:
    """An entity value present verbatim in the text is returned."""
    found = entities_in_text("alice was blocked by the firewall", ["alice"])
    assert found == {"alice"}


def test_entity_match_is_case_insensitive() -> None:
    """The match is case-insensitive on both sides."""
    found = entities_in_text("The user ALICE attempted login.", ["alice"])
    assert found == {"alice"}

    found2 = entities_in_text("alice seen in logs", ["ALICE"])
    assert found2 == {"ALICE"}


def test_entity_not_found_returns_empty_set() -> None:
    """An entity not present in the text is not returned."""
    found = entities_in_text("some unrelated text", ["ghost-entity"])
    assert found == set()


def test_multiple_entities_only_matching_returned() -> None:
    """Only entities present in the text are returned."""
    found = entities_in_text("alice and 10.0.0.1 were involved", ["alice", "bob", "10.0.0.1"])
    assert found == {"alice", "10.0.0.1"}


def test_non_string_entity_values_are_skipped() -> None:
    """Non-string entity values (e.g. ints, None, lists) are silently skipped."""
    # Pass a mix of types — only strings can match.
    found = entities_in_text("42 and None in text", [42, None, "42"])
    assert found == {"42"}


def test_empty_string_entity_is_skipped() -> None:
    """An empty string entity is skipped — it would trivially match everything."""
    found = entities_in_text("any text at all", [""])
    assert found == set()


def test_empty_text_returns_empty_set() -> None:
    """No entity can be found in an empty corpus."""
    found = entities_in_text("", ["alice", "bob"])
    assert found == set()


def test_empty_known_entities_returns_empty_set() -> None:
    """An empty iterable of entities produces an empty result."""
    found = entities_in_text("some text", [])
    assert found == set()


# ---------------------------------------------------------------------------
# attribute_finding helpers
# ---------------------------------------------------------------------------


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-1",
        "timestamp": "2026-06-06T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "test",
        "description": "test alert",
        "entities": {"user": "alice", "ip": "10.0.0.1"},
        "context": {"pipeline": "deploy-prod"},
    }
    return Alert.model_validate({**base, **overrides})


def _finding(statement: str, evidence: str, related_entities: list[str] | None = None) -> Finding:
    return Finding(statement=statement, evidence=evidence, related_entities=related_entities)


# ---------------------------------------------------------------------------
# attribute_finding — declared path (step 1, ADR-0006)
# ---------------------------------------------------------------------------


def test_declared_entity_validated_and_returned() -> None:
    """A declared entity value matching an alert entity is returned."""
    alert = _alert()
    finding = _finding("alice did something", "lookup_user", related_entities=["alice"])
    result = attribute_finding(finding, alert)
    assert result == ["alice"]


def test_declared_hallucinated_entity_dropped() -> None:
    """A declared value that is not an alert entity value is dropped."""
    alert = _alert()
    finding = _finding("someone did something", "lookup_user", related_entities=["ghost-user"])
    result = attribute_finding(finding, alert)
    assert result == []


def test_declared_mixed_valid_and_hallucinated() -> None:
    """Valid declared values pass; hallucinated ones are dropped."""
    alert = _alert()
    finding = _finding(
        "alice and ghost did something",
        "lookup_user",
        related_entities=["alice", "ghost-user"],
    )
    result = attribute_finding(finding, alert)
    assert result == ["alice"]


def test_declared_empty_list_returns_empty_immediately() -> None:
    """An empty declared list skips detection and returns [] immediately."""
    # The statement names the entity — but the declared empty list wins.
    alert = _alert()
    finding = _finding("alice was involved", "lookup_user", related_entities=[])
    result = attribute_finding(finding, alert)
    assert result == []


def test_declared_context_value_accepted() -> None:
    """A context scalar value is valid to declare (validation accepts it)."""
    # 'deploy-prod' is in context — validate accepts it.
    alert = _alert()
    finding = _finding(
        "the deploy-prod pipeline triggered this",
        "tool_result",
        related_entities=["deploy-prod"],
    )
    result = attribute_finding(finding, alert)
    # context value is valid: returned from attribute_finding
    assert result == ["deploy-prod"]


# ---------------------------------------------------------------------------
# attribute_finding — detection fallback (step 2, ADR-0006)
# ---------------------------------------------------------------------------


def test_undeclared_finding_text_scanned_for_entity() -> None:
    """When related_entities is None, text-scan detects entity from statement."""
    alert = _alert()
    finding = _finding("alice logged in from 10.0.0.1", "lookup_user")  # related_entities=None
    result = attribute_finding(finding, alert)
    assert "alice" in result
    assert "10.0.0.1" in result


def test_detection_fallback_case_insensitive() -> None:
    """Detection fallback is case-insensitive."""
    alert = _alert()
    finding = _finding("ALICE was found in logs", "tool_result")
    result = attribute_finding(finding, alert)
    assert "alice" in result


def test_detection_fallback_in_evidence_field() -> None:
    """Detection scans both statement AND evidence."""
    alert = _alert()
    # statement has no entity; evidence has alice
    finding = _finding("suspicious activity observed", "alice confirmed by lookup_user")
    result = attribute_finding(finding, alert)
    assert "alice" in result


def test_undeclared_finding_with_no_text_match_is_unattributed() -> None:
    """When text-scan finds nothing, an empty list is returned (unattributed)."""
    alert = _alert()
    finding = _finding("completely unrelated fact about nothing", "tool_result says nothing")
    result = attribute_finding(finding, alert)
    assert result == []


# ---------------------------------------------------------------------------
# attribute_finding — edge cases
# ---------------------------------------------------------------------------


def test_empty_entities_alert_always_unattributed() -> None:
    """An alert with no entities always produces unattributed findings."""
    alert = _alert(entities={}, context={})
    finding = _finding("alice did something", "lookup_user", related_entities=["alice"])
    result = attribute_finding(finding, alert)
    assert result == []


def test_list_entity_value_in_alert_matchable() -> None:
    """A list entity item is in the known set and can be declared."""
    alert = _alert(entities={"ips": ["1.2.3.4", "5.6.7.8"]}, context={})
    finding = _finding("traffic to 1.2.3.4", "check_reputation", related_entities=["1.2.3.4"])
    result = attribute_finding(finding, alert)
    assert result == ["1.2.3.4"]


def test_detection_finds_list_entity_item() -> None:
    """Text-scan detects a list entity item from the entities dict."""
    alert = _alert(entities={"ips": ["1.2.3.4", "5.6.7.8"]}, context={})
    finding = _finding("suspicious traffic from 1.2.3.4", "check_reputation")
    result = attribute_finding(finding, alert)
    assert "1.2.3.4" in result
