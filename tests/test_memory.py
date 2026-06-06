"""Tests for the memory package (RFC-0001 §Memory; ADR-0005 untrusted recall).

L1 finding atoms persist at verdict time keyed by entity; L2 dossiers are a
deterministic group-by; recall is entity-scoped and shaped exactly for
``Planner.plan``'s ``recall`` param (``run_id`` / ``confidence`` / ``content``).

Structural / determinism assertions only:

* persist -> recall round trip surfaces a prior finding for a matching entity;
* entity scoping: a non-matching alert recalls nothing;
* recall items carry exactly the planner seam keys (atom-grained);
* dossier / recall ordering is deterministic (replay-stable);
* idempotent persist (resume double-write) does not duplicate atoms;
* atom ``ts`` is the alert timestamp, not a wall clock (replay-stable);
* empty / missing store and unmatchable entities -> empty recall (no crash);
* a corrupt store file degrades to empty recall, never crashes a run;
* atom schema is stable (exact key set).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from triage.memory import MemoryStore
from triage.memory.atoms import FindingAtom
from triage.models import Alert, Finding, Verdict

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

_RECALL_KEYS = {"run_id", "confidence", "content"}
_ATOM_KEYS = {
    "atom_id",
    "entity_type",
    "entity_value",
    "statement",
    "evidence",
    "severity",
    "confidence",
    "run_id",
    "ts",
}


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-1",
        "timestamp": "2026-06-05T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "data_exfiltration",
        "description": "Large outbound transfer from alice's host.",
        "entities": {"user": "alice", "ip": "10.0.0.9"},
        "context": {"bytes": 5_000_000},
    }
    return Alert.model_validate({**base, **overrides})


def _verdict(**overrides: object) -> Verdict:
    base: dict[str, Any] = {
        "severity": "high",
        "findings": [
            Finding(statement="Exfiltrated 5MB to a known-bad IP.", evidence="query_logs: flow 42"),
        ],
        "recommended_actions": [],
        "confidence": 0.9,
    }
    return Verdict.model_validate({**base, **overrides})


def test_persist_then_recall_round_trip(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    # A second alert mentioning the same IP recalls the prior finding.
    later = _alert(alert_id="ALT-2", entities={"ip": "10.0.0.9"})
    recalled = store.recall(later)

    assert recalled
    contents = " ".join(str(item["content"]) for item in recalled)
    assert "Exfiltrated 5MB to a known-bad IP." in contents
    assert any(item["run_id"] == "run-1" for item in recalled)


def test_recall_items_carry_exactly_the_planner_seam_keys(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    recalled = store.recall(_alert(alert_id="ALT-2", entities={"ip": "10.0.0.9"}))

    assert recalled
    for item in recalled:
        assert set(item.keys()) == _RECALL_KEYS
        assert isinstance(item["confidence"], float)


def test_entity_scoping_excludes_non_matching_entities(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    # Wholly different entities -> nothing recalled (not the whole store).
    other = _alert(alert_id="ALT-3", entities={"user": "bob", "ip": "192.168.1.1"})
    assert store.recall(other) == []


def test_recall_is_entity_scoped_not_whole_store(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "run-1",
        _alert(entities={"user": "alice"}),
        _verdict(findings=[Finding(statement="alice fact", evidence="ev")]),
    )
    store.persist(
        "run-2",
        _alert(alert_id="ALT-X", entities={"user": "bob"}),
        _verdict(findings=[Finding(statement="bob fact", evidence="ev")]),
    )

    recalled = store.recall(_alert(alert_id="ALT-Y", entities={"user": "alice"}))

    joined = " ".join(str(item["content"]) for item in recalled)
    assert "alice fact" in joined
    assert "bob fact" not in joined


def test_recall_ordering_is_deterministic(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "run-low",
        _alert(),
        _verdict(
            confidence=0.3,
            findings=[Finding(statement="low-confidence fact", evidence="ev")],
        ),
    )
    store.persist(
        "run-high",
        _alert(),
        _verdict(
            confidence=0.95,
            findings=[Finding(statement="high-confidence fact", evidence="ev")],
        ),
    )

    first = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))
    second = store.recall(_alert(alert_id="A3", entities={"ip": "10.0.0.9"}))

    assert first == second  # byte-identical across calls
    # Higher confidence sorts first (recall is confidence-desc).
    assert first[0]["confidence"] == 0.95


def test_persist_is_idempotent_on_resume_double_write(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())
    store.persist("run-1", _alert(), _verdict())  # resumed run re-persists

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    statements = [item["content"] for item in recalled]
    assert len(statements) == len(set(statements))  # no duplicate atom


def test_atom_ts_is_alert_timestamp_not_wall_clock(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(timestamp="2020-01-01T12:00:00Z"), _verdict())

    atoms = store.dossier("ip", "10.0.0.9")

    assert atoms
    assert all(atom.ts == "2020-01-01T12:00:00Z" for atom in atoms)


def test_dossier_is_deterministic_group_by(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "run-b",
        _alert(),
        _verdict(findings=[Finding(statement="b", evidence="ev")]),
    )
    store.persist(
        "run-a",
        _alert(),
        _verdict(findings=[Finding(statement="a", evidence="ev")]),
    )

    first = store.dossier("ip", "10.0.0.9")
    second = store.dossier("ip", "10.0.0.9")

    assert [a.atom_id for a in first] == [a.atom_id for a in second]
    assert all(isinstance(a, FindingAtom) for a in first)


def test_empty_store_recalls_nothing(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    assert store.recall(_alert()) == []


def test_missing_store_dir_recalls_nothing(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path / "does-not-exist")
    assert store.recall(_alert()) == []
    assert store.dossier("ip", "10.0.0.9") == []


def test_non_scalar_entities_are_skipped(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"ip": "10.0.0.9", "ports": [22, 443], "meta": {"a": 1}, "x": None})
    store.persist("run-1", alert, _verdict())

    # The scalar ip persisted; the list/dict/None entities were skipped.
    assert store.dossier("ip", "10.0.0.9")
    # A recall keyed only on a non-scalar entity finds nothing matchable.
    no_match = _alert(alert_id="A2", entities={"ports": [22, 443]})
    assert store.recall(no_match) == []


def test_empty_string_entities_persist_no_atoms_and_never_crash(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    # Empty value and empty key both come from the untrusted, schema-free payload;
    # an empty type/value would violate the atom min_length and must not crash.
    alert = _alert(entities={"user": "", "": "x"})
    store.persist("run-1", alert, _verdict())  # must not raise

    assert list(tmp_path.glob("*.jsonl")) == []
    assert store.recall(_alert(alert_id="A2", entities={"user": ""})) == []


def test_empty_findings_persists_no_atoms(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict(findings=[]))
    assert store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"})) == []


def test_empty_entities_persists_no_atoms(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(entities={}), _verdict())
    assert store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"})) == []


def test_corrupt_store_file_degrades_to_empty_recall(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    # Corrupt every persisted file: a memory failure must never crash a run.
    for path in tmp_path.glob("*.jsonl"):
        path.write_text("{ not valid json\n", encoding="utf-8")

    assert store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"})) == []
    assert store.dossier("ip", "10.0.0.9") == []


def test_persist_swallows_write_failure(tmp_path: Path) -> None:
    # base_dir points at a file, so creating the store dir / writing fails.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    store = MemoryStore(base_dir=blocker / "nested")

    # Must not raise — a memory write failure never crashes a run.
    store.persist("run-1", _alert(), _verdict())
    assert store.recall(_alert()) == []


def test_atom_schema_is_stable(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    atoms = store.dossier("ip", "10.0.0.9")

    assert atoms
    dumped = atoms[0].model_dump()
    assert set(dumped.keys()) == _ATOM_KEYS


def test_default_base_dir_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "env-store"
    monkeypatch.setenv("MEMORY_DIR", str(target))
    store = MemoryStore()
    store.persist("run-1", _alert(), _verdict())

    assert store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))
    assert list(target.glob("*.jsonl"))


def test_default_base_dir_falls_back_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMORY_DIR", raising=False)
    store = MemoryStore()
    # The default is the documented ``.memory`` dir (relative).
    assert store.base_dir.name == ".memory"


def test_recall_caps_at_top_n(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    findings = [
        Finding(statement=f"fact {i}", evidence=f"ev {i}")
        for i in range(MemoryStore.RECALL_TOP_N + 5)
    ]
    store.persist("run-1", _alert(), _verdict(findings=findings))

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    assert len(recalled) == MemoryStore.RECALL_TOP_N


def test_blank_lines_in_store_file_are_skipped(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    # Inject blank lines (hand edits / trailing newlines) around the real atoms.
    for path in tmp_path.glob("*.jsonl"):
        body = path.read_text(encoding="utf-8")
        path.write_text(f"\n{body}\n   \n", encoding="utf-8")

    atoms = store.dossier("ip", "10.0.0.9")
    assert atoms  # blank lines skipped, real atoms still read


def test_atom_round_trips_through_jsonl(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    path = next(tmp_path.glob("*.jsonl"))
    line = path.read_text(encoding="utf-8").splitlines()[0]
    atom = FindingAtom.model_validate(json.loads(line))

    assert atom.entity_value in {"10.0.0.9", "alice"}


# --------------------------------------------------------------------------- #
# B5 (M-mem1) — recall recency tie-break: equal confidence -> newest first    #
# --------------------------------------------------------------------------- #


def test_equal_confidence_newer_atom_ranks_first(tmp_path: Path) -> None:
    """With equal confidence, the atom with the newer ts must rank first in recall."""
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "run-older",
        _alert(timestamp="2024-01-01T00:00:00Z"),
        _verdict(
            confidence=0.7,
            findings=[Finding(statement="older fact", evidence="ev")],
        ),
    )
    store.persist(
        "run-newer",
        _alert(timestamp="2025-06-01T00:00:00Z"),
        _verdict(
            confidence=0.7,
            findings=[Finding(statement="newer fact", evidence="ev")],
        ),
    )

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    # Equal confidence: the newer atom (2025) must come first.
    assert recalled[0]["content"].startswith("[high] newer fact")


# T2 (L1) — explicit tie-break test: two atoms same confidence, different ts → newer first
def test_recall_breaks_confidence_ties_by_recency(tmp_path: Path) -> None:
    """Two atoms with IDENTICAL confidence sort newest-timestamp-first in recall.

    This is a named explicit regression: if the recency tie-break were ever dropped
    or inverted (e.g. ascending ts or missing second sort key) the newer fact would
    rank behind the older one and this test would fail, alerting the author.
    """
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "run-2022",
        _alert(timestamp="2022-03-15T08:00:00Z"),
        _verdict(
            confidence=0.6,
            findings=[Finding(statement="2022 finding", evidence="ev")],
        ),
    )
    store.persist(
        "run-2026",
        _alert(timestamp="2026-01-01T00:00:00Z"),
        _verdict(
            confidence=0.6,
            findings=[Finding(statement="2026 finding", evidence="ev")],
        ),
    )

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    assert len(recalled) == 2
    # Same confidence (0.6): the 2026 atom must rank first.
    assert "2026 finding" in recalled[0]["content"]
    assert "2022 finding" in recalled[1]["content"]


def test_higher_confidence_always_wins_regardless_of_recency(tmp_path: Path) -> None:
    """Higher confidence ranks first even when the atom is older."""
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "run-old-high",
        _alert(timestamp="2022-01-01T00:00:00Z"),
        _verdict(
            confidence=0.95,
            findings=[Finding(statement="old high-conf", evidence="ev")],
        ),
    )
    store.persist(
        "run-new-low",
        _alert(timestamp="2025-06-01T00:00:00Z"),
        _verdict(
            confidence=0.3,
            findings=[Finding(statement="new low-conf", evidence="ev")],
        ),
    )

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    assert recalled[0]["content"].startswith("[high] old high-conf")


# --------------------------------------------------------------------------- #
# B6 (M-mem3) — list-entity matching                                           #
# --------------------------------------------------------------------------- #


def test_list_entity_persists_and_recalls_per_item(tmp_path: Path) -> None:
    """A list entity value yields one atom per non-empty str item."""
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"source_ips": ["1.2.3.4", "5.6.7.8"]})
    store.persist("run-list", alert, _verdict())

    # Each IP in the list should produce a separate recall entry.
    recalled_first = store.recall(_alert(alert_id="A2", entities={"source_ips": ["1.2.3.4"]}))
    recalled_second = store.recall(_alert(alert_id="A3", entities={"source_ips": ["5.6.7.8"]}))

    assert recalled_first, "1.2.3.4 should have been persisted and recalled"
    assert recalled_second, "5.6.7.8 should have been persisted and recalled"
    assert any("Exfiltrated" in item["content"] for item in recalled_first)


def test_list_entity_skips_non_str_members(tmp_path: Path) -> None:
    """Non-str items in a list (int, None, dict) are skipped silently."""
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"ports": [22, None, {"nested": 1}, "valid-str"]})
    store.persist("run-mixed", alert, _verdict())

    # Only the valid str item ("valid-str") should produce atoms.
    recalled = store.recall(_alert(alert_id="A2", entities={"ports": ["valid-str"]}))
    assert recalled, "the valid str item should have been matched"

    # None/int/dict items do not produce atoms.
    no_match = store.recall(_alert(alert_id="A3", entities={"ports": [22]}))
    assert no_match == []


def test_list_entity_skips_empty_strings(tmp_path: Path) -> None:
    """Empty strings inside a list are not persisted (min_length violation guard)."""
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"ips": ["", "  ", "10.0.0.1"]})
    store.persist("run-empty-list", alert, _verdict())

    # Only the non-empty "10.0.0.1" should exist.
    recalled = store.recall(_alert(alert_id="A2", entities={"ips": ["10.0.0.1"]}))
    assert recalled

    empty_recall = store.recall(_alert(alert_id="A3", entities={"ips": [""]}))
    assert empty_recall == []


def test_mixed_scalar_and_list_entities_both_persist(tmp_path: Path) -> None:
    """Both scalar str and list entities in the same alert are all persisted."""
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"user": "alice", "source_ips": ["1.2.3.4", "5.6.7.8"]})
    store.persist("run-combo", alert, _verdict())

    # Scalar and both list items should be matchable.
    assert store.recall(_alert(alert_id="A2", entities={"user": "alice"}))
    assert store.recall(_alert(alert_id="A3", entities={"source_ips": ["1.2.3.4"]}))
    assert store.recall(_alert(alert_id="A4", entities={"source_ips": ["5.6.7.8"]}))


def test_unparseable_timestamp_falls_back_in_recall_sort(tmp_path: Path) -> None:
    """An atom with an unparseable ``ts`` is sorted last (fallback 0.0); no crash."""
    store = MemoryStore(base_dir=tmp_path)
    # Normal atom with a valid timestamp.
    store.persist(
        "run-valid",
        _alert(timestamp="2025-06-01T00:00:00Z"),
        _verdict(confidence=0.5, findings=[Finding(statement="valid fact", evidence="ev")]),
    )
    # Inject an atom with a garbage timestamp directly into the store file.
    path = next(iter(tmp_path.glob("*.jsonl")))
    bad_atom = {
        "atom_id": "bad000",
        "entity_type": "ip",
        "entity_value": "10.0.0.9",
        "statement": "bad-ts fact",
        "evidence": "ev",
        "severity": "high",
        "confidence": 0.5,
        "run_id": "run-bad-ts",
        "ts": "not-a-timestamp",
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(bad_atom) + "\n")

    # Must not crash; both atoms recalled, bad-ts atom treated as oldest.
    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))
    assert len(recalled) == 2
    # The valid-ts atom (2025) sorts before the bad-ts atom (fallback oldest).
    assert recalled[0]["content"].startswith("[high] valid fact")
