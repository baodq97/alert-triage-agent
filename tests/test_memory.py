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
import sys
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
            Finding(
                statement="Exfiltrated 5MB to a known-bad IP.",
                evidence="query_logs: flow 42",
                related_entities=["10.0.0.9"],
            ),
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


def test_recall_shared_entity_precision_no_cross_pollution(tmp_path: Path) -> None:
    """US-0006 success metric: two multi-entity incidents sharing exactly one entity.

    Incident A is about (charlie, 10.0.0.1); incident B about (dave, 10.0.0.2).
    A new alert names only charlie — recall must surface charlie's history and
    NOTHING from incident B (not dave, not B's IP), even though the store holds
    both.  Recall precision is entity-scoped, so it stays high as the store grows
    instead of degrading into cap-N cross-entity noise (ADR-0006).
    """
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "incident-A",
        _alert(alert_id="A", entities={"user": "charlie", "ip": "10.0.0.1"}),
        _verdict(
            findings=[
                Finding(
                    statement="charlie exfiltrated records",
                    evidence="query_logs flow A",
                    related_entities=["charlie"],
                ),
            ],
        ),
    )
    store.persist(
        "incident-B",
        _alert(alert_id="B", entities={"user": "dave", "ip": "10.0.0.2"}),
        _verdict(
            findings=[
                Finding(
                    statement="dave escalated privileges",
                    evidence="query_logs flow B",
                    related_entities=["dave"],
                ),
            ],
        ),
    )

    recalled = store.recall(_alert(alert_id="NEW", entities={"user": "charlie"}))

    joined = " ".join(str(item["content"]) for item in recalled)
    assert "charlie" in joined
    # Zero cross-entity pollution from incident B (the precision metric).
    assert "dave" not in joined
    assert "10.0.0.2" not in joined


def test_recall_ordering_is_deterministic(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    store.persist(
        "run-low",
        _alert(),
        _verdict(
            confidence=0.3,
            findings=[
                Finding(
                    statement="low-confidence fact",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
        ),
    )
    store.persist(
        "run-high",
        _alert(),
        _verdict(
            confidence=0.95,
            findings=[
                Finding(
                    statement="high-confidence fact",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
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
        _verdict(findings=[Finding(statement="b", evidence="ev", related_entities=["10.0.0.9"])]),
    )
    store.persist(
        "run-a",
        _alert(),
        _verdict(findings=[Finding(statement="a", evidence="ev", related_entities=["10.0.0.9"])]),
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
    # The finding declares the scalar ip entity; non-scalar entities can't be declared.
    verdict = _verdict(
        findings=[
            Finding(
                statement="Suspicious traffic from 10.0.0.9.",
                evidence="check_reputation",
                related_entities=["10.0.0.9"],
            )
        ]
    )
    store.persist("run-1", alert, verdict)

    # The scalar ip persisted; the list/dict/None entities were skipped.
    assert store.dossier("ip", "10.0.0.9")
    # A recall keyed only on non-scalar entities (list, dict, None) finds nothing
    # matchable — exercises _matchable_entities for all non-str, non-list branches.
    no_match_list = _alert(alert_id="A2", entities={"ports": [22, 443]})
    assert store.recall(no_match_list) == []
    # dict and None values are skipped by _matchable_entities (neither str nor list).
    no_match_nonscalar = _alert(alert_id="A3", entities={"meta": {"a": 1}, "x": None})
    assert store.recall(no_match_nonscalar) == []


def test_empty_string_entities_persist_no_atoms_and_never_crash(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    # Empty value and empty key both come from the untrusted, schema-free payload;
    # an empty type/value would violate the atom min_length and must not crash.
    alert = _alert(entities={"user": "", "": "x"})
    store.persist("run-1", alert, _verdict())  # must not raise

    assert list(tmp_path.glob("*.jsonl")) == []
    assert store.recall(_alert(alert_id="A2", entities={"user": ""})) == []
    # Recall with an empty-key entity also exercises _matchable_entities empty-name guard.
    assert store.recall(_alert(alert_id="A3", entities={"": "x"})) == []


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
        Finding(statement=f"fact {i}", evidence=f"ev {i}", related_entities=["10.0.0.9"])
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

    # With the attributed persist, only the declared entity (10.0.0.9) gets an atom.
    assert atom.entity_value == "10.0.0.9"


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
            findings=[
                Finding(
                    statement="older fact",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
        ),
    )
    store.persist(
        "run-newer",
        _alert(timestamp="2025-06-01T00:00:00Z"),
        _verdict(
            confidence=0.7,
            findings=[
                Finding(
                    statement="newer fact",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
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
            findings=[
                Finding(
                    statement="2022 finding",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
        ),
    )
    store.persist(
        "run-2026",
        _alert(timestamp="2026-01-01T00:00:00Z"),
        _verdict(
            confidence=0.6,
            findings=[
                Finding(
                    statement="2026 finding",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
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
            findings=[
                Finding(
                    statement="old high-conf",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
        ),
    )
    store.persist(
        "run-new-low",
        _alert(timestamp="2025-06-01T00:00:00Z"),
        _verdict(
            confidence=0.3,
            findings=[
                Finding(
                    statement="new low-conf",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
        ),
    )

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    assert recalled[0]["content"].startswith("[high] old high-conf")


# --------------------------------------------------------------------------- #
# B6 (M-mem3) — list-entity matching                                           #
# --------------------------------------------------------------------------- #


def test_list_entity_persists_and_recalls_per_item(tmp_path: Path) -> None:
    """A list entity value yields one atom per attributed str item."""
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"source_ips": ["1.2.3.4", "5.6.7.8"]})
    verdict = _verdict(
        findings=[
            Finding(
                statement="Traffic from both IPs was suspicious.",
                evidence="check_reputation",
                related_entities=["1.2.3.4", "5.6.7.8"],
            )
        ]
    )
    store.persist("run-list", alert, verdict)

    # Each IP in the list should produce a separate recall entry.
    recalled_first = store.recall(_alert(alert_id="A2", entities={"source_ips": ["1.2.3.4"]}))
    recalled_second = store.recall(_alert(alert_id="A3", entities={"source_ips": ["5.6.7.8"]}))

    assert recalled_first, "1.2.3.4 should have been persisted and recalled"
    assert recalled_second, "5.6.7.8 should have been persisted and recalled"
    assert any("Traffic from both IPs" in item["content"] for item in recalled_first)


def test_list_entity_skips_non_str_members(tmp_path: Path) -> None:
    """Non-str items in a list (int, None, dict) are skipped silently."""
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"ports": [22, None, {"nested": 1}, "valid-str"]})
    verdict = _verdict(
        findings=[
            Finding(
                statement="Activity on valid-str port was suspicious.",
                evidence="check_reputation",
                related_entities=["valid-str"],
            )
        ]
    )
    store.persist("run-mixed", alert, verdict)

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
    verdict = _verdict(
        findings=[
            Finding(
                statement="Traffic from 10.0.0.1.",
                evidence="check_reputation",
                related_entities=["10.0.0.1"],
            )
        ]
    )
    store.persist("run-empty-list", alert, verdict)

    # Only the non-empty "10.0.0.1" should exist.
    recalled = store.recall(_alert(alert_id="A2", entities={"ips": ["10.0.0.1"]}))
    assert recalled

    empty_recall = store.recall(_alert(alert_id="A3", entities={"ips": [""]}))
    assert empty_recall == []


def test_mixed_scalar_and_list_entities_both_persist(tmp_path: Path) -> None:
    """Both scalar str and list entities in the same alert are all persisted."""
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(entities={"user": "alice", "source_ips": ["1.2.3.4", "5.6.7.8"]})
    verdict = _verdict(
        findings=[
            Finding(
                statement="alice triggered traffic from 1.2.3.4 and 5.6.7.8.",
                evidence="check_reputation",
                related_entities=["alice", "1.2.3.4", "5.6.7.8"],
            )
        ]
    )
    store.persist("run-combo", alert, verdict)

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
        _verdict(
            confidence=0.5,
            findings=[
                Finding(
                    statement="valid fact",
                    evidence="ev",
                    related_entities=["10.0.0.9"],
                )
            ],
        ),
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


# --------------------------------------------------------------------------- #
# RFC-0003 adjacent hardening: 0o700 permissions on .memory/                   #
# --------------------------------------------------------------------------- #


def test_memory_store_creates_base_dir_with_0o700(tmp_path: Path) -> None:
    """MemoryStore creates .memory/ with mode 0o700 (owner-only access).

    Skipped on Windows where POSIX mode bits are not enforced.
    """
    if sys.platform == "win32":
        return  # pragma: no cover  # POSIX permissions not applicable on Windows.
    store = MemoryStore(base_dir=tmp_path / ".memory-perm-test")
    store.persist(
        "run-perm",
        _alert(alert_id="ALT-perm", entities={"user": "alice"}),
        _verdict(
            findings=[
                Finding(
                    statement="perm test",
                    evidence="ev",
                    related_entities=["alice"],
                )
            ]
        ),
    )
    mode = store.base_dir.stat().st_mode & 0o777
    assert mode & 0o700 == 0o700, f"expected 0o700 bits set, got {oct(mode)}"
    assert mode & 0o077 == 0, f"expected no group/other bits, got {oct(mode)}"


# --------------------------------------------------------------------------- #
# ADR-0006 success metric — zero cross-entity recall, cartesian gone          #
# --------------------------------------------------------------------------- #


def test_two_incidents_sharing_one_entity_no_cross_entity_recall(
    tmp_path: Path,
) -> None:
    """US-0006 success metric: two incidents share one entity value but each
    has exclusive findings.  Recall for Alice must NOT return findings that
    name only Bob, and vice versa (cartesian fan-out is gone).

    Incident A: users alice + bob; finding_A exclusively about alice.
    Incident B: users alice + carol; finding_B exclusively about carol.
    Recall for alice returns only finding_A (shared entity, correctly stored).
    Recall for bob returns nothing (finding_A not about bob).
    Recall for carol returns finding_B only (not cross-contaminated).
    """
    store = MemoryStore(base_dir=tmp_path)

    # Incident A — two users; only finding_A names alice.
    alert_a = _alert(
        alert_id="ALT-A",
        entities={"user": "alice", "secondary_user": "bob"},
        context={},
    )
    verdict_a = _verdict(
        findings=[
            Finding(
                statement="alice accessed the restricted share.",
                evidence="lookup_user found alice in the audit trail",
                related_entities=["alice"],
            )
        ]
    )
    store.persist("run-A", alert_a, verdict_a)

    # Incident B — two users; only finding_B names carol.
    alert_b = _alert(
        alert_id="ALT-B",
        entities={"user": "alice", "secondary_user": "carol"},
        context={},
    )
    verdict_b = _verdict(
        findings=[
            Finding(
                statement="carol exfiltrated data from the prod bucket.",
                evidence="query_logs detected carol's S3 calls",
                related_entities=["carol"],
            )
        ]
    )
    store.persist("run-B", alert_b, verdict_b)

    # Alice recall: only incident A's finding (alice is named there).
    alice_recall = store.recall(_alert(alert_id="Q1", entities={"user": "alice"}))
    assert any("alice accessed" in item["content"] for item in alice_recall), (
        "alice's finding must be recalled for alice"
    )
    assert not any("carol exfiltrated" in item["content"] for item in alice_recall), (
        "carol's finding must NOT be cross-recalled for alice"
    )

    # Bob recall: zero items (finding_A never named bob).
    # Bob is keyed as secondary_user=bob; the finding only named alice.
    bob_recall = store.recall(_alert(alert_id="Q2", entities={"secondary_user": "bob"}))
    assert bob_recall == [], "bob was not named in any finding — cartesian fan-out is gone"

    # Carol recall: only incident B's finding.
    # Carol is keyed as secondary_user=carol in alert_b.
    carol_recall = store.recall(_alert(alert_id="Q3", entities={"secondary_user": "carol"}))
    assert any("carol exfiltrated" in item["content"] for item in carol_recall), (
        "carol's finding must be recalled for carol"
    )
    assert not any("alice accessed" in item["content"] for item in carol_recall), (
        "alice's finding must NOT be cross-recalled for carol"
    )


def test_cartesian_four_entities_four_findings_not_16_atoms(tmp_path: Path) -> None:
    """US-0006 success metric: 4 entities x 4 findings does NOT equal 16 atoms.

    Under the old cartesian model every finding would produce an atom for every
    entity, regardless of relevance.  Under ADR-0006 only declared/detected
    attributions produce atoms — so a finding about entity A produces exactly one
    atom (for A), not four.
    """
    store = MemoryStore(base_dir=tmp_path)
    alert = _alert(
        alert_id="ALT-CART",
        entities={
            "user": "alice",
            "ip": "10.0.0.1",
            "host": "srv-001",
            "bucket": "prod-data",
        },
        context={},
    )
    verdict = _verdict(
        findings=[
            Finding(
                statement="alice initiated the session.",
                evidence="lookup_user confirmed alice",
                related_entities=["alice"],
            ),
            Finding(
                statement="traffic originated from 10.0.0.1.",
                evidence="check_reputation flagged 10.0.0.1",
                related_entities=["10.0.0.1"],
            ),
            Finding(
                statement="srv-001 is a known jump host.",
                evidence="get_asset_info returned srv-001 profile",
                related_entities=["srv-001"],
            ),
            Finding(
                statement="prod-data bucket was accessed.",
                evidence="query_logs shows prod-data writes",
                related_entities=["prod-data"],
            ),
        ]
    )
    store.persist("run-cart", alert, verdict)

    # Each finding names exactly one entity -> 4 atoms total (not 4x4=16).
    alice_atoms = store.dossier("user", "alice")
    ip_atoms = store.dossier("ip", "10.0.0.1")
    host_atoms = store.dossier("host", "srv-001")
    bucket_atoms = store.dossier("bucket", "prod-data")

    assert len(alice_atoms) == 1, "alice must have exactly 1 atom"
    assert len(ip_atoms) == 1, "ip must have exactly 1 atom"
    assert len(host_atoms) == 1, "host must have exactly 1 atom"
    assert len(bucket_atoms) == 1, "bucket must have exactly 1 atom"

    # Cartesian would have given 16; attributed gives 4.
    total = len(alice_atoms) + len(ip_atoms) + len(host_atoms) + len(bucket_atoms)
    assert total == 4, f"expected 4 atoms total (attributed), got {total} (cartesian would be 16)"


# --------------------------------------------------------------------------- #
# ADR-0006 entity-attribution coverage — _entity_type_for branches            #
# --------------------------------------------------------------------------- #


def test_context_only_attributed_finding_is_unattributed(tmp_path: Path) -> None:
    """A finding that declares a context-only value (not in entities dict) is
    unattributed — ``_entity_type_for`` returns None for context values, so no
    atom is written.  Covers attribution.py line 100 (return None path).
    """
    store = MemoryStore(base_dir=tmp_path)
    # "deploy-prod" is only in context, not in entities.
    alert = _alert(
        entities={"user": "alice"},
        context={"pipeline": "deploy-prod"},
    )
    verdict = _verdict(
        findings=[
            Finding(
                statement="Pipeline deploy-prod was invoked.",
                evidence="query_logs",
                # Declared context value — valid to attribute but has no entity_type.
                related_entities=["deploy-prod"],
            )
        ]
    )
    store.persist("run-ctx", alert, verdict)
    # Context-only attribution → unattributed → no atom persisted.
    assert list(tmp_path.glob("*.jsonl")) == []
    assert store.recall(_alert(alert_id="A2", entities={"user": "alice"})) == []


def test_list_entity_match_in_second_type_covers_loop_fallthrough(
    tmp_path: Path,
) -> None:
    """When entities has two list entity_types and the attributed value is in
    the SECOND list, ``_entity_type_for`` iterates through the first list without
    finding it (branch 97->93 in attribution.py) before matching the second.
    """
    store = MemoryStore(base_dir=tmp_path)
    # Two list entity_types; attributed value "5.6.7.8" is only in the second.
    alert = _alert(
        entities={
            "src_ips": ["1.2.3.4", "2.3.4.5"],
            "dst_ips": ["5.6.7.8", "9.10.11.12"],
        },
        context={},
    )
    verdict = _verdict(
        findings=[
            Finding(
                statement="Egress to 5.6.7.8 detected.",
                evidence="check_reputation",
                related_entities=["5.6.7.8"],
            )
        ]
    )
    store.persist("run-list2", alert, verdict)
    # Atom persisted under dst_ips / 5.6.7.8.
    atoms = store.dossier("dst_ips", "5.6.7.8")
    assert len(atoms) == 1
    assert atoms[0].entity_value == "5.6.7.8"
    assert atoms[0].entity_type == "dst_ips"
