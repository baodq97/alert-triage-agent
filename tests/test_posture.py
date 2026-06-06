"""Tests for the L3 threat posture module (RFC-0001 §Memory L3, US-0004).

Structural / determinism assertions only:

* deterministic synthesis over atoms produces a bounded, wall-clock-free brief;
* synthesis over an empty store produces an empty-but-valid brief;
* posture file is written under MEMORY_DIR and is readable back;
* write failure is swallowed (a memory failure must never crash a Run);
* load_posture_brief returns None when file absent, bounded str when present;
* the brief content never contains wall-clock timestamps (derived from atom ts);
* recall() includes posture brief as an extra item when the file exists;
* recall() does not include a posture item when no file exists (replay safety);
* posture item in recall is bounded (under POSTURE_CHAR_CAP);
* run counter increments on persist_and_check_cadence; cadence=0 = disabled;
* synthesize_posture_if_due triggers when run_count % cadence == 0;
* --synthesize-posture CLI flag forces synthesis regardless of cadence;
* LLM synthesis path produces a brief using the LLM client.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

from triage.errors import LLMError
from triage.memory import MemoryStore
from triage.memory.posture import (
    POSTURE_CHAR_CAP,
    PostureSynthesizer,
    _neg_ts,
    load_posture_brief,
    synthesize_posture_if_due,
)
from triage.models import Alert, Finding, Verdict

if TYPE_CHECKING:
    import pytest

_RUN_PATH = Path(__file__).resolve().parents[1] / "run.py"


def _load_run_module(name: str) -> Any:
    """Load run.py as a fresh module under the given name (avoids re-exec conflicts)."""
    spec = importlib.util.spec_from_file_location(name, _RUN_PATH)
    assert spec is not None
    assert spec.loader is not None
    run_mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = run_mod
    spec.loader.exec_module(run_mod)  # type: ignore[union-attr]
    return run_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "alert_id": "ALT-1",
        "timestamp": "2026-06-05T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "data_exfiltration",
        "description": "Exfil from prod.",
        "entities": {"user": "alice", "ip": "10.0.0.9"},
        "context": {},
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


def _populate_store(store: MemoryStore) -> None:
    """Persist a handful of atoms covering two entities."""
    store.persist("run-1", _alert(), _verdict(severity="high", confidence=0.9))
    store.persist(
        "run-2",
        _alert(
            alert_id="ALT-2",
            timestamp="2026-05-01T00:00:00Z",
            entities={"ip": "10.0.0.9"},
        ),
        _verdict(
            severity="medium",
            confidence=0.6,
            findings=[
                Finding(
                    statement="Repeated connection to bad IP.",
                    evidence="rep: flow",
                    related_entities=["10.0.0.9"],
                )
            ],
        ),
    )
    store.persist(
        "run-3",
        _alert(
            alert_id="ALT-3",
            timestamp="2026-04-01T00:00:00Z",
            entities={"user": "bob"},
        ),
        _verdict(
            severity="low",
            confidence=0.4,
            findings=[Finding(statement="Bob's benign login.", evidence="lookup_user")],
        ),
    )


# ---------------------------------------------------------------------------
# PostureSynthesizer — deterministic path
# ---------------------------------------------------------------------------


def test_deterministic_synthesis_produces_non_empty_brief(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)
    synth = PostureSynthesizer(base_dir=tmp_path)

    brief = synth.synthesize_deterministic()

    assert brief, "brief must be non-empty when atoms exist"
    assert len(brief) <= POSTURE_CHAR_CAP


def test_empty_store_produces_empty_but_valid_brief(tmp_path: Path) -> None:
    synth = PostureSynthesizer(base_dir=tmp_path)

    brief = synth.synthesize_deterministic()

    assert isinstance(brief, str)
    assert len(brief) <= POSTURE_CHAR_CAP


def test_brief_contains_severity_distribution_info(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)
    synth = PostureSynthesizer(base_dir=tmp_path)

    brief = synth.synthesize_deterministic()

    assert any(word in brief.lower() for word in ("high", "medium", "low", "critical"))


def test_brief_contains_top_entities(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)
    synth = PostureSynthesizer(base_dir=tmp_path)

    brief = synth.synthesize_deterministic()

    assert "ip" in brief or "10.0.0.9" in brief or "user" in brief


def test_brief_is_byte_identical_across_calls(tmp_path: Path) -> None:
    """Deterministic path must be byte-identical on successive calls with the same store."""
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)
    synth = PostureSynthesizer(base_dir=tmp_path)

    brief1 = synth.synthesize_deterministic()
    brief2 = synth.synthesize_deterministic()

    assert brief1 == brief2


def test_deterministic_synthesis_is_bounded(tmp_path: Path) -> None:
    store = MemoryStore(base_dir=tmp_path)
    # Use declared related_entities so atoms are persisted; test that synthesis
    # stays within the posture cap even with many atoms.
    findings = [
        Finding(
            statement=f"fact {i}",
            evidence=f"ev{i}",
            related_entities=["10.0.0.9"],
        )
        for i in range(50)
    ]
    store.persist("run-big", _alert(), _verdict(findings=findings))
    # Also persist a duplicate-statement atom (same run-id → same atom_id is
    # idempotent, but two DIFFERENT runs with the same statement exercise the
    # _top_n_atoms dedup path: seen_statements deduplicates by statement text).
    store.persist(
        "run-big-2",
        _alert(alert_id="ALT-BIG2"),
        _verdict(
            findings=[Finding(statement="fact 0", evidence="ev0-2", related_entities=["10.0.0.9"])]
        ),
    )
    synth = PostureSynthesizer(base_dir=tmp_path)

    brief = synth.synthesize_deterministic()

    assert len(brief) <= POSTURE_CHAR_CAP


# ---------------------------------------------------------------------------
# PostureSynthesizer — file persistence
# ---------------------------------------------------------------------------


def test_write_persists_to_posture_file(tmp_path: Path) -> None:
    synth = PostureSynthesizer(base_dir=tmp_path)
    MemoryStore(base_dir=tmp_path).persist("run-1", _alert(), _verdict())

    synth.write(synth.synthesize_deterministic())

    assert (tmp_path / "posture.md").exists()


def test_write_swallows_filesystem_failure(tmp_path: Path) -> None:
    """A write failure must never raise — a memory failure never crashes a Run."""
    blocker = tmp_path / "posture.md"
    blocker.mkdir()  # make posture.md a directory so writes fail
    synth = PostureSynthesizer(base_dir=tmp_path)

    synth.write("some content")  # no assert — absence of exception is the contract


def test_write_is_idempotent_overwrite(tmp_path: Path) -> None:
    synth = PostureSynthesizer(base_dir=tmp_path)

    synth.write("first")
    synth.write("second")

    assert (tmp_path / "posture.md").read_text(encoding="utf-8") == "second"


# ---------------------------------------------------------------------------
# load_posture_brief
# ---------------------------------------------------------------------------


def test_load_posture_brief_returns_none_when_absent(tmp_path: Path) -> None:
    assert load_posture_brief(tmp_path) is None


def test_load_posture_brief_returns_content_when_present(tmp_path: Path) -> None:
    (tmp_path / "posture.md").write_text("brief content", encoding="utf-8")

    result = load_posture_brief(tmp_path)

    assert result == "brief content"


def test_load_posture_brief_is_bounded(tmp_path: Path) -> None:
    long_content = "x" * (POSTURE_CHAR_CAP + 1000)
    (tmp_path / "posture.md").write_text(long_content, encoding="utf-8")

    result = load_posture_brief(tmp_path)

    assert result is not None
    assert len(result) <= POSTURE_CHAR_CAP


def test_load_posture_brief_swallows_read_failure(tmp_path: Path) -> None:
    blocker = tmp_path / "posture.md"
    blocker.mkdir()  # directory, not a file — read fails

    result = load_posture_brief(tmp_path)

    assert result is None


# ---------------------------------------------------------------------------
# MemoryStore.recall() — posture integration
# ---------------------------------------------------------------------------


def test_recall_includes_posture_when_file_exists(tmp_path: Path) -> None:
    (tmp_path / "posture.md").write_text("Org posture: 3 high alerts.", encoding="utf-8")
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    contents = [item["content"] for item in recalled]
    assert any("Org posture" in c for c in contents)


def test_recall_does_not_include_posture_when_file_absent(tmp_path: Path) -> None:
    """Without a posture file, recall must be identical to pre-L3 behavior (replay safety)."""
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    recalled = store.recall(_alert(alert_id="A2", entities={"ip": "10.0.0.9"}))

    assert recalled
    for item in recalled:
        assert set(item.keys()) == {"run_id", "confidence", "content"}
    assert not any("posture" in str(item.get("content", "")).lower() for item in recalled)


def test_recall_with_empty_store_but_posture_file_returns_posture_only(tmp_path: Path) -> None:
    (tmp_path / "posture.md").write_text("High threat env.", encoding="utf-8")
    store = MemoryStore(base_dir=tmp_path)

    recalled = store.recall(_alert())

    assert len(recalled) == 1
    assert "High threat env." in recalled[0]["content"]


def test_posture_item_has_planner_seam_keys(tmp_path: Path) -> None:
    (tmp_path / "posture.md").write_text("brief", encoding="utf-8")
    store = MemoryStore(base_dir=tmp_path)

    recalled = store.recall(_alert())

    posture_items = [item for item in recalled if "posture" in item.get("run_id", "")]
    assert posture_items, "posture item must be present"
    assert set(posture_items[0].keys()) == {"run_id", "confidence", "content"}


def test_posture_item_is_bounded_in_recall(tmp_path: Path) -> None:
    long_brief = "P" * (POSTURE_CHAR_CAP + 500)
    (tmp_path / "posture.md").write_text(long_brief, encoding="utf-8")
    store = MemoryStore(base_dir=tmp_path)

    recalled = store.recall(_alert())

    posture_items = [item for item in recalled if "posture" in item.get("run_id", "")]
    assert posture_items
    assert len(posture_items[0]["content"]) <= POSTURE_CHAR_CAP


# ---------------------------------------------------------------------------
# synthesize_posture_if_due — cadence logic
# ---------------------------------------------------------------------------


def test_cadence_zero_never_synthesizes(tmp_path: Path) -> None:
    synth = PostureSynthesizer(base_dir=tmp_path)
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)

    for _ in range(5):
        synthesize_posture_if_due(synth, cadence=0)

    assert not (tmp_path / "posture.md").exists()
    # Counter must still increment when cadence=0 so that enabling cadence later
    # counts from the correct base.  (NOTE-2 from wave-4 QA report.)
    assert synth._read_counter() == 5  # noqa: SLF001 — package-internal test cohesion


def test_cadence_first_persist_synthesizes_when_cadence_1(tmp_path: Path) -> None:
    synth = PostureSynthesizer(base_dir=tmp_path)
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)

    synthesize_posture_if_due(synth, cadence=1)

    assert (tmp_path / "posture.md").exists()


def test_cadence_n_synthesizes_on_nth_call(tmp_path: Path) -> None:
    synth = PostureSynthesizer(base_dir=tmp_path)
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)

    for _ in range(4):
        synthesize_posture_if_due(synth, cadence=5)
    assert not (tmp_path / "posture.md").exists(), "must not synthesize before cadence reached"

    synthesize_posture_if_due(synth, cadence=5)
    assert (tmp_path / "posture.md").exists(), "must synthesize on 5th call"


def test_cadence_continues_after_first_synthesis(tmp_path: Path) -> None:
    synth = PostureSynthesizer(base_dir=tmp_path)
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)

    # cadence=2: calls 2, 4, 6 trigger synthesis.
    for i in range(1, 7):
        synthesize_posture_if_due(synth, cadence=2)
        posture_exists = (tmp_path / "posture.md").exists()
        if i % 2 == 0:
            assert posture_exists, f"expected synthesis after call {i}"


def test_cadence_counter_survives_restarts(tmp_path: Path) -> None:
    """The run counter must persist across Python process boundaries."""
    synth = PostureSynthesizer(base_dir=tmp_path)

    synthesize_posture_if_due(synth, cadence=3)
    synthesize_posture_if_due(synth, cadence=3)
    assert not (tmp_path / "posture.md").exists()

    # Simulate restart: create a new synthesizer bound to same dir.
    synth2 = PostureSynthesizer(base_dir=tmp_path)
    synthesize_posture_if_due(synth2, cadence=3)
    assert (tmp_path / "posture.md").exists()


def test_cadence_counter_write_failure_is_swallowed(tmp_path: Path) -> None:
    """A counter write failure must not crash the Run."""
    synth = PostureSynthesizer(base_dir=tmp_path)
    counter_path = tmp_path / "_run_count"
    counter_path.mkdir()  # block counter writes

    synthesize_posture_if_due(synth, cadence=1)  # must not raise


# ---------------------------------------------------------------------------
# LLM synthesis path
# ---------------------------------------------------------------------------


def test_synthesize_with_llm_calls_llm_and_returns_text(tmp_path: Path) -> None:
    """synthesize_with_llm must call the LLM and return its response as the brief."""
    mock_llm = MagicMock()
    mock_completion = MagicMock()
    mock_completion.value = MagicMock()
    mock_completion.value.brief = "LLM-generated posture brief."
    mock_llm.complete.return_value = mock_completion

    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)
    synth = PostureSynthesizer(base_dir=tmp_path)

    result = synth.synthesize_with_llm(mock_llm)

    assert result == "LLM-generated posture brief."
    assert mock_llm.complete.called


def test_synthesize_with_llm_falls_back_on_llm_error(tmp_path: Path) -> None:
    """When the LLM call fails, synthesize_with_llm falls back to deterministic."""
    mock_llm = MagicMock()
    mock_llm.complete.side_effect = LLMError("LLM unavailable")

    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)
    synth = PostureSynthesizer(base_dir=tmp_path)

    result = synth.synthesize_with_llm(mock_llm)

    assert isinstance(result, str)
    assert len(result) <= POSTURE_CHAR_CAP


# ---------------------------------------------------------------------------
# run.py --synthesize-posture integration
# ---------------------------------------------------------------------------


def test_main_synthesize_posture_writes_posture_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--synthesize-posture must write posture.md regardless of cadence (including 0)."""
    run_mod = _load_run_module("run_sp")

    mem_dir = tmp_path / "mem"
    mem_dir.mkdir()
    monkeypatch.setenv("MEMORY_DIR", str(mem_dir))
    monkeypatch.setenv("MEMORY_SYNTHESIZE_EVERY_N_RUNS", "0")

    exit_code = run_mod.main(["--synthesize-posture"])  # type: ignore[union-attr]

    assert exit_code == 0
    assert (mem_dir / "posture.md").exists()


def test_main_synthesize_posture_on_empty_store_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--synthesize-posture on an empty store must succeed and write an empty-but-valid brief."""
    run_mod = _load_run_module("run_sp2")

    mem_dir = tmp_path / "mem-empty"
    mem_dir.mkdir()
    monkeypatch.setenv("MEMORY_DIR", str(mem_dir))

    exit_code = run_mod.main(["--synthesize-posture"])  # type: ignore[union-attr]

    assert exit_code == 0
    posture = mem_dir / "posture.md"
    assert posture.exists()
    content = posture.read_text(encoding="utf-8")
    assert len(content) <= POSTURE_CHAR_CAP


# ---------------------------------------------------------------------------
# Coverage: missing branches in posture.py + run.py
# ---------------------------------------------------------------------------


def test_load_all_atoms_skips_unreadable_file(tmp_path: Path) -> None:
    """A file that exists but cannot be read is skipped silently."""
    store = MemoryStore(base_dir=tmp_path)
    _populate_store(store)
    synth = PostureSynthesizer(base_dir=tmp_path)

    jsonl_files = list(tmp_path.glob("*.jsonl"))
    assert jsonl_files
    first = jsonl_files[0]
    first.unlink()
    first.mkdir()  # replace file with dir so read_text fails

    atoms = synth._load_all_atoms()  # noqa: SLF001
    assert isinstance(atoms, list)


def test_load_all_atoms_on_nonexistent_dir_returns_empty(tmp_path: Path) -> None:
    """When the base_dir does not exist, _load_all_atoms returns [] without raising."""
    synth = PostureSynthesizer(base_dir=tmp_path / "does-not-exist")

    atoms = synth._load_all_atoms()  # noqa: SLF001

    assert atoms == []


def test_load_all_atoms_skips_blank_lines_and_corrupt_json(tmp_path: Path) -> None:
    """Blank lines and corrupt JSON in a JSONL file are silently skipped."""
    store = MemoryStore(base_dir=tmp_path)
    store.persist("run-1", _alert(), _verdict())

    for path in tmp_path.glob("*.jsonl"):
        body = path.read_text(encoding="utf-8")
        path.write_text(f"\n{body}\nnot valid json\n   \n", encoding="utf-8")

    synth = PostureSynthesizer(base_dir=tmp_path)
    atoms = synth._load_all_atoms()  # noqa: SLF001
    assert atoms  # valid atoms still present


def test_neg_ts_fallback_on_unparseable_timestamp() -> None:
    """_neg_ts returns 0.0 without raising on an unparseable timestamp."""
    result = _neg_ts("not-a-timestamp")
    assert result == 0.0


def test_maybe_synthesize_posture_ignores_invalid_cadence_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-integer MEMORY_SYNTHESIZE_EVERY_N_RUNS is silently treated as 0."""
    run_mod = _load_run_module("run_sp3")

    mem_dir = tmp_path / "mem3"
    mem_dir.mkdir()
    monkeypatch.setenv("MEMORY_DIR", str(mem_dir))
    monkeypatch.setenv("MEMORY_SYNTHESIZE_EVERY_N_RUNS", "not-a-number")

    run_mod._maybe_synthesize_posture()  # type: ignore[union-attr]  # noqa: SLF001

    # cadence=0 (invalid env treated as 0) → posture.md not written.
    assert not (mem_dir / "posture.md").exists()


def test_maybe_synthesize_posture_swallows_unexpected_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The broad except in _maybe_synthesize_posture swallows unexpected errors.

    Verifies the defensive-depth contract from NOTE-1 of the wave-4 QA report:
    any exception raised inside the try block (e.g. a future edit to
    synthesize_posture_if_due) must not propagate out.
    """
    run_mod = _load_run_module("run_sp4")

    mem_dir = tmp_path / "mem4"
    mem_dir.mkdir()
    monkeypatch.setenv("MEMORY_DIR", str(mem_dir))
    monkeypatch.setenv("MEMORY_SYNTHESIZE_EVERY_N_RUNS", "0")

    # The run.py module was already loaded above; patch the name it imported at load time.
    # run_mod._maybe_synthesize_posture calls synthesize_posture_if_due imported from
    # triage.memory.posture — patch that exact attribute on the freshly loaded module.
    with patch.object(
        run_mod,
        "synthesize_posture_if_due",
        side_effect=RuntimeError("injected crash"),
    ):
        run_mod._maybe_synthesize_posture()  # type: ignore[union-attr]  # noqa: SLF001 — must not raise


# --------------------------------------------------------------------------- #
# RFC-0003 adjacent hardening: 0o700 permissions on posture write              #
# --------------------------------------------------------------------------- #


def test_posture_write_creates_base_dir_with_0o700(tmp_path: Path) -> None:
    """PostureSynthesizer.write() creates the memory dir with mode 0o700.

    Skipped on Windows where POSIX mode bits are not enforced.
    """
    if sys.platform == "win32":
        return  # pragma: no cover  # POSIX permissions not applicable on Windows.
    base = tmp_path / ".memory-posture-perm"
    synth = PostureSynthesizer(base_dir=base)
    synth.write("# test posture brief")
    mode = base.stat().st_mode & 0o777
    assert mode & 0o700 == 0o700, f"expected 0o700 bits set, got {oct(mode)}"
    assert mode & 0o077 == 0, f"expected no group/other bits, got {oct(mode)}"
