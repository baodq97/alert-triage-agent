"""The Memory Store — L1 finding atoms, L2 dossiers, entity-scoped recall.

Persistence is a deterministic on-disk JSONL store, one file per entity under a
configurable base dir (``MEMORY_DIR``, default ``.memory/``). The file name is the
sha256 of the entity key, never the raw entity value: entity values come from the
untrusted alert payload (ADR-0005), so using them as path components would be a
path-traversal write primitive. The raw entity type/value are stored *inside* each
atom; recall hashes the key to locate the file.

Levels (RFC-0001 §Memory):

* **L1 — Finding Atoms** (``persist``): each ``(attributed entity, finding)`` pair
  becomes one atom appended to that entity's file.  Attribution follows ADR-0006's
  resolution order (declared → detected → unattributed).
* **L2 — Entity Dossier** (``dossier``): the deterministic group-by of all atoms
  for one entity, derived on read (dedupe by ``atom_id``, stably sorted). No LLM.
* **Recall** (``recall``): the atoms for the *current alert's* entities only —
  never the whole store — shaped exactly for ``Planner.plan``'s ``recall`` param
  (``run_id`` / ``confidence`` / ``content`` per item), confidence-ranked and
  capped top-N (RFC-0001 §Memory: dossier injection is capped per alert).

**L3 (threat posture) is Wave 4 and is intentionally not built here.** The seam:
an org-level brief, synthesized on the ``MEMORY_SYNTHESIZE_EVERY_N_RUNS`` cadence
with a deterministic top-N degradation path, would join ``recall``'s output as an
extra (non-entity-scoped) item — added without disturbing this leaf's contract.

A memory failure must never crash a Run: ``persist`` and ``recall`` swallow
filesystem and JSON-decode errors and degrade to a no-op / empty recall. No typed
``TriageError`` is raised from this module (none is warranted — the seam is
best-effort), so nothing here crosses a module boundary as an exception.

**ADR-0006 entity-attribution (US-0006):**

``persist`` uses ``attribution.attribute_finding`` (ADR-0006's resolution order)
rather than a cartesian fan-out.  Only the attributed entity values are keyed;
a finding unattributed by both the declared and detection paths persists no atom
and emits a ``finding_unattributed`` journal event — visible in the audit trail,
never silently lost.

Attribution VALIDATES against ``entities union context`` values (per ADR-0006 §1):
a context entity value (e.g. a pipeline name) is a valid attribution target.
However, ATOM KEYS remain envelope ``entities`` only: ``entity_type`` is looked
up in ``alert.entities``; when a value matches only ``context`` (not in
``entities``), it has no ``entity_type`` in the envelope, so no atom is written
for that value — context-attributed findings go to the unattributed path.
This preserves recall compatibility (recall scopes by alert entities, keyed on
``entity_type``); context-only findings are surfaced via ``finding_unattributed``
in the audit trail.

**Existing stores:** no migration required.  Old cartesian atoms age out by
confidence/recency ranking on recall; new attributed atoms simply score alongside
them.  The append-only, idempotent atom contract makes coexistence safe.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from triage.attribution import _entity_type_for, attribute_finding
from triage.constants import EVT_FINDING_UNATTRIBUTED
from triage.memory.atoms import FindingAtom, atom_id_for
from triage.memory.posture import load_posture_brief

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from triage.journal import Journal
    from triage.models import Alert, Verdict

_UNATTRIBUTED_STATEMENT_MAX = 200
"""Max chars for the statement field in ``finding_unattributed`` events."""

_DEFAULT_BASE_DIR = ".memory"
_ENV_VAR = "MEMORY_DIR"


class MemoryStore:
    """Entity-keyed JSONL memory: persist atoms, derive dossiers, scope recall."""

    RECALL_TOP_N = 10
    """Cap on recalled items per alert (RFC-0001 §Memory dossier-injection cap)."""

    def __init__(self, base_dir: str | os.PathLike[str] | None = None) -> None:
        """Bind the store base dir.

        Args:
            base_dir: Where per-entity files live. Defaults to ``$MEMORY_DIR``,
                then the documented ``.memory/`` dir when the env var is unset.
        """
        if base_dir is None:
            base_dir = os.environ.get(_ENV_VAR, _DEFAULT_BASE_DIR)
        self.base_dir = Path(base_dir)

    def persist(
        self,
        run_id: str,
        alert: Alert,
        verdict: Verdict,
        *,
        journal: Journal | None = None,
    ) -> None:
        """Persist one L1 atom per ``(attributed entity, finding)`` association.

        Attribution follows ADR-0006's resolution order:

        1. **Declared** — ``finding.related_entities`` is not ``None``: validated
           against ``alert.entities union scalar string values of alert.context``; only
           values matching an envelope entity (``alert.entities``) yield atoms —
           context-only values emit ``finding_unattributed`` (see module docstring).
        2. **Detected (fallback)** — ``finding.related_entities`` is ``None``: a
           substring scan of the finding text against the known entity values.
        3. **Unattributed** — neither path yields an envelope entity: no atom
           persisted; a ``finding_unattributed`` event is emitted to ``journal``
           when provided (``None`` = silent, preserving the leaf's best-effort
           posture; ``core._conclude_run`` passes the real journal).

        Atom KEYS are envelope ``entities`` only (``entity_type`` is looked up
        from ``alert.entities``).  This preserves recall compatibility: recall
        scopes by alert entities, keyed on ``entity_type``.

        Empty entities or empty findings persist nothing. Writes are idempotent:
        an atom's id is deterministic, so a resumed/replayed re-persist does not
        duplicate it. A filesystem failure is swallowed — a memory write never
        crashes a Run.

        Args:
            run_id: The Run's unique identifier (stamped on every atom).
            alert: The Alert whose entity envelope defines valid atom keys.
            verdict: The synthesized Verdict whose findings are attributed.
            journal: Optional Journal for ``finding_unattributed`` events.  Pass
                the real journal from ``core._conclude_run``; omit (or pass
                ``None``) from ``_seed_memory`` (NoopJournal acceptable there).
        """
        atoms_by_entity: dict[tuple[str, str], list[FindingAtom]] = {}
        for finding in verdict.findings:
            attributed_values = attribute_finding(finding, alert)
            # Filter to envelope entities only (context-only values have no
            # entity_type in the envelope and cannot key an atom — see module
            # docstring: "ATOM KEYS remain envelope entities only").
            envelope_values = [
                value
                for value in attributed_values
                if _entity_type_for(value, alert.entities) is not None
            ]

            if not envelope_values:
                # Unattributed path: emit journal event when a journal is provided.
                if journal is not None:
                    journal.emit(
                        EVT_FINDING_UNATTRIBUTED,
                        {
                            "statement": finding.statement[:_UNATTRIBUTED_STATEMENT_MAX],
                            "reason": (
                                "no alert entity attributed to this finding"
                                " (declared empty or text-scan found nothing)"
                            ),
                        },
                    )
                continue

            for entity_value in envelope_values:
                entity_type = _entity_type_for(entity_value, alert.entities)
                if entity_type is None:  # pragma: no cover  # defensive: filtered above
                    continue  # safety guard — envelope_values only contains matched values
                atom = FindingAtom(
                    atom_id=atom_id_for(
                        run_id=run_id,
                        entity_type=entity_type,
                        entity_value=entity_value,
                        statement=finding.statement,
                        evidence=finding.evidence,
                    ),
                    entity_type=entity_type,
                    entity_value=entity_value,
                    statement=finding.statement,
                    evidence=finding.evidence,
                    severity=verdict.severity,
                    confidence=verdict.confidence,
                    run_id=run_id,
                    ts=alert.timestamp,
                )
                atoms_by_entity.setdefault((entity_type, entity_value), []).append(atom)

        for (entity_type, entity_value), atoms in atoms_by_entity.items():
            self._append(entity_type, entity_value, atoms)

    def dossier(self, entity_type: str, entity_value: str) -> list[FindingAtom]:
        """Return the deterministic L2 dossier for one entity (no LLM).

        Group-by-on-read: all atoms in the entity's file, deduped by ``atom_id``
        and stably ordered. A missing file or corrupt content yields an empty
        dossier rather than crashing.
        """
        seen: dict[str, FindingAtom] = {}
        for atom in self._read_atoms(entity_type, entity_value):
            seen.setdefault(atom.atom_id, atom)
        return sorted(seen.values(), key=_atom_sort_key)

    def recall(self, alert: Alert) -> list[Mapping[str, Any]]:
        """Recall the prior atoms for ``alert``'s entities, shaped for the planner.

        Entity-scoped: only atoms for the current alert's matchable entities — the
        whole store is never returned. Each item is atom-grained and carries
        exactly the ``Planner.plan`` recall keys (``run_id`` / ``confidence`` /
        ``content``). Items are ranked confidence-desc (then recency) and capped at
        :attr:`RECALL_TOP_N`. An empty/missing/corrupt store recalls ``[]``.

        **L3 posture (Wave 4):** if ``.memory/posture.md`` exists, one extra item is
        appended *after* the entity-scoped atoms — the org-level posture brief,
        labeled as untrusted context from ``"posture-brief"`` with ``confidence=0.0``
        (the lowest possible, so the planner discounts it appropriately).  When no
        posture file exists the output is byte-identical to pre-L3 behavior, keeping
        the 34 replay caches valid.
        """
        atoms: dict[str, FindingAtom] = {}
        for entity_type, entity_value in _matchable_entities(alert.entities):
            for atom in self._read_atoms(entity_type, entity_value):
                atoms.setdefault(atom.atom_id, atom)
        ranked = sorted(atoms.values(), key=_recall_sort_key)[: self.RECALL_TOP_N]
        items: list[Mapping[str, Any]] = [_to_recall_item(atom) for atom in ranked]
        # Append the L3 posture brief as an extra non-entity-scoped item — only when
        # the file exists (the default state is absent, preserving replay-cache
        # compatibility).
        brief = load_posture_brief(self.base_dir)
        if brief is not None:
            items.append(_to_posture_item(brief))
        return items

    def _path_for(self, entity_type: str, entity_value: str) -> Path:
        """Map an entity key to its (hashed, traversal-safe) JSONL file path."""
        key = f"{entity_type}={entity_value}".encode()
        return self.base_dir / f"{hashlib.sha256(key).hexdigest()}.jsonl"

    def _append(self, entity_type: str, entity_value: str, atoms: Sequence[FindingAtom]) -> None:
        """Append atoms to an entity file, swallowing any filesystem failure."""
        path = self._path_for(entity_type, entity_value)
        try:
            # 0o700: the memory dir contains per-entity finding atoms that may
            # contain sensitive org data; restrict to owner only. ``mkdir`` with
            # mode is advisory when the process umask masks some bits — on those
            # systems the effective permissions are already at least as tight.
            self.base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            lines = [
                json.dumps(atom.model_dump(), sort_keys=True, ensure_ascii=False) for atom in atoms
            ]
            with path.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except OSError:
            # A memory write failure must never crash a Run (RFC-0001 §Memory).
            return

    def _read_atoms(self, entity_type: str, entity_value: str) -> list[FindingAtom]:
        """Read an entity file into atoms; degrade to empty on any read failure."""
        path = self._path_for(entity_type, entity_value)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return []
        atoms: list[FindingAtom] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                atoms.append(FindingAtom.model_validate(json.loads(line)))
            except (json.JSONDecodeError, ValueError):
                # A corrupt line never crashes a Run — skip it and keep reading.
                continue
        return atoms


def _matchable_entities(entities: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Return ``(type, value)`` pairs for every matchable entity in ``entities``.

    Entity values are ``Any`` from the untrusted, schema-free payload; the rules:

    * **Scalar ``str``** — matched as-is when both name and value are non-empty.
    * **``list``** — each non-empty ``str`` item in the list yields a separate
      ``(name, item)`` pair; non-str items (ints, dicts, ``None``, …) are skipped.
    * **Everything else** (``dict``, ``int``, ``None``, …) — skipped entirely.

    An empty type/value would violate the atom's ``min_length=1`` and crash
    ``persist`` (a memory failure must never crash a Run), so empty strings are
    always excluded regardless of path.
    """
    result: list[tuple[str, str]] = []
    for name, value in entities.items():
        if not name:
            continue
        if isinstance(value, str):
            if value:
                result.append((name, value))
        elif isinstance(value, list):
            result.extend((name, item) for item in value if isinstance(item, str) and item)
    return result


def _atom_sort_key(atom: FindingAtom) -> tuple[str, str, str]:
    """Stable total order for a dossier — deterministic across reads."""
    return (atom.ts, atom.run_id, atom.statement)


def _ts_sort_key(ts: str) -> float:
    """Parse an ISO-8601 timestamp to a float for descending recency sort.

    Negated so that newer timestamps sort *first* inside a single
    ascending ``sorted()`` call.  Falls back to ``0.0`` (sorts last, i.e.
    treated as oldest) if the string cannot be parsed — a best-effort
    approach that keeps sorting total and crash-free on arbitrary strings
    from the untrusted payload (ADR-0005).
    """
    try:
        return -datetime.fromisoformat(ts).timestamp()
    except (ValueError, OSError):
        return 0.0


def _recall_sort_key(atom: FindingAtom) -> tuple[float, float, str, str]:
    """Confidence-desc, then recency-desc (newest first), then identity.

    The docstring previously stated "confidence-desc, then recency" but
    ``atom.ts`` ascending made *older* atoms win ties.  Fixed: the
    timestamp is negated so that equal-confidence atoms are ranked newest
    first.  ``run_id`` and ``statement`` are final tie-breakers (ascending)
    to keep the order deterministic and total.
    """
    return (-atom.confidence, _ts_sort_key(atom.ts), atom.run_id, atom.statement)


def _to_recall_item(atom: FindingAtom) -> dict[str, Any]:
    """Shape one atom into the planner recall seam item (exactly three keys).

    ``content`` is untrusted context (ADR-0005); the planner labels and delimits
    it. ``run_id`` + ``confidence`` let the planner discount it — memory informs,
    never dictates.
    """
    content = f"[{atom.severity}] {atom.statement} (evidence: {atom.evidence})"
    return {"run_id": atom.run_id, "confidence": atom.confidence, "content": content}


def _to_posture_item(brief: str) -> dict[str, Any]:
    """Shape the L3 posture brief into a recall seam item (same three keys).

    ``run_id="posture-brief"`` identifies this as the org-level synthesis rather
    than an entity-scoped atom from a specific run. ``confidence=0.0`` signals the
    planner to treat this as low-certainty context — the brief aggregates many runs
    and is deliberately coarser than per-run atoms.
    """
    return {"run_id": "posture-brief", "confidence": 0.0, "content": brief}
