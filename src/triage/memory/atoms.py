"""The L1 Finding Atom — an entity-keyed fact distilled from a Verdict.

A Finding Atom is the atomic unit of memory (RFC-0001 §Memory): one
``(entity, finding)`` association persisted at verdict time. Atoms are strict and
closed so their key set is a stable contract — recall, dossiers, and the
schema-stability test all pin exactly these keys.

The model defines its own strict base rather than importing ``models._Strict``:
that symbol is private and ``models.py`` is owned by another seam. Duplicating the
two-line ``ConfigDict`` keeps the memory package a standalone leaf.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field

# Runtime import: Pydantic resolves the field annotation at model-build time, so
# ``Severity`` cannot live in a TYPE_CHECKING block (TC001 false positive here).
from triage.models import Severity  # noqa: TC001


class _StrictBase(BaseModel):
    """Strict, closed base — no coercion, no unexpected fields (mirrors ADR-0004)."""

    model_config = ConfigDict(strict=True, extra="forbid")


def atom_id_for(
    *,
    run_id: str,
    entity_type: str,
    entity_value: str,
    statement: str,
    evidence: str,
) -> str:
    """Deterministic id over the atom's identity fields.

    Stable across re-persists of the same ``(run, entity, finding)`` so a resumed
    or replayed run that re-persists does not duplicate the atom (dedupe on read).
    """
    raw = f"{run_id}\x00{entity_type}\x00{entity_value}\x00{statement}\x00{evidence}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FindingAtom(_StrictBase):
    """One entity-keyed fact derived from a Verdict's Finding.

    ``ts`` is the *alert* timestamp, never a wall clock: recall content feeds the
    planner prompt and therefore ``prompt_hash`` / the Replay Mode key, so the
    atom must be byte-identical for identical inputs.
    """

    atom_id: str = Field(min_length=1)
    entity_type: str = Field(min_length=1)
    entity_value: str = Field(min_length=1)
    statement: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    run_id: str = Field(min_length=1)
    ts: str = Field(min_length=1)
