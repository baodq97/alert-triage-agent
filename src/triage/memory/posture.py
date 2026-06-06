"""L3 Threat Posture — org-level synthesis over the memory store (RFC-0001 §Memory).

The L3 brief is an org-level summary synthesised over **all** L1 finding atoms in
the store.  It is the only memory level that is *not* entity-scoped: one brief per
org, regenerated on a configured cadence or on demand.

Storage: ``.memory/posture.md`` — a plain-text markdown file written atomically
under the configured base dir.  No wall-clock timestamps inside the brief content:
ordering keys are derived from atom ``ts`` values (which are the alert timestamp
from the untrusted payload — deterministic and replay-safe).

**Degradable to deterministic (RFC-0001):** with an LLM available the synthesis
*may* call one; the deterministic fallback (``synthesize_deterministic``) is a
top-N aggregation — most-seen entities, severity distribution, recent
high-confidence findings — implemented in pure Python with no LLM and no wall-clock
output, so it is replay-safe and can run key-free in tests and CI.

**Cadence and run counter:** a tiny counter file (``.memory/_run_count``) tracks
cumulative ``synthesize_posture_if_due`` calls.  The counter is a single decimal
integer, updated atomically (overwrite).  A write failure is swallowed — a memory
failure must never crash a Run.

**Recall integration:** ``MemoryStore.recall`` appends the posture brief as one
extra non-entity-scoped item *only when* ``.memory/posture.md`` exists.  When the
file is absent (the default state before the first synthesis), recall is identical
to pre-L3 behavior — the 34 existing replay caches remain valid.

Leaf module: nothing here imports from ``core``, ``executor``, ``journal``, or any
other non-leaf module (triage-conventions dependency direction).
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from triage.errors import LLMError
from triage.memory.atoms import FindingAtom

if TYPE_CHECKING:
    from triage.llm import LLM, Message

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

POSTURE_CHAR_CAP: int = 1200
"""Maximum character length of the posture brief exposed to the planner.

~10 lines at 120 chars each.  Both ``write`` (content passed in is already bounded
by the synthesiser) and ``load_posture_brief`` (truncates file content) enforce this
cap so the brief never inflates the planner prompt beyond budget.
"""

_POSTURE_FILENAME = "posture.md"
_COUNTER_FILENAME = "_run_count"
_TOP_ENTITIES = 5  # top-N entities by atom count included in the brief
_TOP_FINDINGS = 3  # top-N high-confidence findings included in the brief


# ---------------------------------------------------------------------------
# Prompt file for LLM synthesis
# ---------------------------------------------------------------------------

_POSTURE_PROMPT_PATH = Path(__file__).resolve().parents[3] / "prompts" / "posture.md"


# ---------------------------------------------------------------------------
# PostureSynthesizer
# ---------------------------------------------------------------------------


class PostureSynthesizer:
    """Synthesises and persists the L3 org-level threat posture brief.

    Args:
        base_dir: The memory store root (same dir ``MemoryStore`` uses).  Defaults
            to ``$MEMORY_DIR`` then ``.memory/``.
    """

    def __init__(self, base_dir: str | os.PathLike[str] | None = None) -> None:
        """Bind the memory store base dir (defaults to ``$MEMORY_DIR`` then ``.memory/``)."""
        if base_dir is None:
            base_dir = os.environ.get("MEMORY_DIR", ".memory")
        self.base_dir = Path(base_dir)

    # ------------------------------------------------------------------
    # Synthesis paths
    # ------------------------------------------------------------------

    def synthesize_deterministic(self) -> str:
        """Produce a posture brief using only pure Python — no LLM, no wall clock.

        Aggregates all atoms from the store into:
        * severity distribution counts;
        * top-N entities by atom count;
        * top-N high-confidence recent findings (ordered by atom ts desc, then
          confidence desc — both derived from atom data, never from time.time()).

        Returns an empty string when the store is empty; always bounded to
        :data:`POSTURE_CHAR_CAP`.
        """
        atoms = self._load_all_atoms()
        if not atoms:
            return ""

        severity_counts = _count_severities(atoms)
        top_entities = _top_entities(atoms, n=_TOP_ENTITIES)
        top_findings = _top_findings(atoms, n=_TOP_FINDINGS)

        lines: list[str] = ["# Org threat posture (deterministic summary)"]
        lines.append("")
        lines.append("## Severity distribution")
        for sev in ("critical", "high", "medium", "low"):
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"- {sev}: {count} atom(s)")

        lines.append("")
        lines.append("## Most-seen entities")
        lines.extend(f"- {entity_key}: {count} atom(s)" for entity_key, count in top_entities)

        lines.append("")
        lines.append("## Recent high-confidence findings")
        lines.extend(
            f"- [{atom.severity}|{atom.confidence:.2f}] {atom.statement}" for atom in top_findings
        )

        brief = "\n".join(lines)
        return brief[:POSTURE_CHAR_CAP]

    def synthesize_with_llm(self, llm: LLM) -> str:
        """Attempt LLM synthesis; fall back to deterministic on any LLM failure.

        The LLM is passed the deterministic summary as context inside the prompt
        template from ``prompts/posture.md``.  When the LLM call fails for any
        reason (``LLMError``, missing prompt file, etc.) the deterministic brief is
        returned — a memory failure must never crash a Run.
        """
        deterministic = self.synthesize_deterministic()
        try:
            template = _POSTURE_PROMPT_PATH.read_text(encoding="utf-8")
            rendered_prompt = template.replace("{{DETERMINISTIC_SUMMARY}}", deterministic)
            messages: list[Message] = [{"role": "user", "content": rendered_prompt}]
            completion = llm.complete(messages, _PostureBrief)  # type: ignore[arg-type]
            raw = completion.value.brief
            return raw[:POSTURE_CHAR_CAP]
        except (LLMError, OSError, AttributeError, TypeError):
            # Degrade gracefully: LLM unavailable, prompt file missing, or unexpected
            # output shape — return the deterministic brief (always valid).
            return deterministic

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def write(self, brief: str) -> None:
        """Write the brief to ``.memory/posture.md``, swallowing any I/O failure.

        Content is truncated to :data:`POSTURE_CHAR_CAP` before writing so the file
        is always bounded.  A write failure is logged silently — a memory failure
        must never crash a Run (RFC-0001 §Memory).
        """
        path = self.base_dir / _POSTURE_FILENAME
        try:
            # 0o700: memory dir contains sensitive org data; owner-only access.
            self.base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(brief[:POSTURE_CHAR_CAP], encoding="utf-8")
        except OSError:
            return  # A posture write failure must never crash a Run.

    # ------------------------------------------------------------------
    # Counter
    # ------------------------------------------------------------------

    def _read_counter(self) -> int:
        """Read the run counter from disk; return 0 if absent or unreadable."""
        path = self.base_dir / _COUNTER_FILENAME
        try:
            return int(path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return 0

    def _write_counter(self, value: int) -> None:
        """Overwrite the counter file; swallow any I/O failure."""
        path = self.base_dir / _COUNTER_FILENAME
        try:
            # 0o700: same memory dir; keep permissions consistent with _append.
            self.base_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text(str(value), encoding="utf-8")
        except OSError:
            return  # A counter write failure must never crash a Run.

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_all_atoms(self) -> list[FindingAtom]:
        """Read every ``*.jsonl`` atom file in the base dir (excluding meta files).

        Skips the counter file and any non-atom files.  A corrupt line or an
        unreadable file degrades to empty (never crashes).
        """
        atoms: list[FindingAtom] = []
        if not self.base_dir.exists():
            return []
        files = list(self.base_dir.glob("*.jsonl"))
        for path in files:
            try:
                raw = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for line in raw.splitlines():
                if not line.strip():
                    continue
                try:
                    atoms.append(FindingAtom.model_validate(json.loads(line)))
                except (json.JSONDecodeError, ValueError):
                    continue
        return atoms


# ---------------------------------------------------------------------------
# Cadence driver
# ---------------------------------------------------------------------------


def synthesize_posture_if_due(synth: PostureSynthesizer, *, cadence: int) -> None:
    """Increment the run counter and regenerate the brief when cadence is reached.

    Args:
        synth: The ``PostureSynthesizer`` bound to the memory store dir.
        cadence: How many runs between re-syntheses.  ``0`` disables synthesis
            entirely (``MEMORY_SYNTHESIZE_EVERY_N_RUNS=0``).

    Side-effects:
        * Always increments the counter file (even when cadence is 0) so that
          enabling cadence later starts counting from the correct base.
        * Writes ``.memory/posture.md`` when ``cadence > 0`` and
          ``new_count % cadence == 0``.
        * A counter or posture write failure is swallowed — never crashes a Run.
    """
    current = synth._read_counter()  # noqa: SLF001 — package-internal cohesion
    new_count = current + 1
    synth._write_counter(new_count)  # noqa: SLF001 — package-internal cohesion
    if cadence <= 0:
        return
    if new_count % cadence == 0:
        brief = synth.synthesize_deterministic()
        synth.write(brief)


# ---------------------------------------------------------------------------
# load_posture_brief — called by MemoryStore.recall
# ---------------------------------------------------------------------------


def load_posture_brief(base_dir: Path) -> str | None:
    """Return the posture brief text (bounded), or ``None`` if no file exists.

    This is the only function ``MemoryStore.recall`` needs: it reads the file
    written by :meth:`PostureSynthesizer.write` and caps it at
    :data:`POSTURE_CHAR_CAP`.  A missing file returns ``None`` (not an error);
    a read failure also returns ``None`` (best-effort, never crashes).

    Args:
        base_dir: The memory store root (same dir the synthesiser and store use).

    Returns:
        The bounded posture brief string, or ``None`` when no posture file exists
        or it cannot be read.
    """
    path = base_dir / _POSTURE_FILENAME
    try:
        content = path.read_text(encoding="utf-8")
        return content[:POSTURE_CHAR_CAP]
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Pydantic model for LLM structured output
# ---------------------------------------------------------------------------


class _PostureBrief(BaseModel):
    """Structured output schema for LLM posture synthesis.

    Defined here rather than in ``models.py`` so the posture module stays a
    self-contained leaf that does not pollute the main models namespace with an
    internal synthesis type.
    """

    brief: str = Field(description="The synthesised posture brief (plain text, max ~10 lines).")


# ---------------------------------------------------------------------------
# Private aggregation helpers (pure Python, no LLM, no wall clock)
# ---------------------------------------------------------------------------


def _count_severities(atoms: list[FindingAtom]) -> dict[str, int]:
    """Return a count map ``{severity_str: count}`` over all atoms."""
    counts: dict[str, int] = {}
    for atom in atoms:
        key = atom.severity if isinstance(atom.severity, str) else atom.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _top_entities(atoms: list[FindingAtom], *, n: int) -> list[tuple[str, int]]:
    """Return the ``n`` most-seen ``entity_type=entity_value`` keys, desc by count."""
    counts: dict[str, int] = {}
    for atom in atoms:
        key = f"{atom.entity_type}={atom.entity_value}"
        counts[key] = counts.get(key, 0) + 1
    # Sort desc by count, then alpha for determinism.
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ranked[:n]


def _top_findings(atoms: list[FindingAtom], *, n: int) -> list[FindingAtom]:
    """Return the ``n`` highest-confidence, most-recent unique findings.

    Ordering: confidence desc, then ``ts`` desc (newest alert timestamp first),
    then ``statement`` alpha for total determinism.  Deduped by statement so the
    same finding from multiple entities is shown only once.
    """
    seen_statements: set[str] = set()
    unique: list[FindingAtom] = []
    for atom in sorted(
        atoms,
        key=lambda a: (-a.confidence, _neg_ts(a.ts), a.statement),
    ):
        if atom.statement not in seen_statements:
            seen_statements.add(atom.statement)
            unique.append(atom)
        if len(unique) >= n:
            break
    return unique


def _neg_ts(ts: str) -> float:
    """Negate the parsed ISO-8601 timestamp for descending sort; 0.0 on parse failure."""
    try:
        return -datetime.fromisoformat(ts).timestamp()
    except (ValueError, OSError):
        return 0.0
