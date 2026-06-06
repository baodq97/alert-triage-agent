"""The Journal port and its no-op implementation (triage-conventions §Journal).

The Journal is the append-only, event-sourced record of one Run. Wave 1 lays the
seam — the executor, planner, and gate emit events from day one — and ships only
``NoopJournal``; wave 2 adds ``JsonlJournal`` behind the same ``Journal``
Protocol, so callers are never refactored.

``emit`` is the contract. The *implementation* owns ``seq`` (monotonic),
``event_id`` (uuid), and ``ts`` (ISO-8601) — callers never supply them, so they
cannot drift. Callers pass only the event name, its payload, and an optional
``agent`` override (``"triage"`` by default; ``"threat-intel"`` for the
delegated loop). One generic method, never per-event-type methods — mirroring
the "never branch on event_type" rule.

Wave 2 adds two reader-side seams on top of the same file (ADR-0003 — the journal
is the single runtime record, and Resume rebuilds state from it):

* **``rebuild``** reads a ``journal.jsonl`` into a typed ``ReconstructedRun`` — the
  ordered events plus the views Resume needs (alert id / config, the plan and its
  revisions, the completed Tool Steps with their Observations keyed by
  ``(step, attempt)``, gate request/decision state, executed / skipped / rejected
  Actions, the Verdict, the termination reason, and the last ``seq``).
* **Reopening** an existing run dir for Resume: ``JsonlJournal`` continues ``seq``
  strictly monotonic *after* the last recorded line. Because ``emit`` writes one
  flushed line per event, a clean process kill leaves complete lines; a torn
  in-flight last line (no trailing newline) is *physically truncated* on reopen
  before the first new append, so a resumed Run never concatenates a fresh event
  onto a partial one. Both reader paths share one ``_scan`` over the file.

**Torn-line crash contract (ADR-0003):** only a *trailing* line that fails to
parse is tolerated — it is the in-flight write a kill interrupted. A malformed
line anywhere *before* the end means a corrupted or hand-edited journal, which is
a ``JournalError`` (the audit record's integrity is broken, not merely truncated).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from triage.errors import JournalError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


@runtime_checkable
class Journal(Protocol):
    """Append-one-Journal-Event-per-call port consumed across the agent."""

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        """Append one Journal Event.

        Args:
            event: The event name (e.g. ``"run_started"``, ``"tool_called"``).
            payload: The event's payload fields, per the journal event schema.
            agent: Which loop emitted it — ``"triage"`` or ``"threat-intel"``.
        """
        ...  # pragma: no cover  # Protocol signature, never executed.


class NoopJournal:
    """A Journal that records nothing — the default seam for tests and CI."""

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        """Discard the event; the no-op keeps emit calls free of branching."""


class JsonlJournal:
    """The append-only JSONL ``Journal`` implementation (ADR-0003 / wave 2).

    One ``JsonlJournal`` records exactly one Run to ``<run_dir>/journal.jsonl``:
    one JSON object per line, append-only, never mutated. It is a **single-run,
    single-writer** instance — ADR-0003 grants the single-writer assumption (no
    concurrent runs on one ``run_id``).

    **Resume reopen (wave 2):** constructing a ``JsonlJournal`` on a run dir that
    already holds a ``journal.jsonl`` continues the same Run. ``seq`` resumes
    strictly monotonic after the last recorded event, and a torn in-flight final
    line (a write a process kill interrupted, leaving no trailing newline) is
    physically truncated before the first new append — so a resumed Run never
    concatenates a fresh event onto a partial one. A fresh run dir (no file) starts
    at ``seq`` 0 exactly as wave 1 did, so the ``--alert`` adapter is untouched.

    The implementation owns the three common fields callers never supply
    (triage-conventions §Journal event schema): ``seq`` (monotonic ``int`` from 1,
    held in memory), ``event_id`` (``uuid4``), and ``ts`` (ISO-8601 UTC). Each
    written line is the flat merge ``{seq, event_id, ts, event, agent, **payload}``
    — the payload fields live at the top level, never nested, because the core
    tests and the eval adapters read them there (e.g. ``run_started`` exposes
    ``schema_version`` directly).

    **Crash durability:** the file handle is opened once at construction and each
    ``emit`` writes one line then ``flush()``es it. A flush pushes the bytes into
    the OS page cache, so a killed process loses at most the *in-flight* line
    (ADR-0003: "a torn final JSONL line is discarded" on resume) — exactly the
    process-kill contract. ``fsync`` was considered and deliberately omitted: it
    only adds power-loss durability at a real per-line cost that would bite the
    long-running ``--watch`` adapter, and the stated contract is process-kill, not
    power-loss. Add ``fsync`` only if a future ADR raises the durability bar.

    Every IO fault (parent-dir creation, open, write/flush) converts to
    ``JournalError`` here — the typed-errors seam rule: the error is raised only
    inside the module that owns the failure.
    """

    def __init__(self, run_dir: Path) -> None:
        """Open ``<run_dir>/journal.jsonl`` for append, creating ``run_dir``.

        On a fresh run dir this starts ``seq`` at 0; on an existing journal it
        reopens for Resume — continuing ``seq`` after the last recorded event and
        truncating any torn in-flight final line first (see the class docstring).

        Args:
            run_dir: The Run's directory (``runs/<run_id>``); ``run.py`` composes
                it, mirroring how the run record is persisted alongside at
                ``<run_dir>/result.json``. The signature the Resume and watch
                adapters reuse — a path in, never a ``run_id`` string (the id is
                implicit in the path).

        Raises:
            JournalError: The directory could not be created, the journal file
                could not be opened (e.g. an unwritable path), or a non-trailing
                line of an existing journal is malformed (a corrupted record).
        """
        self._path = run_dir / "journal.jsonl"
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
            self._seq = self._prepare_for_append()
            self._handle = self._path.open("a", encoding="utf-8")
        except OSError as exc:
            msg = f"could not open journal at {self._path}: {exc}"
            raise JournalError(msg) from exc

    def _prepare_for_append(self) -> int:
        """Truncate a torn trailing line on an existing journal; return its last seq.

        Reads the file with the shared ``_scan`` (which enforces the torn-line
        crash contract: only a trailing parse failure is tolerated). When the
        scanned good content stops short of the file's end (a torn final line was
        present), the file is truncated to the last clean newline so the next
        ``emit`` appends a whole line rather than concatenating onto the partial
        one. A nonexistent file means a fresh Run — ``seq`` starts at 0.
        """
        if not self._path.exists():
            return 0
        scanned = _scan(self._path)
        if scanned.good_offset < scanned.size:
            with self._path.open("r+", encoding="utf-8") as handle:
                handle.truncate(scanned.good_offset)
        return scanned.last_seq

    def emit(
        self,
        event: str,
        payload: Mapping[str, Any],
        *,
        agent: str = "triage",
    ) -> None:
        """Append one Journal Event as a single flushed JSONL line.

        Merges the three implementation-owned common fields (``seq``, ``event_id``,
        ``ts``) with the caller's ``event``, ``agent``, and flat ``payload``, then
        writes one line and flushes it (process-kill durability).

        Raises:
            JournalError: The line could not be written or flushed.
        """
        self._seq += 1
        record: dict[str, Any] = {
            "seq": self._seq,
            "event_id": str(uuid.uuid4()),
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            "agent": agent,
            **payload,
        }
        try:
            self._handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._handle.flush()
        except (OSError, ValueError) as exc:
            # OSError: a real IO fault (disk full, broken pipe). ValueError: writing
            # to a journal whose handle was already closed — emitting on a finished
            # Run. Both convert to JournalError here, the typed-errors seam.
            msg = f"could not append event {event!r} to {self._path}: {exc}"
            raise JournalError(msg) from exc

    def close(self) -> None:
        """Close the underlying file handle (idempotent enough for one Run)."""
        self._handle.close()


# --- Resume rebuild --------------------------------------------------------- #


@dataclass(frozen=True)
class _ScanResult:
    """The shared scan of a ``journal.jsonl`` — events plus offset bookkeeping.

    ``good_offset`` is the byte offset just past the last cleanly-terminated line
    that parsed; ``size`` is the file's total byte length. ``good_offset < size``
    means a torn (or trailing-unparseable) final line was present and skipped —
    the only tolerated malformation (the process-kill crash contract). ``events``
    are the parsed event dicts in file order; ``last_seq`` is the highest ``seq``
    seen (0 for an empty journal).
    """

    events: list[dict[str, Any]]
    good_offset: int
    size: int
    last_seq: int


def _scan(path: Path) -> _ScanResult:
    """Read ``path`` line by line, enforcing the torn-line crash contract.

    Every line *except possibly the last* must parse as a JSON object; a malformed
    non-trailing line is a corrupted journal -> ``JournalError``. A malformed or
    missing-newline trailing line is the in-flight write a kill interrupted: it is
    skipped, and ``good_offset`` is left at the end of the last clean line so a
    reopen can truncate the partial bytes.

    Raises:
        JournalError: A non-trailing line is not a JSON object, or the file could
            not be read.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"could not read journal at {path}: {exc}"
        raise JournalError(msg) from exc
    size = len(raw.encode("utf-8"))
    # ``splitlines(keepends=True)`` preserves the trailing "\n" so a line without
    # one is identifiable as the torn final write.
    lines = raw.splitlines(keepends=True)
    events: list[dict[str, Any]] = []
    good_offset = 0
    last_seq = 0
    for index, line in enumerate(lines):
        is_last = index == len(lines) - 1
        stripped = line.strip()
        if not stripped:
            # A blank line: tolerated only as the trailing remnant, never mid-file.
            if is_last:
                break
            msg = f"blank line at position {index} in journal {path}"
            raise JournalError(msg)
        parsed = _parse_line(stripped, path, index=index, is_last=is_last)
        if parsed is None:  # torn trailing line — stop without advancing the offset.
            break
        events.append(parsed)
        good_offset += len(line.encode("utf-8"))
        seq = parsed.get("seq")
        if isinstance(seq, int):
            last_seq = max(last_seq, seq)
    return _ScanResult(events=events, good_offset=good_offset, size=size, last_seq=last_seq)


def _parse_line(
    text: str,
    path: Path,
    *,
    index: int,
    is_last: bool,
) -> dict[str, Any] | None:
    """Parse one journal line into an event dict, honouring the crash contract.

    Returns the parsed object, or ``None`` for a tolerated torn trailing line.

    Raises:
        JournalError: A non-trailing line is malformed, or any line parses to a
            non-object — both are corruption, not the in-flight-write contract.
    """
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        if is_last:
            return None  # the in-flight write a process kill interrupted.
        msg = f"malformed (non-trailing) line at position {index} in journal {path}: {exc}"
        raise JournalError(msg) from exc
    if not isinstance(parsed, dict):
        msg = f"journal line at position {index} is not a JSON object: {path}"
        raise JournalError(msg)
    return parsed


@dataclass(frozen=True)
class StepObservation:
    """One completed Tool Step's recorded Observation, keyed by ``(step, attempt)``.

    Rebuilt from a ``tool_called`` -> ``tool_result`` pair sharing ``step`` +
    ``attempt`` (triage-conventions: the pair is reconstructable without positional
    inference). ``ok`` plus ``data``/``error`` mirror the ``tool_result`` payload —
    Resume reuses these so a completed Tool Step is *never* re-executed.
    """

    step: int
    attempt: int
    tool: str
    args: dict[str, Any]
    ok: bool
    data: dict[str, Any] | None = None
    error: str | None = None


@dataclass(frozen=True)
class ActionRecord:
    """One recorded Action outcome — executed, skipped, or pre-gate rejected.

    ``kind`` is the journal event name (``action_executed`` | ``action_skipped`` |
    ``action_rejected``) so a consumer tells the three apart without string-matching
    a free-text reason. ``result`` is set only for an executed Action (the recorded
    mock result Resume reuses for idempotency); ``reason`` only for skipped/rejected.
    """

    kind: str
    action: dict[str, Any]
    result: dict[str, Any] | None = None
    reason: str | None = None


@dataclass
class ReconstructedRun:
    """The typed state rebuilt from a ``journal.jsonl`` for Resume / eval reads.

    A read-only projection of the event stream (ADR-0003): every field is derived
    deterministically from the recorded events, never re-inferred. Views Resume and
    the eval adapters depend on:

    * ``events`` — the ordered event dicts (the raw audit trail).
    * ``alert_id`` / ``config`` / ``schema_version`` — from ``run_started``.
    * ``plan_steps`` — the initial plan's steps; ``plan_revisions`` — each
      ``plan_revised``'s steps in order.  When non-empty, Resume rebuilds pending
      from the last revision's steps indexed by the steps executed after that
      revision (see ``core.resume_investigation``).
    * ``steps_after_last_revision`` — the number of completed Tool Steps (i.e.
      ``tool_result`` events) recorded *strictly after* the last ``plan_revised``
      event.  Zero when no revision was recorded (the linear case).  Resume uses
      this instead of the broken ``steps_executed - n_revisions`` arithmetic, which
      fails when a single revision fires at step ≥2.
    * ``observations`` — completed Tool Steps as ``StepObservation`` (one per
      ``tool_result``), so a resumed Run reuses them instead of re-executing.
    * ``llm_purposes`` — the ``purpose`` of each ``llm_call`` in order (audit; the
      reasoner *decision* is not recorded, so it is re-run on resume — see core).
    * ``gate_requested`` / ``gate_decision`` — the pending-gate state.
    * ``actions`` — executed / skipped / rejected Action records.
    * ``verdict`` — the full recorded Verdict object, if one shipped.
    * ``terminated_reason`` — from ``run_terminated`` (``None`` if the Run was
      killed before terminating — the interrupted-investigation case).
    * ``last_seq`` — the highest recorded ``seq`` (0 for an empty journal).
    """

    events: list[dict[str, Any]] = field(default_factory=list)
    alert_id: str | None = None
    config: dict[str, Any] | None = None
    schema_version: int | None = None
    plan_steps: list[dict[str, Any]] = field(default_factory=list)
    plan_revisions: list[list[dict[str, Any]]] = field(default_factory=list)
    steps_after_last_revision: int = 0
    observations: list[StepObservation] = field(default_factory=list)
    llm_purposes: list[str] = field(default_factory=list)
    gate_requested: dict[str, Any] | None = None
    gate_decision: dict[str, Any] | None = None
    actions: list[ActionRecord] = field(default_factory=list)
    verdict: dict[str, Any] | None = None
    terminated_reason: str | None = None
    last_seq: int = 0

    def executed_actions(self) -> list[ActionRecord]:
        """Return only the ``action_executed`` records (idempotency reuse source)."""
        return [a for a in self.actions if a.kind == "action_executed"]

    def is_awaiting_approval(self) -> bool:
        """Whether the Run parked at the gate (terminated reason ``awaiting_approval``)."""
        return self.terminated_reason == "awaiting_approval"

    def is_interrupted(self) -> bool:
        """Whether the Run was killed mid-investigation (no ``run_terminated`` recorded)."""
        return self.terminated_reason is None


def rebuild(path: Path) -> ReconstructedRun:
    """Reconstruct typed Run state from the ``journal.jsonl`` at ``path``.

    Reads every event in order (tolerating only a torn trailing line per the crash
    contract) and folds it into a ``ReconstructedRun``. Pure read — never writes.

    Raises:
        JournalError: The file is missing, unreadable, or a non-trailing line is
            malformed (a corrupted journal — distinct from the tolerated torn tail).
    """
    if not path.exists():
        msg = f"cannot rebuild — no journal at {path}"
        raise JournalError(msg)
    scanned = _scan(path)
    builder = _RunBuilder()
    for event in scanned.events:
        builder.fold(event)
    return builder.finish(events=scanned.events, last_seq=scanned.last_seq)


class _RunBuilder:
    """The rebuild reducer — folds events into a ``ReconstructedRun`` one at a time.

    A small per-event-name handler table keeps the dispatch flat (no long
    ``if/elif`` chain). ``_pending_calls`` pairs a ``tool_called`` with its matching
    ``tool_result`` by the shared ``(step, attempt)`` key — a Tool Step counts as
    completed (and a ``StepObservation`` recorded) only when its *result* event is
    seen (ADR-0003: a step is completed only when its result event is written).
    """

    def __init__(self) -> None:
        self._run = ReconstructedRun()
        self._pending_calls: dict[tuple[int, int], dict[str, Any]] = {}
        # Track whether a plan_revised has been seen, so tool_result events after
        # the last revision can be counted for steps_after_last_revision.
        self._saw_revision: bool = False
        # Track which step numbers were already counted after the last revision so
        # that a transient retry (two tool_result events sharing the same step) is
        # counted as ONE step, matching the by_step dedup in core.resume_investigation.
        self._counted_steps_after_revision: set[int] = set()
        self._handlers: dict[str, Any] = {
            "run_started": self._on_run_started,
            "plan_created": self._on_plan_created,
            "plan_revised": self._on_plan_revised,
            "llm_call": self._on_llm_call,
            "tool_called": self._on_tool_called,
            "tool_result": self._on_tool_result,
            "gate_requested": self._on_gate_requested,
            "gate_decision": self._on_gate_decision,
            "action_executed": self._on_action,
            "action_skipped": self._on_action,
            "action_rejected": self._on_action,
            "verdict": self._on_verdict,
            "run_terminated": self._on_run_terminated,
        }

    def fold(self, event: dict[str, Any]) -> None:
        """Dispatch one event to its handler; unknown names contribute no view.

        Forward compatibility: a future event type is still kept in ``events`` (the
        raw audit trail) but folds into no view, so rebuild of older fields holds.
        """
        handler = self._handlers.get(str(event.get("event")))
        if handler is not None:
            handler(event)

    def finish(self, *, events: list[dict[str, Any]], last_seq: int) -> ReconstructedRun:
        """Attach the raw event list and ``last_seq``, returning the built state."""
        self._run.events = events
        self._run.last_seq = last_seq
        return self._run

    def _on_run_started(self, event: dict[str, Any]) -> None:
        self._run.alert_id = event.get("alert_id")
        self._run.config = event.get("config")
        self._run.schema_version = event.get("schema_version")

    def _on_plan_created(self, event: dict[str, Any]) -> None:
        self._run.plan_steps = list(event.get("steps", []))

    def _on_plan_revised(self, event: dict[str, Any]) -> None:
        self._run.plan_revisions.append(list(event.get("steps", [])))
        # Reset the counter each time a new revision fires so that
        # steps_after_last_revision always reflects the LAST revision only.
        self._saw_revision = True
        self._run.steps_after_last_revision = 0
        self._counted_steps_after_revision = set()

    def _on_llm_call(self, event: dict[str, Any]) -> None:
        purpose = event.get("purpose")
        if isinstance(purpose, str):
            self._run.llm_purposes.append(purpose)

    def _on_tool_called(self, event: dict[str, Any]) -> None:
        self._pending_calls[(event.get("step", 0), event.get("attempt", 0))] = event

    def _on_tool_result(self, event: dict[str, Any]) -> None:
        _record_observation(self._run, event, self._pending_calls)
        if self._saw_revision:
            step = int(event.get("step", 0))
            if step not in self._counted_steps_after_revision:
                self._counted_steps_after_revision.add(step)
                self._run.steps_after_last_revision += 1

    def _on_gate_requested(self, event: dict[str, Any]) -> None:
        self._run.gate_requested = event

    def _on_gate_decision(self, event: dict[str, Any]) -> None:
        self._run.gate_decision = event

    def _on_action(self, event: dict[str, Any]) -> None:
        self._run.actions.append(
            ActionRecord(
                kind=str(event.get("event")),
                action=event.get("action", {}),
                result=event.get("result"),
                reason=event.get("reason"),
            ),
        )

    def _on_verdict(self, event: dict[str, Any]) -> None:
        self._run.verdict = event.get("verdict")

    def _on_run_terminated(self, event: dict[str, Any]) -> None:
        self._run.terminated_reason = event.get("reason")


def _record_observation(
    run: ReconstructedRun,
    result: dict[str, Any],
    pending_calls: dict[tuple[int, int], dict[str, Any]],
) -> None:
    """Pair a ``tool_result`` with its ``tool_called`` into a ``StepObservation``."""
    step = result.get("step", 0)
    attempt = result.get("attempt", 0)
    called = pending_calls.pop((step, attempt), {})
    run.observations.append(
        StepObservation(
            step=step,
            attempt=attempt,
            tool=called.get("tool", ""),
            args=dict(called.get("args", {})),
            ok=bool(result.get("ok")),
            data=result.get("data"),
            error=result.get("error"),
        ),
    )
