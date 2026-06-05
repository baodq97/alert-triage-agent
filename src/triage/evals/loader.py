"""Golden Case + Run-record loading (US-0003).

Two read seams the runner orchestrates over:

* ``load_case`` / ``load_cases`` parse ``evals/cases/*.yaml`` into ``GoldenCase``
  models (the declarative Tier-1 assertions + the tool-neutral ``reference``).
* ``load_run_record`` reads a finished Run's two artifacts off disk
  (``runs/<run_id>/result.json`` + ``journal.jsonl``) into a ``RunRecord`` — the
  exact shape the pure assertion engine scores and an external adapter rebuilds.

Both convert IO/parse faults to ``ConfigError`` (the cases are operator-authored
config; a malformed one is a build-time fault, not a Run-time crash).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from triage.errors import ConfigError
from triage.evals.models import GoldenCase, RunRecord

if TYPE_CHECKING:
    from pathlib import Path

_CASE_GLOB = "*.yaml"


def load_case(path: Path) -> GoldenCase:
    """Load and validate one Golden Case YAML file.

    Raises:
        ConfigError: The file is missing, not valid YAML, or does not match the
            Golden Case schema.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"golden case not found or unreadable: {path}"
        raise ConfigError(msg) from exc
    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"golden case is not valid YAML: {path}"
        raise ConfigError(msg) from exc
    expect = document.pop("expect", {}) if isinstance(document, dict) else {}
    if not isinstance(document, dict):
        msg = f"golden case must be a mapping at the top level: {path}"
        raise ConfigError(msg)
    merged = {**document, **(expect if isinstance(expect, dict) else {})}
    try:
        return GoldenCase.model_validate(merged)
    except ValidationError as exc:
        msg = f"golden case does not match the schema: {path}\n{exc}"
        raise ConfigError(msg) from exc


def load_cases(directory: Path) -> list[GoldenCase]:
    """Load every ``*.yaml`` Golden Case in ``directory``, sorted by file name.

    Raises:
        ConfigError: The directory holds no cases, or any case fails to load.
    """
    paths = sorted(directory.glob(_CASE_GLOB))
    if not paths:
        msg = f"no golden cases found in {directory}"
        raise ConfigError(msg)
    return [load_case(path) for path in paths]


def load_run_record(run_dir: Path) -> RunRecord:
    """Load a finished Run's artifacts (``result.json`` + ``journal.jsonl``).

    This is the seam an external eval adapter uses too: hand it a ``runs/<run_id>``
    directory and it returns the same ``RunRecord`` the assertion engine scores —
    no import of ``src/triage`` beyond ``triage.models`` is needed to read these.

    Raises:
        ConfigError: A required artifact is missing or malformed.
    """
    result_path = run_dir / "result.json"
    journal_path = run_dir / "journal.jsonl"
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"run record result.json not found: {result_path}"
        raise ConfigError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"run record result.json is not valid JSON: {result_path}"
        raise ConfigError(msg) from exc
    journal = _read_journal(journal_path)
    return RunRecord(result=result, journal=journal)


def _read_journal(path: Path) -> list[dict[str, object]]:
    """Read a ``journal.jsonl`` into a list of event dicts (one per non-empty line).

    Raises:
        ConfigError: The file is missing or a line is not valid JSON.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"run journal not found: {path}"
        raise ConfigError(msg) from exc
    events: list[dict[str, object]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            events.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            msg = f"journal line {number} is not valid JSON: {path}"
            raise ConfigError(msg) from exc
    return events
