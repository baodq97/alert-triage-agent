"""The CLI adapter — the only transport binding for the wave-1 ``--alert`` path.

``run.py`` is an adapter, never the loop: it parses argv, loads ``.env``, builds
the leaf dependencies from the env contract (``OpenAICompatibleLLM`` over
``LLM_API_KEY`` / ``LLM_BASE_URL`` / ``LLM_MODEL``, the Fixture World source, the
interactive ``CLIGate``, ``NoopJournal`` for wave 1), reads the Alert JSON, calls
the transport-agnostic ``triage(alert, deps)``, prints a readable Verdict summary,
and persists the versioned run record at ``runs/<run_id>/result.json`` (gitignored).
Nothing in ``src/triage`` imports this file (triage-conventions §Module map).

Wave 1 ships only ``--alert``; ``--watch`` / ``--resume`` are later adapters.
``triage`` never crashes, so once a Run starts a Verdict always ships and the exit
code is ``0``. A configuration fault *before* the Run (e.g. a missing
``LLM_API_KEY`` when the LLM transport is built) surfaces as a ``TriageError``; the
adapter catches it, prints a clean one-line message to stderr, and exits non-zero —
the traceback path is reserved for genuine bugs (non-``TriageError``), which stay
loud.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from triage.core import TriageDeps, summarize, triage
from triage.errors import TriageError
from triage.gate import CLIGate, RiskPolicy
from triage.journal import NoopJournal
from triage.llm import OpenAICompatibleLLM
from triage.models import Alert, RunResult
from triage.tools import FixtureDataSource, ToolRegistry

_RUNS_DIR = Path(__file__).resolve().parent / "runs"


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse the CLI arguments — wave 1 exposes only ``--alert <file>``."""
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Triage one security alert JSON end-to-end and print the verdict.",
    )
    parser.add_argument(
        "--alert",
        required=True,
        type=Path,
        help="Path to the alert JSON file to investigate.",
    )
    return parser.parse_args(argv)


def _load_alert(path: Path) -> Alert:
    """Read and validate the Alert JSON at ``path`` (strict envelope)."""
    return Alert.model_validate_json(path.read_text(encoding="utf-8"))


def _persist(result: RunResult, runs_dir: Path) -> Path:
    """Write the versioned run record to ``runs/<run_id>/result.json``."""
    run_dir = runs_dir / result.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    record_path = run_dir / "result.json"
    record_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return record_path


def main(argv: list[str] | None = None, *, runs_dir: Path = _RUNS_DIR) -> int:
    """Run the ``--alert`` adapter end-to-end and return the process exit code.

    Args:
        argv: The CLI arguments (defaults to ``sys.argv[1:]``); injectable so the
            adapter test drives it directly.
        runs_dir: Where the run record is persisted; injectable so the test points
            it at a tmp dir instead of the repo's gitignored ``runs/``.

    Returns:
        ``0`` when a Verdict shipped (``triage`` never crashes once a Run starts);
        ``1`` when a ``TriageError`` (e.g. ``ConfigError`` from an unset
        ``LLM_API_KEY``) prevents the Run from starting — a clean one-line message
        is printed to stderr. A non-``TriageError`` (a genuine bug) is not caught
        and propagates as a traceback.
    """
    load_dotenv()
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    alert = _load_alert(args.alert)

    journal = NoopJournal()
    try:
        deps = TriageDeps(
            llm=OpenAICompatibleLLM(),
            journal=journal,
            registry=ToolRegistry(),
            source=FixtureDataSource(),
            gate=CLIGate(journal),
            policy=RiskPolicy(),
        )
        result = triage(alert, deps)
    except TriageError as exc:
        print(f"error: {exc}", file=sys.stderr)  # noqa: T201 — CLI adapter: stderr is the point.
        return 1

    record_path = _persist(result, runs_dir)
    print(summarize(result))  # noqa: T201 — CLI adapter: user-facing stdout is the point.
    print(f"\nRun record: {record_path}")  # noqa: T201 — CLI adapter output.
    return 0


if __name__ == "__main__":  # pragma: no cover  # CLI entrypoint guard — main() is tested directly.
    sys.exit(main())
