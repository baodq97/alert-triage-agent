"""Tests for the CLI adapter — ``run.py`` ``main()`` (the ``--alert`` path).

The adapter is driven directly through ``main(argv, runs_dir=...)`` — never a
subprocess — so the run record lands in a tmp dir, stdin is monkeypatched for the
interactive ``CLIGate``, and the env / LLM transport are stubbed (Tier A: no key,
no network). The ``OpenAICompatibleLLM`` the adapter builds from env is swapped
for a ``FakeLLM`` via the module attribute, keeping the loop deterministic while
still exercising the real wiring (argparse, dotenv, alert load, persist, summary).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from triage.core import TriageDeps, triage
from triage.errors import ConfigError
from triage.gate import DeferredGate, RiskPolicy
from triage.journal import JsonlJournal
from triage.llm import FakeLLM
from triage.memory import MemoryStore
from triage.models import Alert
from triage.tools import FixtureDataSource, ToolRegistry

# ``run.py`` lives at the repo root, outside the ``triage`` package, so it is not
# importable by name from the package src layout. Load it by path — this keeps the
# adapter test self-contained (no new conftest / pyproject pythonpath needed).
_RUN_PATH = Path(__file__).resolve().parents[1] / "run.py"
_spec = importlib.util.spec_from_file_location("run", _RUN_PATH)
assert _spec is not None
assert _spec.loader is not None  # ty: loader is Optional on the spec.
run_module = importlib.util.module_from_spec(_spec)
sys.modules["run"] = run_module
_spec.loader.exec_module(run_module)


@pytest.fixture(autouse=True)
def _isolate_memory_dir(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Point ``MEMORY_DIR`` at a throwaway dir for every adapter test.

    ``run.py`` now wires an env-driven ``MemoryStore()`` into ``TriageDeps``, so a
    fresh ``--alert`` Run (and a resumed investigation) persists atoms. Without this
    the writes would land in the repo's default ``.memory/`` and dirty the working
    tree — this keeps the adapter tests hermetic.
    """
    mem = tmp_path_factory.mktemp("memory")
    monkeypatch.setenv("MEMORY_DIR", str(mem))


def _script() -> list[str]:
    plan = json.dumps(
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "svc-deploy-prod"}, "rationale": "x"},
            ],
        },
    )
    conclude = json.dumps({"decision": "conclude", "rationale": "done"})
    verdict = json.dumps(
        {
            "severity": "high",
            "findings": [{"statement": "s", "evidence": "lookup_user"}],
            "recommended_actions": [],
            "confidence": 0.7,
        },
    )
    return [plan, conclude, verdict]


def _write_alert(tmp_path: Path) -> Path:
    alert = {
        "alert_id": "ALT-RUN-1",
        "timestamp": "2026-06-05T00:00:00Z",
        "source": "edr",
        "severity_hint": "high",
        "event_type": "data_exfiltration",
        "description": "exfil from svc-deploy-prod",
        "entities": {"service_account": "svc-deploy-prod"},
        "context": {},
    }
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(alert), encoding="utf-8")
    return path


def test_main_runs_alert_persists_record_and_prints_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alert_path = _write_alert(tmp_path)
    runs_dir = tmp_path / "runs"
    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM(_script()))

    exit_code = run_module.main(["--alert", str(alert_path)], runs_dir=runs_dir)

    assert exit_code == 0
    # Exactly one run dir, with a parseable versioned run record.
    run_dirs = list(runs_dir.iterdir())
    assert len(run_dirs) == 1
    record = json.loads((run_dirs[0] / "result.json").read_text(encoding="utf-8"))
    assert record["verdict"]["severity"] == "high"
    assert record["terminated_reason"] == "completed"
    # Wave 2: the JsonlJournal writes journal.jsonl next to result.json in the
    # SAME run dir — the adapter mints one run_id for both. flush-per-line means
    # the file is readable even though the adapter never closes the handle.
    journal_path = run_dirs[0] / "journal.jsonl"
    assert journal_path.exists()
    journal_events = [
        json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
    ]
    assert journal_events[0]["event"] == "run_started"
    assert journal_events[-1]["event"] == "run_terminated"
    # The summary was printed to stdout.
    out = capsys.readouterr().out
    assert "Severity:" in out
    assert "Run record:" in out


def test_main_reads_argv_from_sys_when_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alert_path = _write_alert(tmp_path)
    runs_dir = tmp_path / "runs"
    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM(_script()))
    monkeypatch.setattr(run_module.sys, "argv", ["run.py", "--alert", str(alert_path)])

    exit_code = run_module.main(runs_dir=runs_dir)

    assert exit_code == 0
    assert len(list(runs_dir.iterdir())) == 1


def test_main_prints_clean_error_and_nonzero_exit_on_config_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A missing LLM_API_KEY surfaces as ConfigError when the adapter builds the LLM.
    # main() must catch the TriageError, print a clean one-line message to stderr,
    # and return a nonzero exit code — not dump a raw traceback.
    alert_path = _write_alert(tmp_path)
    runs_dir = tmp_path / "runs"

    def _raise() -> object:
        msg = "LLM_API_KEY is not set"
        raise ConfigError(msg)

    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", _raise)

    exit_code = run_module.main(["--alert", str(alert_path)], runs_dir=runs_dir)

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "LLM_API_KEY is not set" in captured.err
    # One clean line, no traceback marker, nothing on stdout, no run record written.
    assert "Traceback" not in captured.err
    assert captured.out == ""
    assert not runs_dir.exists()


# --- wave 2: --resume adapter path -------------------------------------------


def _block_alice() -> dict[str, object]:
    return {"name": "block_user", "params": {"user": "svc-deploy-prod"}, "description": "block"}


def _high_risk_verdict() -> str:
    return json.dumps(
        {
            "severity": "high",
            "findings": [
                {
                    "statement": "anomaly detected for svc-deploy-prod",
                    "evidence": "lookup_user confirmed svc-deploy-prod",
                }
            ],
            "recommended_actions": [_block_alice()],
            "confidence": 0.7,
        },
    )


def _resume_alert() -> Alert:
    return Alert.model_validate(
        {
            "alert_id": "ALT-RESUME",
            "timestamp": "2026-06-05T00:00:00Z",
            "source": "edr",
            "severity_hint": "high",
            "event_type": "data_exfiltration",
            "description": "exfil",
            "entities": {"service_account": "svc-deploy-prod"},
            "context": {},
        },
    )


def _park_run_via_adapter(run_id: str, runs_dir: Path) -> None:
    """Build a parked (awaiting_approval) Run on disk using core + a DeferredGate.

    The adapter's fresh path uses the interactive CLIGate, so a parked Run is staged
    here through core directly, then the adapter's --resume path completes it.
    """
    plan = json.dumps(
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "svc-deploy-prod"}, "rationale": "x"}
            ]
        },
    )
    conclude = json.dumps({"decision": "conclude", "rationale": "done"})
    journal = JsonlJournal(runs_dir / run_id)
    deps = TriageDeps(
        llm=FakeLLM([plan, conclude, _high_risk_verdict()]),
        journal=journal,
        registry=ToolRegistry(),
        source=FixtureDataSource(),
        gate=DeferredGate(journal),
        policy=RiskPolicy(),
    )
    result = triage(_resume_alert(), deps, run_id=run_id)
    journal.close()
    assert result.terminated_reason == "awaiting_approval"


def test_main_resume_approve_completes_a_pending_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runs_dir = tmp_path / "runs"
    run_id = "run-adapter-approve"
    _park_run_via_adapter(run_id, runs_dir)
    # The resume LLM build is swapped; the decision path makes no LLM call anyway.
    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM([]))

    exit_code = run_module.main(["--resume", run_id, "--approve"], runs_dir=runs_dir)

    assert exit_code == 0
    events = [
        json.loads(line)
        for line in (runs_dir / run_id / "journal.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    names = [e["event"] for e in events]
    assert names.count("gate_decision") == 1
    assert names.count("action_executed") == 1
    assert names[-1] == "run_terminated"
    record = json.loads((runs_dir / run_id / "result.json").read_text(encoding="utf-8"))
    assert record["terminated_reason"] == "completed"
    assert "Executed actions: ['block_user']" in capsys.readouterr().out


def test_main_resume_deny_records_and_concludes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs_dir = tmp_path / "runs"
    run_id = "run-adapter-deny"
    _park_run_via_adapter(run_id, runs_dir)
    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM([]))

    exit_code = run_module.main(["--resume", run_id, "--deny"], runs_dir=runs_dir)

    assert exit_code == 0
    record = json.loads((runs_dir / run_id / "result.json").read_text(encoding="utf-8"))
    assert record["gate_decisions"][0]["decision"] == "denied"
    assert record["executed_actions"] == []


def test_main_resume_investigation_reads_alert_json_and_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fresh --alert path persists alert.json at run start; here we stage an
    # interrupted journal + alert.json, then resume the investigation (re-reads it).
    runs_dir = tmp_path / "runs"
    run_id = "run-adapter-invest"
    run_dir = runs_dir / run_id
    journal = JsonlJournal(run_dir)
    journal.emit("run_started", {"alert_id": "ALT-RESUME", "config": {}, "schema_version": 1})
    journal.emit("plan_created", {"steps": [{"tool": "lookup_user", "args": {}, "rationale": "a"}]})
    journal.emit("tool_called", {"step": 1, "tool": "lookup_user", "args": {}, "attempt": 1})
    journal.emit("tool_result", {"step": 1, "attempt": 1, "ok": True, "data": {"ok": 1}})
    journal.close()
    (run_dir / "alert.json").write_text(_resume_alert().model_dump_json(), encoding="utf-8")

    conclude = json.dumps({"decision": "conclude", "rationale": "done"})
    verdict = json.dumps(
        {
            "severity": "low",
            "findings": [{"statement": "s", "evidence": "lookup_user"}],
            "recommended_actions": [],
            "confidence": 0.5,
        },
    )
    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM([conclude, verdict]))

    exit_code = run_module.main(["--resume", run_id], runs_dir=runs_dir)

    assert exit_code == 0
    record = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    assert record["terminated_reason"] == "completed"


def test_main_resume_approve_on_non_pending_run_errors_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # --approve on a completed Run is a misuse: a clean stderr error, nonzero exit,
    # no result.json written.
    alert_path = _write_alert(tmp_path)
    runs_dir = tmp_path / "runs"
    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM(_script()))
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")  # CLIGate denies, run completes
    assert run_module.main(["--alert", str(alert_path)], runs_dir=runs_dir) == 0
    run_id = next(p.name for p in runs_dir.iterdir())

    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM([]))
    exit_code = run_module.main(["--resume", run_id, "--approve"], runs_dir=runs_dir)

    assert exit_code == 1
    assert "not awaiting approval" in capsys.readouterr().err


# --- memory wiring: the adapter builds an env-driven Memory Store -------------


def test_deps_wires_an_env_driven_memory_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # _deps must attach a MemoryStore bound to the env MEMORY_DIR on BOTH paths.
    mem_dir = tmp_path / "mem"
    monkeypatch.setenv("MEMORY_DIR", str(mem_dir))
    journal = JsonlJournal(tmp_path / "runs" / "wire")

    for interactive in (True, False):
        deps = run_module._deps(FakeLLM([]), journal, interactive=interactive)  # noqa: SLF001 — adapter internal under test
        assert isinstance(deps.memory, MemoryStore)
        assert deps.memory.base_dir == mem_dir
    journal.close()


def test_main_alert_path_persists_atoms_into_memory_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fresh --alert path recalls + persists through the wired Memory Store: after a
    # Run whose verdict carries a finding for entity service_account=svc-deploy-prod,
    # recall over the same alert returns the persisted atom from the env MEMORY_DIR.
    mem_dir = tmp_path / "mem"
    monkeypatch.setenv("MEMORY_DIR", str(mem_dir))
    alert_path = _write_alert(tmp_path)
    runs_dir = tmp_path / "runs"
    monkeypatch.setattr(run_module, "OpenAICompatibleLLM", lambda: FakeLLM(_script()))

    assert run_module.main(["--alert", str(alert_path)], runs_dir=runs_dir) == 0

    recalled = MemoryStore(base_dir=mem_dir).recall(_resume_alert())
    assert recalled  # an atom was persisted at verdict time and is recallable
