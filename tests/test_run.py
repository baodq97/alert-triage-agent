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
from typing import TYPE_CHECKING

from triage.errors import ConfigError
from triage.llm import FakeLLM

if TYPE_CHECKING:
    import pytest

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
