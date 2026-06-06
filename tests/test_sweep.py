"""Tests for the multi-model eval sweep (US-0009).

Every non-LLM seam is covered without a live client: the pure functions directly,
and the per-case / orchestration paths via injected ``FakeLLM`` factories and the
real ``run_case``.  No network, no key.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from triage.evals import sweep
from triage.evals.models import GoldenCase
from triage.llm import FakeLLM

if TYPE_CHECKING:
    from pathlib import Path

# --------------------------------------------------------------------------- #
# Fixtures: a minimal real golden case + a passing script                      #
# --------------------------------------------------------------------------- #


def _case(name: str = "sweep-fixture") -> GoldenCase:
    return GoldenCase.model_validate(
        {
            "name": name,
            "alert": "src/triage/evals/cases/alerts/benign.json",
            "verdict": {"severity_in": ["low", "medium", "high", "critical"]},
        }
    )


def _script() -> list[str]:
    plan = json.dumps(
        {
            "steps": [
                {"tool": "lookup_user", "args": {"entity": "dev-intern-jpark"}, "rationale": "x"}
            ]
        }
    )
    conclude = json.dumps({"decision": "conclude", "rationale": "enough"})
    verdict = json.dumps(
        {
            "severity": "low",
            "findings": [{"statement": "benign", "evidence": "lookup_user returned active user"}],
            "recommended_actions": [],
            "confidence": 0.35,
        }
    )
    return [plan, conclude, verdict]


# --------------------------------------------------------------------------- #
# load_env_file                                                                 #
# --------------------------------------------------------------------------- #


def test_load_env_file_sets_and_returns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = tmp_path / ".env.x"
    env.write_text("# comment\n\nLLM_MODEL=foo\nLLM_BASE_URL=http://x\nnoequalsline\n")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    applied = sweep.load_env_file(env)
    assert applied == {"LLM_MODEL": "foo", "LLM_BASE_URL": "http://x"}
    import os  # noqa: PLC0415

    assert os.environ["LLM_MODEL"] == "foo"


def test_load_env_file_prefix_map_renames(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = tmp_path / ".env.judge"
    # OTHER= does not match the prefix → loaded under its own name (loop exhausts).
    env.write_text("LLM_MODEL=judgemodel\nLLM_API_KEY=k\nOTHER=z\n")
    monkeypatch.delenv("JUDGE_MODEL", raising=False)
    monkeypatch.delenv("OTHER", raising=False)
    applied = sweep.load_env_file(env, prefix_map={"LLM_": "JUDGE_"})
    assert applied == {"JUDGE_MODEL": "judgemodel", "JUDGE_API_KEY": "k", "OTHER": "z"}


# --------------------------------------------------------------------------- #
# judge_overrides_present                                                       #
# --------------------------------------------------------------------------- #


def test_judge_overrides_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JUDGE_MODEL", raising=False)
    assert sweep.judge_overrides_present() is False
    monkeypatch.setenv("JUDGE_MODEL", "m")
    assert sweep.judge_overrides_present() is True


# --------------------------------------------------------------------------- #
# cache_destination                                                            #
# --------------------------------------------------------------------------- #


def test_cache_destination_scratch_vs_baseline(tmp_path: Path) -> None:
    yaml_path = tmp_path / "cases" / "c.yaml"
    out = tmp_path / "out"
    scratch = sweep.cache_destination("c", yaml_path, out, scratch=True)
    assert scratch == out / "c.replay.json"
    baseline = sweep.cache_destination("c", yaml_path, out, scratch=False)
    assert baseline == yaml_path.with_suffix(".replay.json")


# --------------------------------------------------------------------------- #
# throttle_remaining + _sleep                                                  #
# --------------------------------------------------------------------------- #


def test_throttle_remaining() -> None:
    assert sweep.throttle_remaining(5.0, 0.0) == 0.0  # disabled
    assert sweep.throttle_remaining(70.0, 60.0) == 0.0  # already long enough
    assert sweep.throttle_remaining(10.0, 60.0) == pytest.approx(50.0)


def test_sleep_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(sweep.time, "sleep", slept.append)
    sweep._sleep(0.0)  # noqa: SLF001
    sweep._sleep(1.5)  # noqa: SLF001
    assert slept == [1.5]


# --------------------------------------------------------------------------- #
# aggregate + SweepSummary                                                     #
# --------------------------------------------------------------------------- #


def _write_result(d: Path, name: str, **over: Any) -> None:
    payload = {
        "name": name,
        "pending": False,
        "wall_s": 10.0,
        "tier1": [{"name": "t", "passed": True, "detail": ""}],
        "judge": {"scored": True, "score": 80},
        "llm_calls": [{"purpose": "plan", "tokens": 100}],
    }
    payload.update(over)
    (d / f"{name}.json").write_text(json.dumps(payload))


def test_aggregate_skips_replay_and_counts_crash(tmp_path: Path) -> None:
    _write_result(tmp_path, "a")
    _write_result(tmp_path, "b", judge={"scored": True, "score": 90})
    (tmp_path / "c.json").write_text(json.dumps({"name": "c", "crashed": "boom"}))
    (tmp_path / "a.replay.json").write_text("{}")  # must be ignored
    summary = sweep.aggregate(tmp_path)
    assert summary.cases == 3  # a, b, c (not the replay file)
    assert summary.tier1_passed == 2
    assert summary.judge_mean == pytest.approx(85.0)
    assert summary.judge_min == 80
    assert summary.judge_stdev is not None


def test_aggregate_result_without_wall(tmp_path: Path) -> None:
    # A (non-crashed) result missing wall_s still aggregates — walls list stays empty.
    _write_result(tmp_path, "a", wall_s=None)
    summary = sweep.aggregate(tmp_path)
    assert summary.cases == 1
    assert summary.wall_per_case == 0.0


def test_aggregate_empty_dir(tmp_path: Path) -> None:
    summary = sweep.aggregate(tmp_path)
    assert summary.cases == 0
    assert summary.judge_mean is None
    assert summary.judge_stdev is None
    assert summary.wall_per_case == 0.0
    assert summary.tokens_per_case == 0


def test_summary_as_row_with_and_without_scores() -> None:
    full = sweep.SweepSummary(35, 35, 83.8, 3.1, 72, 12.0, 14800)
    row = full.as_row("gpt-5.4-mini")
    assert row == "| gpt-5.4-mini | 35/35 | 83.8 | 3.1 | 72 | 12.0s | 14800 |"
    bare = sweep.SweepSummary(1, 1, None, None, None, 0.0, 0)
    assert bare.as_row("m") == "| m | 1/1 | — | — | — | 0.0s | 0 |"


# --------------------------------------------------------------------------- #
# build_judge_llm                                                              #
# --------------------------------------------------------------------------- #


def test_build_judge_llm_no_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JUDGE_MODEL", raising=False)
    sentinel = object()
    monkeypatch.setattr(sweep, "_build_live_llm", lambda: sentinel)
    assert sweep.build_judge_llm() is sentinel


def test_build_judge_llm_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JUDGE_MODEL", "judge-x")
    monkeypatch.setenv("JUDGE_API_KEY", "k")
    monkeypatch.setenv("JUDGE_BASE_URL", "http://j")
    captured: dict[str, Any] = {}

    class _StubOpenAI:
        def __init__(self, *, api_key: str, base_url: str | None) -> None:
            captured["api_key"] = api_key
            captured["base_url"] = base_url

    class _StubLLM:
        def __init__(self, *, client: Any, model: str) -> None:
            captured["client_built"] = client is not None
            captured["model"] = model

    import openai  # noqa: PLC0415

    import triage.llm as llm_mod  # noqa: PLC0415

    monkeypatch.setattr(openai, "OpenAI", _StubOpenAI)
    monkeypatch.setattr(llm_mod, "OpenAICompatibleLLM", _StubLLM)
    sweep.build_judge_llm()
    assert captured == {
        "api_key": "k",
        "base_url": "http://j",
        "client_built": True,
        "model": "judge-x",
    }


# --------------------------------------------------------------------------- #
# run_case_to_disk                                                             #
# --------------------------------------------------------------------------- #


def _config(**over: Any) -> sweep.SweepConfig:
    """A SweepConfig wired to FakeLLM + real run_case, overridable per test."""
    base: dict[str, Any] = {
        "llm_factory": lambda: FakeLLM(_script()),
        "judge_factory": None,
        "case_runner": sweep.run_case,
        "scratch_caches": True,
    }
    base.update(over)
    return sweep.SweepConfig(**base)


def test_run_case_to_disk_success_with_judge(tmp_path: Path) -> None:
    case = _case()
    yaml_path = tmp_path / "cases" / "sweep-fixture.yaml"
    out = tmp_path / "out"
    out.mkdir()

    outcome = sweep.run_case_to_disk(
        case,
        yaml_path,
        out,
        _config(judge_factory=lambda: FakeLLM(["irrelevant"])),
    )
    # Judge is real here (samples=3) — just assert structure, not the score.
    assert outcome.name == "sweep-fixture"
    assert outcome.crashed is False
    assert outcome.tier1_passed is True
    assert (out / "sweep-fixture.json").exists()
    assert (out / "sweep-fixture.replay.json").exists()  # scratch cache stayed in out


def test_run_case_to_disk_no_judge(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    outcome = sweep.run_case_to_disk(_case(), tmp_path / "c.yaml", out, _config())
    assert outcome.judge_score is None
    data = json.loads((out / "sweep-fixture.json").read_text())
    assert data["judge"] is None


def test_run_case_to_disk_crash_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    slept: list[float] = []
    monkeypatch.setattr(sweep.time, "sleep", slept.append)

    def _boom(_case: Any, _llm: Any) -> Any:
        msg = "kaboom"
        raise RuntimeError(msg)

    outcome = sweep.run_case_to_disk(
        _case(),
        tmp_path / "c.yaml",
        out,
        _config(case_runner=_boom, min_case_seconds=30.0),  # throttle-after-crash path
    )
    assert outcome.crashed is True
    assert outcome.tier1_passed is False
    data = json.loads((out / "sweep-fixture.json").read_text())
    assert "kaboom" in data["crashed"]
    assert slept  # throttle slept after the crash
    assert slept[0] > 0


# --------------------------------------------------------------------------- #
# _atomic_write                                                                #
# --------------------------------------------------------------------------- #


def test_atomic_write_cleans_temp_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "x.json"
    monkeypatch.setattr(sweep.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError, match="disk"):
        sweep._atomic_write(dest, "data")  # noqa: SLF001
    # no leftover .tmp files
    assert not list(tmp_path.glob("*.tmp"))


# --------------------------------------------------------------------------- #
# run_sweep + _pairs_from_dirs + main                                          #
# --------------------------------------------------------------------------- #


def test_run_sweep_runs_skips_and_aggregates(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    # Pre-existing result → skipped (resume behavior).
    _write_result(out, "already")
    pairs = [(_case("sweep-fixture"), tmp_path / "sweep-fixture.yaml")]
    result = sweep.run_sweep(pairs, out, _config(), workers=1)
    names = {o.name for o in result.outcomes}
    assert names == {"sweep-fixture"}  # 'already' was skipped, not re-run
    assert result.all_passed is True
    assert result.summary.cases == 2  # aggregate reads both files in out


def test_run_sweep_all_passed_false_on_failure(tmp_path: Path) -> None:
    out = tmp_path / "out"
    # A non-pending case that fails Tier-1 (severity mismatch).
    bad = GoldenCase.model_validate(
        {
            "name": "sweep-fixture",
            "alert": "src/triage/evals/cases/alerts/benign.json",
            "verdict": {"severity_in": ["critical"]},  # script returns low → fail
        }
    )
    result = sweep.run_sweep([(bad, tmp_path / "c.yaml")], out, _config(), workers=1)
    assert result.all_passed is False


def test_pairs_from_dirs_sorted() -> None:
    pairs = sweep._pairs_from_dirs([str(sweep._CASES_DIR)])  # noqa: SLF001
    names = [c.name for c, _ in pairs]
    assert names == sorted(names)
    assert len(names) >= 35


def test_main_runs_with_env_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env = tmp_path / ".env.agent"
    env.write_text("LLM_MODEL=agent-x\n")
    judge_env = tmp_path / ".env.judge"
    judge_env.write_text("LLM_MODEL=judge-x\n")
    out = tmp_path / "out"

    monkeypatch.setattr(sweep, "_pairs_from_dirs", lambda _dirs: [(_case(), tmp_path / "c.yaml")])
    monkeypatch.setattr(sweep, "_build_live_llm", lambda: FakeLLM(_script()))

    code = sweep.main(
        [
            "--env-file",
            str(env),
            "--judge-env-file",
            str(judge_env),
            "--out",
            str(out),
            "--scratch-caches",
            "--no-judge",
            "--workers",
            "1",
        ]
    )
    assert code == 0
    captured = capsys.readouterr().out
    assert "agent model: agent-x  judge model: judge-x" in captured
    assert "| agent-x |" in captured  # the summary row printed


def test_main_without_env_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No --env-file / --judge-env-file: both load branches skipped, judge falls to agent model."""
    out = tmp_path / "out"
    monkeypatch.setenv("LLM_MODEL", "inherited-model")
    monkeypatch.delenv("JUDGE_MODEL", raising=False)
    monkeypatch.setattr(sweep, "_pairs_from_dirs", lambda _dirs: [(_case(), tmp_path / "c.yaml")])
    monkeypatch.setattr(sweep, "_build_live_llm", lambda: FakeLLM(_script()))

    code = sweep.main(["--out", str(out), "--scratch-caches", "--no-judge", "--workers", "1"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "agent model: inherited-model  judge model: inherited-model" in captured
