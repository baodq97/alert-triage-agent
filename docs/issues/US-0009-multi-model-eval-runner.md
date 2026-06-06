---
id: US-0009
title: "Multi-model eval runner: promote sweep to source + cross-model results"
status: done
owner: baodq97
date: 2026-06-06
priority: P2
---

# US-0009 — Multi-model eval runner: promote the sweep to source + cross-model results

Parent: RFC-0001 §Eval (two-tier contract), US-0003, US-0007. The model-agnostic
LLM boundary is ADR-0002 (accepted) — this story adds no new architectural decision;
it promotes an existing workspace driver into shipped, tested source and proves the
"swap model without changing agent logic" claim (requirements bonus #3) with measured
cross-model results.

As a maintainer evaluating the agent on more than one model, I want the multi-model
eval sweep to be a standardized, tested part of the source tree — not a scratch script
— so that running, comparing, and re-recording any OpenAI-compatible model is a
documented one-command operation, and the model-portability evidence is reproducible.

## Scope

- **Promote** `_workspace/run_dataset.py` → `src/triage/evals/sweep.py`: a standardized
  module exposing `run_sweep(...)` (orchestrator) and `main(argv)` (CLI, mirroring
  `runner.main` style). Pure, independently testable seams extracted as functions:
  env-file parsing, the `LLM_`→`JUDGE_` prefix map (judge-pin), the per-case throttle
  floor, the scratch-cache destination selector, and results aggregation.
- **CLI flags**: `--env-file` / `--judge-env-file` (isolated per-model env; judge stays
  pinned for score comparability), `--scratch-caches` (never overwrite the committed
  baseline replay caches), `--min-case-seconds` (RPM throttle for rate-limited
  serverless models), `--workers`, `--out`.
- **Results aggregation** into source: a function that reduces a run directory to the
  per-model table (Tier-1 pass count, judge mean/stdev/min, wall/case, tokens/case),
  consumed by `docs/evals/results.md`.
- **Make targets**: `make eval-sweep ENV=<file>` (and judge-pin variant), documented in
  `docs/evals/README.md`.
- **Memory recall case**: add one golden case asserting cross-entity recall precision —
  two prior incidents sharing exactly one entity; recall surfaces only the shared
  entity's history (US-0006's success metric made executable). gpt-5.4-mini replay
  cache recorded; Tier-1 assertions only; no agent-loop change.
- **Delete** `_workspace/run_dataset.py` once its logic lives in source.

Out of scope: any `core`/`executor`/`planner`/`verdict` behavior change; new RFC/ADR;
judge-as-gate (unchanged from US-0007); MITRE/Sigma/graph features.

## Acceptance criteria

- [x] `src/triage/evals/sweep.py` exists with `run_sweep` + `main`; `make eval-sweep`
      runs a single model end-to-end and writes per-case JSON + an aggregated summary
- [x] Judge stays pinned via `--judge-env-file` regardless of the agent model (proven by
      a unit test on the env/prefix-map seam)
- [x] `--scratch-caches` writes recorded caches under `--out`, never next to the case
      YAMLs (unit test on the destination selector; committed caches unchanged)
- [x] `--min-case-seconds` floors per-case wall time (unit test on the throttle math)
- [x] Results aggregation reduces a fixture run dir to the documented table (unit test)
- [x] The cross-entity memory recall case passes Tier-1 on its recorded cache; recall
      surfaces only the shared entity (no cross-entity pollution)
- [x] `_workspace/run_dataset.py` removed; `grep` shows no remaining import of it
- [x] `make check` green at 100% coverage (new `tests/test_sweep.py`); `make eval-replay`
      green including the new case; `npx govkit verify` clean

## Success metric

A second model is evaluated against the full suite with a single documented command and
zero `src/triage` edits, producing the per-model comparison table in
`docs/evals/results.md` — demonstrating model portability is configuration, not code.
The three-model matrix (gpt-5.4-mini 35/35, Llama-3.3-70B 31/35, deepseek-v4-flash
29/35; judge pinned) is the first such artifact.
