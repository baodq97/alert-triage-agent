# Assessment-review fixes — design

Date: 2026-06-06. Input: a technical review of this repo as a take-home
submission against the Agentic AI Engineer JD. Five reviewer concerns are
addressed with documentation; one (cross-model proof) adds an eval run on a
second model family. MITRE ATT&CK mapping was considered and dropped by the
owner.

## Goals

1. Convert the reviewer's biggest doubt (build-time / AI-assistance signal)
   into a demonstrated strength via full transparency.
2. Give self-reported metrics honest weight (Tier-1 and independent telemetry
   lead; the self-graded judge follows with a caveat).
3. Document the trade-offs the JD will probe: sync-by-design scale path,
   framework fluency behind the no-framework decision, verify-hook calibration
   limits.
4. Consolidate eval documentation into one folder and prove the
   model-swap-without-behavior-change claim with a real cross-model run.

## Scope expansion (v2, owner-directed)

The owner expanded scope beyond docs: promote the eval driver into shipped,
tested source; emphasize memory across docs and evals; add a memory golden
case. This is a real feature in the eval subsystem → it is governed by a new
**US-0009** authored via spec-author BEFORE code (parent RFC-0001 §Eval; the
model-agnostic boundary is ADR-0002, already accepted — no new RFC/ADR). The
three-model cross-eval is already run (results below).

## Non-goals

- No new RFC/ADR (no new architectural decision — promotion + cross-model are
  covered by RFC-0001 §Eval and ADR-0002).
- No MITRE/Sigma/Neo4j features.
- No agent-loop (`core`/`executor`/`planner`/`verdict`) behavior changes — the
  eval runner is the only new source; the one new golden case is data.

## Changes

### 1. README — "How this was built" (new section after "What and why")

~15 lines, full-transparency framing approved by the owner: built with an
agentic workflow (Claude Code driving implementation inside an owner-designed
harness — govkit governance gates PRD→RFC→ADR→US, triage-build
implementer/QA agents, two-tier eval gates between waves). Ownership split
stated plainly: agents wrote most code and tests; the owner owns every
architecture decision (ADR-0001…0006), the calibration constants (K=6, the
[0.30, 0.40] clamp band, the zero-covered coverage rule), the accept/reject
call on every review finding, and the eval-contract design. Closing line: for
an Agentic AI Engineer role, the workflow itself is part of the demonstration.
Links to `docs/evals/` as the process evidence.

### 2. README — §Evaluation results reframed

Reorder the metrics table: Tier-1 35/35 and coverage-gap telemetry 10→3
(judge-independent) first; judge mean 84.1 after, with a one-sentence caveat:
self-graded rubric, median-of-3, and round 5 of the quality loop calibrated
the judge itself — treat as a trend signal; the independent rows above carry
the acceptance weight. The number stays; only its weight changes.

### 3. README — §Trade-offs: "Sync single-process by design"

~6 lines: triage of one alert is inherently sequential (each step depends on
the previous observation), so the run is sync; scale-out is across alerts, and
the seams already permit it — `triage(alert, deps)` is pure with injected
deps, the journal is event-sourced per run — so the path is a queue with one
worker per alert, async LLM calls as the first concurrency win, and the
file-based memory store replaced with a DB before multi-worker writes.

### 4. docs/architecture.md §8 — "The LangGraph equivalence" (new subsection)

A mapping table proving the no-framework decision was made from fluency, not
avoidance: planner/executor/reasoner/verdict → StateGraph nodes; reasoner
verbs → conditional edges; journal ↔ SqliteSaver checkpointing (and why the
journal wins: human-readable, event-sourced, eval-assertable); CLIGate /
DeferredGate ↔ `interrupt()` + `Command(resume=...)`; MAX_STEPS /
no_progress / revise_exhausted ↔ recursion_limit + custom guard nodes.
Closing: the mapping is mechanical — the reason to hand-roll is the journal
contract, not the framework.

### 5. docs/architecture.md §6 — verify-hook calibration limits

3–4 lines appended: the calibration set is 35 self-authored cases, not a real
SOC distribution; the 8.6% live rate is the first out-of-calibration evidence;
`VERIFY_REENTRY` stays the kill-switch and Phase-1 telemetry
(`verdict_verification` events) is the standing re-calibration mechanism when
the alert distribution drifts.

### 6. docs/evals/ — consolidated eval documentation

- `docs/evals/README.md`: how to run (`make eval-replay`, `make eval`,
  single-case via runner, re-record via `_workspace/run_dataset.py`), and the
  model settings disclosed: primary = `gpt-5.4-mini` on Azure AI Foundry
  (OpenAI-compatible endpoint), judge = same model, median-of-3; env contract
  (`LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL`, never committed).
- `docs/evals/results.md`: per-model results table (Tier-1 pass rate, judge
  mean where comparable, latency/tokens) — gpt-5.4-mini baseline plus the
  cross-model run below.
- Move `docs/reports/2026-06-06-quality-loop-summary.md` and the HTML report
  into `docs/evals/`; update the links in README and RFC-0003. `docs/reports/`
  is removed.

### 6b. docs/evals/ — memory recall results

Memory is a graded JD capability ("context layer that gives agents awareness of
past incidents"). `docs/evals/memory.md` reports the measured recall behaviour:
the two seeded golden cases (`benign-after-flagged`, `medium-recall-elevates`),
atom counts before/after entity attribution (277 → 108, −61% cross-entity
noise), the `finding_unattributed` rate, and the new cross-entity precision case
(item 9). Numbers come from a measurement script promoted alongside the runner.

### 7. Cross-model eval — three-model matrix (RUN, results final)

Proves the requirements-bonus claim "swap in another model without changing
agent logic": configuration only — same agent, three model families, three
endpoints (2 Azure Foundry + 1 OpenRouter), only `.env` changed.

| Model | Endpoint | Tier-1 | Judge (pinned) | stdev | wall/case | tok/case |
|---|---|---|---|---|---|---|
| gpt-5.4-mini | Azure Foundry | **35/35** | 83.8 | 3.1 | 12.0s | 14.8k |
| Llama-3.3-70B-Instruct | Azure Foundry | 31/35 | 78.6 | 5.7 | 17.3s | 11.6k |
| deepseek-v4-flash | OpenRouter | 29/35 | 83.3 | 3.4 | 80.4s | 19.6k |

Judge pinned to gpt-5.4-mini for all three (score comparability). Honest
framing: Tier-1 35/35 holds only on the model the cases were calibrated against;
the others **degrade gracefully** (never-crash + clamp + verify hook keep a
valid verdict). Key insight: deepseek's judge (83.3) ≈ gpt's (83.8) while its
Tier-1 (29/35) is lower — strong reasoning, but confidence/severity band drift
and missed entity references that the **deterministic Tier-1 gate** catches and
the holistic judge forgives. This is the live argument for why Tier-1 gates and
the judge only advises. Operational finding: Azure Foundry's default
Responsible-AI content filter 400-blocked security alert content on the
DeepSeek/Llama deployments until the filter policy was relaxed — a real
deployment lesson for running security agents on serverless models.

### 8. Promote the eval runner to source (US-0009)

`_workspace/run_dataset.py` → `src/triage/evals/sweep.py` as a standardized,
tested module — the multi-model eval runner becomes a shipped capability, not a
scratch script.

- Module: `sweep.py` exposing a `run_sweep(...)` orchestrator and a `main(argv)`
  CLI mirroring `runner.main`'s style. Capabilities: `--env-file` /
  `--judge-env-file` (isolated per-model env, judge-pin via `LLM_`→`JUDGE_`
  prefix map), `--scratch-caches` (never overwrite committed baseline),
  `--min-case-seconds` (RPM throttle), `--workers`, `--out`. Pure seams
  (env-file parse, prefix map, throttle, cache-dest selection, results
  aggregation) are extracted as small functions.
- `results.py` (or a function in sweep): aggregate a run dir → the per-model
  table (Tier-1 count, judge mean/stdev/min, wall, tokens) used in
  `docs/evals/results.md`.
- Make targets: `make eval-sweep ENV=.env.deepseek` etc., documented in
  `docs/evals/README.md`.
- Tests (`tests/test_sweep.py`): unit-cover every non-LLM seam — env-file
  parsing + JUDGE_ prefix mapping, throttle floor math, scratch-cache
  destination, results aggregation over fixture JSONs, judge-pin selection.
  100% coverage gate applies to the new module.
- `_workspace/run_dataset.py` is deleted (its logic now lives in source);
  `_workspace/audit_run.py` / `measure_attribution.py` either promote too or
  stay as throwaway analysis — decide in the plan (lean: promote the results
  aggregation into source, keep ad-hoc analysis in workspace).

### 9. Memory emphasis (owner-directed, all four)

- **docs/architecture.md §5 deep-dive**: L1 entity-attributed atoms (ADR-0006
  resolution order), L2 deterministic dossiers, L3 posture; the recall→planner
  flow; why precision rises with store size (entity-scoping) instead of
  degrading; the 277→108 atom measurement.
- **README — Memory as its own section** (lifted from one Architecture line):
  frames the context layer the JD names explicitly.
- **docs/evals/memory.md**: the recall measurement (item 6b).
- **New golden case** `medium-shared-entity-recall` (or similar): two prior
  incidents seeded sharing exactly one entity; asserts recall surfaces only the
  shared entity's history, not cross-entity pollution — the success metric from
  US-0006 made executable. Needs a gpt-5.4-mini replay-cache record (one live
  case). Tier-1 assertions only; no agent-loop change.

## Error handling / testing

- New source (`sweep.py`, results agg, new case): `make check` stays green at
  100% coverage; `tests/test_sweep.py` covers the non-LLM seams.
- `make eval-replay` 35/35 + the new case's recorded cache = 36/36.
- `npx govkit verify` clean (US-0009 front-matter + INDEX; moved-report links).
- The three cross-model sweeps are already run; their numbers are transcribed
  into `docs/evals/results.md` (the sweeps are the test for the swap claim).

## Delivery

Governance first: author **US-0009** via spec-author (owner:TBD, status:open;
propose owner + flip in the PR body). Then implement on one branch: promote
runner + tests, new memory case + record, all docs (items 1–6b, 9), results
table (item 7). One PR, gates green, merged per the owner's standing pattern.
Spec at `docs/superpowers/specs/2026-06-06-assessment-review-fixes-design.md`.
