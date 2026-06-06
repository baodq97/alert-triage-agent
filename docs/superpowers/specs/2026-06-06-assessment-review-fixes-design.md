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

## Non-goals

- No `src/triage/` code changes (one workspace-script tweak only).
- No MITRE/Sigma/Neo4j features.
- No new golden cases.

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

### 7. Cross-model eval — DeepSeek-V4-Pro (Azure AI Foundry)

Proves the requirements-bonus claim "swap in another model without changing
agent logic": configuration only.

- Config: `.env.deepseek` (gitignored; `.env.*` already in .gitignore) with
  the Foundry endpoint `https://aoi-aiq-002.services.ai.azure.com/openai/v1`
  and `LLM_MODEL=DeepSeek-V4-Pro`. Endpoint smoke-tested OK
  (OpenAI-compatible response shape).
- Fair comparison: `_workspace/run_dataset.py` gains optional `JUDGE_MODEL` /
  `JUDGE_BASE_URL` / `JUDGE_API_KEY` env overrides so the judge stays pinned
  to gpt-5.4-mini while the agent runs on DeepSeek. Workspace script only —
  `src/triage/` untouched.
- Run: full 35-case live sweep on DeepSeek-V4-Pro, judge pinned; output to
  `_workspace/evalrun-deepseek/`. **Replay caches are NOT re-recorded from
  this run** (the committed caches stay gpt-5.4-mini — the deterministic CI
  baseline); the DeepSeek run writes its caches to a scratch dir.
- Report: Tier-1 per case (the gate — expectation: pass, this is the claim
  under test), judge mean as secondary, latency/token comparison. Results land
  in `docs/evals/results.md`. If Tier-1 fails on some cases, the failures are
  reported as-is with a short analysis — an honest negative beats a polished
  claim.

## Error handling / testing

Docs-only plus one workspace script change: gates are `make check` (code
untouched, must stay green), `make eval-replay` (35/35 — proves the committed
caches still serve), `npx govkit verify` (link/INDEX hygiene), and a manual
link check on moved report files. The DeepSeek sweep itself is the test for
item 7.

## Delivery

One branch, one PR, merged per the owner's standing pattern. Spec committed at
`docs/superpowers/specs/2026-06-06-assessment-review-fixes-design.md`.
