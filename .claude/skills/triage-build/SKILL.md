---
name: triage-build
description: Orchestrates building the alert-triage-agent — dispatches triage-implementer and triage-qa through the D1–D4 implementation waves with make check / make eval / govkit verify gates. Use when asked to implement, build, continue building, re-run, update, fix, or extend any part of the agent (core loop, journal, gate, memory, evals, watch mode); also for "implement the next wave", "tiếp tục implement", "redo module X", "apply QA fixes", or resuming after an interrupted build session.
---

# triage-build (orchestrator)

Builds the product defined by PRD-0001/RFC-0001 using the project agents. **Execution mode: sub-agents** (pipeline with generate→verify per wave) — artifacts flow through git working tree + `_workspace/`; no team communication needed.

## Phase 0: context check (always run first)

1. `git log --oneline -5` + `git status --short` + `ls _workspace/ 2>/dev/null` + `ls src/triage/`
2. Decide the mode:
   - No module code yet → **initial build** from Wave 1
   - Modules exist + user asks to continue → **resume**: find the first wave whose Definition of Done fails (run `make check`, inspect module presence), restart there
   - User asks to redo/fix a specific module → **partial re-run**: dispatch only that module's implementer (+QA), with the user feedback verbatim in the prompt
3. Read `docs/rfc/RFC-0001-agent-architecture.md` §Impact/rollout and any open `docs/issues/US-*` for current scope adjustments.

## Waves (from RFC-0001 rollout)

| Wave | Scope | Definition of Done |
|---|---|---|
| 1 (D1–2) | `models` → `llm` → `tools` (registry + fixtures) → `planner` → `executor` → `gate` → `verdict` → `run.py --alert` | `make check` green; the 3 required tests exist (tool call, approval gate, tool error); both sample alerts produce a verdict end-to-end |
| 2 (D2–3) | `journal` (emit + replay) → retry visibility → `--resume [--approve\|--deny]` | journal written per run; kill-after-step-2 → resume → correct verdict; gate rides on resume |
| 3 (D3) | **eval harness (mandatory, not cuttable)** → memory L1–L2 + entity-scoped recall | `make eval` runs the 5-case golden set; replay mode works key-free |
| 4 (D4) | L3 posture (degradable to deterministic) → `--watch` → README | full sweep QA; README sections per PRD (incl. assumptions, trade-offs, requirements traceability) |

Within a wave, dispatch `triage-implementer` (model: opus) per module group sequentially when dependent, in parallel (background) when independent. After each module group lands, dispatch `triage-qa` (model: opus) scoped to the new seams (incremental QA). Both agents read `triage-conventions` themselves — do not paste conventions into prompts; pass module scope + RFC section + allowed files + acceptance criteria.

## Gates between waves

A wave is done only when: `make check` green + incremental QA report has no open MISMATCH + (wave ≥3) `make eval` green + `npx govkit verify` green. Then pause and report to the user — the user decides commit timing (agents never commit).

## Data flow

- Implementer output (final message) → orchestrator → QA prompt (files touched, seams to check)
- QA report → `_workspace/{wave}_qa_report.md`; fix list → next implementer dispatch
- Naming: `_workspace/{wave}_{agent}_{artifact}.md`; `_workspace/` is preserved for audit, never committed

## Error handling

- Implementer stops at its 2-failed-fixes rule → review its hypotheses; re-dispatch once with a sharper prompt (include the failing output); if it fails again, surface to the user with options — never loop a third time blind.
- QA finds a MISMATCH → re-dispatch the implementer with the QA fix list verbatim; QA re-checks only the affected seams.
- A wave's DoD cannot be met within scope (e.g. missing API key for live runs) → record what was skipped and why in the wave report; ask the user before degrading scope (the RFC's cut lines: L3 → deterministic; watch-mode → README; eval is NEVER cut).
- Conflicting instructions between RFC and user → user wins; note the deviation so doc-keeper can sync the RFC afterwards.

## Test scenarios

- **Happy path:** "implement wave 1" on a clean tree → 7 module groups land sequentially, each followed by scoped QA; finishes with both alerts producing verdicts; `make check` output in the report; user prompted to commit.
- **Error path:** executor tests keep failing (LLM mock shape wrong) → implementer stops per its rule → orchestrator re-dispatches once with the pytest output inline → still failing → user gets the two hypotheses + a proposal (fix the mock contract in `triage-conventions` first), no third blind retry.
- **Resume path:** "continue the build" after a crashed session mid-wave-2 → Phase 0 detects journal module present but resume test failing → restarts wave 2 at the resume task, skipping completed emit work.
