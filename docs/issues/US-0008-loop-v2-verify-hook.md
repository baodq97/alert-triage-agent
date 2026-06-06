---
id: US-0008
title: "Agent loop v2: verify hook, no-progress backstop, structured termination"
status: done
owner: baodq97
date: 2026-06-06
priority: P1
---

# US-0008 — Agent loop v2: verify hook + structured termination

Parent: RFC-0003 (the normative decision tree and phasing — code mirrors that document),
ADR-0006 (the shared attribution helper seam), ADR-0005. First story of the improvement
wave: US-0006/US-0007 build on the constants and helpers this story lands.

As a SOC operator trusting the agent's verdicts, I want every verdict verified against
its own gathered evidence before it ships — degraded visibly when ungrounded (Phase 1),
and repaired by one bounded re-investigation once the checks are proven calibrated
(Phase 2) — so ungrounded verdicts are never silently shipped.

## Scope

Implement RFC-0003 §Decision exactly (the tree and the §Module seams are the review
artifacts; the build order in RFC-0003 §Impact is the sequencing):

- **Verify hook** (`verification.py`, new leaf): the FOUR calibrated checks of RFC-0003
  (citation validity with the three-way trace test incl. the alert-correlation exemption;
  confidence-evidence band; action traceability — `_filter_traceable_actions` removed
  from synthesis and re-homed here; coverage over envelope entities, TI observations
  counting). Phase 1 wiring: every outcome journals `verdict_verification`; failures
  degrade exactly as today (clamp + ship). Phase 2 wiring ships in the same code behind
  `VERIFY_REENTRY` (default off): re-plan via the planner with the verification gap note,
  fresh `pending`, re-entry through the executor's resume seam
  (`initial_step`/`pre_observations`/`executor_pre_count`), at most once per run.
- **`attribution.py`** (new leaf, imports only `models`): the shared entity text-scan
  extracted from `_filter_traceable_actions` — used by the hook and, in US-0006, by the
  persist path. This story lands the helper; US-0006 lands `attribute_finding`.
- **No-progress backstop:** K=6 consecutive **ok=false observations** (the narrow
  definition — repeat-guard refusals do NOT count, matching the existing
  `consecutive_miss_count` semantics) → `terminated_reason: no_progress`. Pre-widen the
  all-miss cases' `terminated_reason_in` to include `no_progress` in this wave.
- **`revise_exhausted`:** degenerate revise_plan (no next_step) terminates with its own
  reason instead of laundering into `completed`.
- **Structured termination & events:** centralized, **value-preserving** constants for
  `terminated_reason` (serialized records and existing test/YAML literals stay valid) and
  journal event names + payload TypedDicts (emitter coherence only — the journal stays
  additive); guard/adapt notes become `{kind, step, detail}` records rendered through one
  seam with deterministic stable output.
- **Adjacent hardening:** `args_schema` enforced at the `execute_tool` boundary with the
  minimal in-tree grammar (required-key presence + scalar type; no jsonschema dependency;
  violation → ok=false ToolResult with the normal journal pair, covers the TI registry
  for free); 0o700 permissions on `runs/` and `.memory/` dir creation; TI classifier
  org-domain allowlist knob (env, empty default = current behavior).
- **Eval updates:** pre-widened reasons as above; Phase-1 metrics measured on the
  re-recorded suite; the Phase-2 re-entry golden case is live-recorded when the flag
  turns on. Prompt-affecting edits ship in the wave's single batched re-record.

Out of scope: LLM self-critique, unbounded re-entry, runtime journal schema enforcement,
re-entry enabled by default (gated on the Phase-1 false-flag measurement), memory
attribution itself (US-0006).

## Acceptance criteria

- [x] Code structure mirrors RFC-0003's tree: the PR description maps each branch of the
      diagram to one code path; no undeclared transitions
- [x] Phase-1 calibration gate: the hook reports **0 failing checks** across all
      recorded-correct verdicts when run over the replayed suite, and ≤10% on live
      re-runs of benign cases — measured numbers in the wave report
- [x] A verdict with a hallucinated citation (evidence matching no tool name, no
      observation value, and no alert field) journals a failing `verdict_verification`
      and ships degraded (Phase 1); with `VERIFY_REENTRY=true` and budget remaining, the
      run re-plans against the gap note and re-enters at most once (pinned by test),
      then ships the re-synthesized verdict
- [x] Re-entry with empty re-plan output degrades (never loops); loop remains absolutely
      bounded; never-crash preserved on every new path; resume works across journals
      containing the new events/reasons (rebuild test)
- [x] 6 consecutive ok=false steps → `no_progress` termination with a verdict; a
      3-4-miss-then-self-conclude run (the recorded all-miss shape) still concludes
      itself; repeat-guard refusals do not advance the no-progress counter (pinned)
- [x] Degenerate revise terminates `revise_exhausted`, verdict ships
- [x] `terminated_reason` values and journal event names come from value-preserving
      constants (grep: no bare string literals at emit/termination sites; serialized
      `result.json`/journal bytes unchanged for existing reasons)
- [x] `execute_tool` rejects args violating the declared grammar as an ok=false
      observation (not a crash), for primary and TI registries; TI allowlist knob
      excludes configured org domains
- [x] RFC-0003 §Success metrics Phase-1 rows measured and met on the re-recorded suite
      (Tier-1 green, judge mean ≥ 72, citation validity 100% pass-or-journaled)
- [x] `make check` 100% coverage; `make eval` + `make eval-replay` green

## Success metric

The RFC-0003 phase-aware metrics table is the acceptance gate; the wave report includes
the per-metric numbers, including the Phase-1 false-flag measurement that gates Phase 2.
