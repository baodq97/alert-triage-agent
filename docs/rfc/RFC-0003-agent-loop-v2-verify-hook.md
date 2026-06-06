---
id: RFC-0003
title: Agent loop v2 — explicit decision tree, verdict verify hook, structured termination
status: draft
owner: TBD
date: 2026-06-06
---

# RFC-0003 — Agent loop v2: decision tree, verify hook, structured termination

Parent: RFC-0001 (§Core loop), ADR-0005 (containment properties). Implemented by US-0008.
Related: ADR-0006 (entity-attribution principle — applied at the persist path, deliberately
NOT in this hook; see §Decision). Revised 2026-06-06 after an adversarial design review
calibrated the verify checks against the 35 recorded verdicts (101 findings) — see
§Calibration findings.

## Summary

Three structural upgrades to the core loop, motivated by the 2026-06-06 quality audit:
(1) the loop's state machine becomes an **explicitly declared decision tree** (this RFC is
its normative home — code mirrors this document, not the reverse); (2) a **deterministic
verdict verify hook** closes the one unguarded seam — today a Verdict ships one-shot with
no grounding check beyond the zero-evidence clamp — rolled out in **two phases**:
degrade-and-journal first, bounded re-investigation second, gated on measured calibration;
(3) termination becomes **structured**: two new terminated reasons (`no_progress`,
`revise_exhausted`) replace silent degradations, and `terminated_reason` plus journal
event names move from scattered string literals to centralized constants.

## Decision

### The decision tree (normative)

```
each loop iteration:
├─ budget_used ≥ MAX_STEPS?            → terminate: max_steps
├─ no-progress ≥ K consecutive steps?  → terminate: no_progress        [NEW]
│    (a no-progress step is an executed step whose observation is
│     ok=false; repeat-guard refusals do NOT count — they produce no
│     observation and already consume MAX_STEPS budget; counter
│     resets on any ok=true observation)
├─ pending empty?                       → conclude path
├─ execute step → observation
└─ REASONER decides:
    ├─ continue       → next iteration
    ├─ conclude       → verdict path
    └─ revise_plan
        ├─ next_step present → replace pending, next iteration
        └─ next_step absent  → terminate: revise_exhausted             [NEW]

verdict path:
└─ VERDICT synthesize
    └─ VERIFY HOOK (deterministic, code-only — no LLM call)            [NEW]
        ├─ all checks pass     → gate flow → ship
        ├─ any check fails:
        │   Phase 1 (this wave): clamp (existing) + ship
        │                        + journal verdict_verification
        │   Phase 2 (gated, see §Phasing): budget remains and re-entry
        │     unused → RE-PLAN + RE-ENTER loop (once); else Phase 1 path
        └─ hook outcome ALWAYS journaled as verdict_verification
```

Invariants preserved from RFC-0001: every exit carries a terminated reason; every path
ships a Verdict (never-crash); the loop is bounded absolutely (MAX_STEPS + at most one
verify re-entry in Phase 2); TI pre-steps remain budget-free (RFC-0002).

### Verify hook — what it verifies and how

The hook verifies the **Verdict against the run's own evidence trajectory** — grounding
and consistency, which code can check deterministically. It does NOT verify correctness
against ground truth (the eval suite's job). The check set was calibrated against the 35
recorded verdicts: every check below passes all currently-recorded correct verdicts.

| Check | Pass condition (deterministic) |
|---|---|
| Citation validity | every `finding.evidence` either (a) contains the name of a tool the run actually called, (b) contains a data value present in the run's observation set, or (c) is an alert-correlation citation (references alert fields — sanctioned by verdict.md for zero-evidence runs). Fails only when evidence matches none of the three. |
| Confidence-evidence consistency | ok_count=0 → conf ∈ [0.30,0.40] (the existing clamp band); conf ≥ 0.8 requires ≥2 ok observations; conf is never > the band ceiling when every observation failed |
| Action traceability | every targeted action's entity named by ≥1 finding (the `_filter_traceable_actions` call is removed from verdict synthesis and re-homed here as the canonical enforcement point) |
| Coverage | every alert **envelope entity** (the `entities` dict) either has ≥1 observation targeting it (by args) or its value appears in ≥1 finding (acknowledged) — TI enrichment observations count as coverage for their IOC |

**Deliberately excluded** (adversarial-review findings — not deterministically
implementable without false-failing real verdicts):

- *Severity-evidence consistency* ("low requires an observation pointing to benign") —
  code has no benign/malign classifier; two recorded-correct low verdicts (zero-evidence
  shape) would false-fail. Severity quality stays with the Tier-2 judge and the prompt
  rubric; the confidence band already binds the zero-evidence case.
- *Entity grounding* ("every entity a finding names ∈ known entities") — code has no
  entity-extraction primitive, and 7/35 recorded verdicts legitimately name `context`
  entities outside the envelope. Entity grounding lives at the **persist path**
  (ADR-0006), where a miss is journaled, never re-entered.

### Phasing (the re-entry gate)

- **Phase 1 (this wave):** the hook runs on every verdict, outcomes journaled
  (`verdict_verification` {checks: [name, pass]..., failed_entities, action}), failures
  degrade exactly as today (clamp + ship). Zero new LLM cost; replay caches unaffected by
  the hook itself. Phase 1 produces the calibration data: the measured false-flag rate on
  the recorded suite must be **0** and on live re-runs ≤ 10% before Phase 2 turns on.
- **Phase 2 (same code, config-gated `VERIFY_REENTRY=true`):** on failure with budget
  remaining and re-entry unused, the run **re-plans**: the planner is re-invoked with the
  verification gap note (failed checks + uncovered entities) appended to its context; the
  resulting steps seed a fresh `pending` and the loop re-enters via the executor's resume
  seam (`pre_observations` = the full trajectory, `executor_pre_count` preserving the
  budget contract). The verdict is then re-synthesized once. Re-entry is bounded to 1.
  A re-entry produces new prompts → those runs require **live re-recording**, not replay
  (quantified in §Impact).

The re-plan step answers "who produces new steps": the planner, with the gap note —
re-entering the executor with an empty `pending` would no-op (the loop exits on empty
pending), which is why re-entry without re-planning is unsound.

### Structured termination and events

- `terminated_reason` becomes a centralized constants module with **value-preserving**
  members (e.g. `COMPLETED = "completed"`) — serialized run records and replay caches stay
  byte-identical; existing test/YAML literals remain valid. New members: `no_progress`,
  `revise_exhausted`.
- Journal event names move to a constants module with lightweight per-event payload
  TypedDicts. The journal stays additive (unknown events still fold to no view) — the
  constants are for emitter-side coherence, not a runtime allow-list.
- Guard/adapt notes become structured `{kind, step, detail}` records rendered through one
  seam with deterministic, stable output (sorted, fixed tag order) — note text reaches
  prompts, so the wave's batched re-record absorbs the wording change.

### Parameters

- `K = 6` for the no-progress backstop — a conservative fixed safety constant: the
  recorded all-miss trajectories run 3–4 failed steps before self-concluding, and K sits
  comfortably above that while staying well below MAX_STEPS=15. The backstop is a safety
  net for weak models; it must never preempt a capable model's own conclude decision.
  Counter definition is the **narrow** one (ok=false observations only — matching the
  existing `consecutive_miss_count` semantics); repeat-guard refusals are excluded.
  Fixed constant first; an env knob only if a real need appears.
- Verify re-entry budget (Phase 2): exactly 1 per run.
- `args_schema` enforcement grammar (US-0008 adjacent hardening): required-key presence +
  scalar type check, implemented in-tree (no jsonschema dependency); a violating call
  becomes an ok=false ToolResult with the normal journal pair, never a crash.

### Module seams (binding for the implementation)

- Verify checks: new leaf `verification.py` (pure functions over Verdict + observations).
- Shared entity text-scan: new leaf `attribution.py` (imports only `models`) — used by the
  hook's action-traceability/coverage checks, by `verdict.py` (replacing its inline
  matcher), and by the ADR-0006 persist path; `memory/` stays a leaf.
- Re-entry (Phase 2): the executor's existing resume-style entry
  (`initial_step`/`pre_observations`/`executor_pre_count`) — no third entry-point.

### Success metrics (acceptance, phase-aware)

| Metric | Phase | Target |
|---|---|---|
| Hook false-flag rate on the recorded suite (replay) | 1 | **0** failing checks across all recorded-correct verdicts |
| Hook false-flag rate on live re-runs of benign cases | 1 | ≤ 10% |
| Citation validity (live suite, post-wave) | 1 | 100% pass or journaled degrade — no silent ungrounded verdict |
| Tier-1 | 1+2 | stays green |
| Judge mean (median-of-3) | 1+2 | ≥ 72 |
| Re-entry effectiveness (Phase 2 golden case) | 2 | the re-entry golden case passes verification on retry (expand to a ≥70% percentage gate once the re-entry case count warrants a denominator) |
| Token overhead | 2 | ≤ +15% mean tokens/case (only re-entering runs pay) |

### Eval impact

- All-miss cases (`tool-failure*`, `high-persistence`, `edge-empty-entities` shape)
  **pre-widen** `terminated_reason_in` to include `no_progress` in this wave, before the
  backstop lands — a weaker live model may legitimately hit the backstop.
- Prompt-affecting edits (structured note wording, planner gap-note plumbing) ship in the
  wave's single batched re-record.
- Phase 2 re-entry runs cannot replay (new prompt hashes); the re-entry golden case is
  live-recorded, and any case that starts re-entering on a future re-record is re-recorded
  live — budgeted as part of enabling `VERIFY_REENTRY`.

## Calibration findings (adversarial review, 2026-06-06)

The original six-check design false-failed ≥7 of 35 recorded-correct verdicts (severity-
evidence and entity-grounding checks chiefly), re-entry lacked a step source (empty
`pending` no-ops), and K=6's empirical anchor was overstated. This revision: 4 calibrated
checks, the re-plan mechanism, phased rollout gated on a measured false-flag rate, and K
restated as a conservative constant. The review also verified: `benign-after-flagged`
recall survives ADR-0006's cartesian removal; no invariant (never-crash, boundedness,
single-writer journal, ADR-0005 containment) is violated by the revised design.

## Alternatives considered

- **The original six-check set** — rejected by calibration: two checks are not
  deterministically implementable (benign classification, prose entity extraction) and
  false-fail recorded-correct verdicts; a hook that re-enters on correct verdicts burns
  tokens to reproduce the same conclusion.
- **Re-entry from day one (no phasing)** — rejected: the false-flag rate must be measured
  at 0 on the recorded suite before re-entry can be trusted not to fire on good verdicts;
  Phase 1 produces that measurement for free.
- **LLM self-critique as the verify hook** — rejected: stochastic, costs tokens on every
  run, duplicates the Tier-2 judge concept inline.
- **Unbounded re-entry until verification passes** — rejected: breaks absolute
  boundedness; one re-entry captures the recoverable case.
- **Keep laundering degenerate revise_plan into `completed`** — rejected: hides incomplete
  runs; a distinct reason costs one constant.
- **Runtime journal event schema enforcement** — rejected: the additive free-form journal
  is a deliberate RFC-0001 property; constants + TypedDicts give emitter coherence without
  a runtime gate.

## Impact / rollout

One wave (US-0008), build order: value-preserving constants module → `revise_exhausted` →
no-progress backstop (narrow definition; pre-widen the all-miss YAMLs) → structured notes
seam → `attribution.py` extraction (pure refactor) → `verification.py` checks (unit-tested
in isolation) → Phase-1 wiring in `_conclude_run` (no-op-on-pass first, suite stays green)
→ adjacent hardening (args_schema, 0o700 perms for runs/.memory, TI org-domain allowlist
knob) → batched re-record shared with US-0006/US-0007 → measure Phase-1 metrics. Phase 2
(`VERIFY_REENTRY`) ships in the same code, enabled only after the Phase-1 false-flag gate
is met, with its live-recorded golden case. Rollback: the hook is additive (Phase 1 changes
no shipped behavior besides journaling); the new terminated reasons only widen eval ranges.

## Open questions

- `verdict_verification` payload: check names + booleans + uncovered-entity list (bounded),
  no prose — confirm at implementation.
- Phase-2 enablement: same wave if Phase-1 calibration is immediately clean, or a
  follow-up flip? Default: same wave, flag off; the flip is a one-line config change with
  its golden case.

## Security & operational risks

- The verify hook consumes only run-local data (verdict + observations) — no new input
  surface. Its checks extend the ADR-0005 containment set to the verdict seam.
- Phase-2 gap notes quote entity values from untrusted alert data into the planner prompt —
  through the existing labeled untrusted channel (no new injection path).
- The no-progress backstop reduces the blast radius of adversarial alerts engineered to
  burn budget (today: full MAX_STEPS of LLM calls; after: K failed steps + conclude).
