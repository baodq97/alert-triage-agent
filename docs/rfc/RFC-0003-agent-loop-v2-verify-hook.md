---
id: RFC-0003
title: Agent loop v2 — explicit decision tree, verdict verify hook, structured termination
status: draft
owner: TBD
date: 2026-06-06
---

# RFC-0003 — Agent loop v2: decision tree, verify hook, structured termination

Parent: RFC-0001 (§Core loop), ADR-0005 (containment properties). Implemented by US-0008.
Related: ADR-0006 (entity-attribution principle — the verify hook's grounding checks apply it).

## Summary

Three structural upgrades to the core loop, motivated by the 2026-06-06 quality audit:
(1) the loop's state machine becomes an **explicitly declared decision tree** (this RFC is
its normative home — code mirrors this document, not the reverse); (2) a **deterministic
verdict verify hook** closes the one unguarded seam — today a Verdict ships one-shot with
no grounding check beyond the zero-evidence clamp; (3) termination becomes **structured**:
two new terminated reasons (`no_progress`, `revise_exhausted`) replace silent degradations,
and `terminated_reason` plus journal event names move from scattered string literals to
centralized constants.

## Decision

### The decision tree (normative)

```
each loop iteration:
├─ budget_used ≥ MAX_STEPS?            → terminate: max_steps
├─ no-progress ≥ K consecutive steps?  → terminate: no_progress        [NEW]
│    (a step is no-progress when it yields no ok=true observation:
│     tool failure or repeat-guard refusal; counter resets on ok=true)
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
        ├─ all checks pass                        → gate flow → ship
        ├─ any check fails, budget remains,
        │  re-entry not yet used                  → RE-ENTER loop (once):
        │     guard note names the failed checks and the
        │     entities/aspects still needing evidence
        └─ any check fails, budget exhausted
           or re-entry already used               → clamp (existing) + ship
                                                     + journal verdict_verification
```

Invariants preserved from RFC-0001: every exit carries a terminated reason; every path
ships a Verdict (never-crash); the loop is bounded absolutely (MAX_STEPS + at most one
verify re-entry); TI pre-steps remain budget-free (RFC-0002).

### Verify hook — what it verifies and how

The hook verifies the **Verdict against the run's own evidence trajectory** — grounding
and consistency, which code can check deterministically. It does NOT verify correctness
against ground truth (that remains the eval suite's job: golden cases + Tier-2 judge).

| Check | Pass condition |
|---|---|
| Citation validity | every `finding.evidence` traces to ≥1 real observation of this run |
| Entity grounding | every entity a finding names ∈ alert entities ∪ observation data |
| Action traceability | every action target named by ≥1 finding (the `_filter_traceable_actions` call is removed from verdict synthesis and re-homed here as the canonical enforcement point) |
| Confidence-evidence consistency | ok_count=0 → conf ∈ [0.30,0.40]; conf ≥ 0.8 requires ≥2 consistent ok-observations; mixed evidence → conf < 0.8 |
| Severity-evidence consistency | `low` requires ≥1 ok-observation pointing to benign ("low because nothing is known" is medium + low confidence) |
| Coverage | every alert entity either investigated (≥1 observation) or acknowledged unverified in a finding |

On failure with budget remaining, the re-entry guard note names the failed checks and the
missing entities/aspects — the agent knows precisely what to gather. The hook's outcome is
always journaled as `verdict_verification` {checks, failed, action: pass|reenter|degrade}.

### Structured termination and events

- `terminated_reason` becomes a centralized enum/constants module (today: string literals
  scattered across executor/core). New members: `no_progress`, `revise_exhausted`.
- Journal event names move to a constants module with lightweight per-event payload
  TypedDicts. The journal stays additive (unknown events still fold to no view) — the
  constants are for emitter-side coherence, not a runtime allow-list.
- Guard/adapt notes become structured `{kind, step, detail}` records rendered through one
  seam (today: inline f-strings in the executor), so note wording is tunable without
  touching loop logic.

### Parameters

- `K = 6` for the no-progress backstop — above the longest legitimately observed
  all-tools-miss run (5 failed steps then self-conclude, case high-persistence), below
  MAX_STEPS=15. The backstop is a safety net for weak models; it must never preempt a
  capable model's own conclude decision. Fixed constant first (the RFC-0002 step-cap
  pattern); an env knob only if a real need appears.
- Verify re-entry budget: exactly 1 per run.

### Success metrics (acceptance, measured by the eval suite before/after)

| Metric | Target |
|---|---|
| Citation validity rate across the golden suite | 100% |
| Tier-1 | stays green (35/35 + new cases) |
| Judge mean (median-of-3) | ≥ 72 (no regression; re-entry should lift weak runs) |
| Re-entry effectiveness | the re-entry golden case passes verification on retry (expand to a ≥70% percentage gate once the re-entry case count warrants a denominator) |
| False re-entry rate on benign cases | ≤ 10% |
| Token overhead | ≤ +15% mean tokens/case (only failing runs pay) |

Eval impact: cases whose recorded trajectories legitimately end in the new reasons widen
`terminated_reason_in`; all-miss cases add `no_progress` to their accepted set. Prompt
changes from the re-entry guard note → one replay re-record (the standing workflow).

## Alternatives considered

- **LLM self-critique as the verify hook** — rejected: stochastic, costs tokens on every
  run, and duplicates the Tier-2 judge concept inline. The deterministic checks cover the
  failure modes observed in audits (hallucinated citations, over-confidence on thin
  evidence); the judge remains the offline substance critic.
- **Unbounded re-entry until verification passes** — rejected: breaks the absolute
  boundedness invariant; a model that cannot satisfy the checks loops forever. One
  re-entry captures the recoverable case (agent simply stopped early); the rest degrade
  visibly instead of silently.
- **Keep laundering degenerate revise_plan into `completed`** (status quo) — rejected: it
  hides incomplete runs from operators and evals; a distinct reason costs one constant.
- **Runtime journal event schema enforcement** — rejected: the additive free-form journal
  is a deliberate RFC-0001 property (forward compatibility, resume folds unknown events
  safely). Constants + TypedDicts give emitter coherence without a runtime gate.

## Impact / rollout

One wave (US-0008), code mirroring this tree: constants/enum module → no_progress +
revise_exhausted in the executor → structured notes seam → verify hook module + re-entry
wiring in core → journal event + tests → eval expectation updates + one re-record batch
(shared with US-0006/US-0007 prompt changes). The tree diagram above is the review
artifact for the implementing PR: QA verifies code-vs-tree, not code-vs-intuition.
Rollback: the hook and backstop are additive guards — removing them restores v1 behavior;
the new terminated reasons only widen eval ranges.

## Open questions

- Should `verdict_verification` carry per-check detail strings or only check names + bools?
  Propose names + bools + the failed checks' missing-entity lists (bounded), no prose.
- Coverage check vs TI: does a TI enrichment observation count as "investigated" for the
  IOC entity? Propose yes (it is an observation on that entity).

## Security & operational risks

- The verify hook consumes only run-local data (verdict + observations) — no new input
  surface. Its checks are the ADR-0005 containment set extended to the verdict seam.
- Re-entry notes quote entity values from untrusted alert data into the reasoner prompt —
  they pass through the existing guard-note channel, which renders inside the labeled
  untrusted block (no new injection path).
- The no-progress backstop reduces the blast radius of adversarial alerts engineered to
  burn budget (today: full MAX_STEPS of LLM calls; after: K + conclude).
