---
id: US-0008
title: "Agent loop v2: verify hook, no-progress backstop, structured termination"
status: open
owner: TBD
date: 2026-06-06
priority: P1
---

# US-0008 — Agent loop v2: verify hook + structured termination

Parent: RFC-0003 (the normative decision tree — code mirrors that document), ADR-0006
(the verify hook's entity-grounding check), ADR-0005. First story of the improvement
wave: US-0006/US-0007 build on the constants and helpers this story lands.

As a SOC operator trusting the agent's verdicts, I want every verdict verified against
its own gathered evidence before it ships — with one bounded re-investigation when the
evidence does not support it — so ungrounded verdicts are either repaired or visibly
degraded, never silently shipped.

## Scope

Implement RFC-0003 §Decision exactly (the tree in that RFC is the review artifact):

- **Verify hook** (new module, e.g. `verification.py`): the six deterministic checks of
  RFC-0003 (citation validity, entity grounding, action traceability folded in,
  confidence-evidence, severity-evidence, coverage). Outcomes: pass → gate flow;
  fail + budget + unused re-entry → re-enter the loop once with a structured guard note
  naming failed checks and missing entities; otherwise clamp (existing) + ship. Every
  outcome journals `verdict_verification`.
- **No-progress backstop:** K=6 consecutive steps without an ok=true observation →
  `terminated_reason: no_progress` (fixed constant, RFC-0003 §Parameters).
- **`revise_exhausted`:** degenerate revise_plan (no next_step) terminates with its own
  reason instead of laundering into `completed`.
- **Structured termination & events:** centralized `terminated_reason` constants; journal
  event-name constants + lightweight payload TypedDicts (emitter coherence only — the
  journal stays additive); guard/adapt notes become `{kind, step, detail}` records
  rendered through one seam.
- **Adjacent hardening (small, from the audit):** `args_schema` validated at the
  `execute_tool` boundary (advisory → enforced); restrictive permissions (0o700 dirs)
  for `runs/` and `.memory/`; TI classifier org-domain allowlist knob (env, empty
  default = current behavior).
- **Eval updates:** widen `terminated_reason_in` where recorded trajectories legitimately
  hit the new reasons; add golden coverage for the hook (one case whose recorded run
  re-enters and passes; the all-miss cases accept `no_progress`). Prompt-affecting edits
  ship in the wave's single batched re-record.

Out of scope: LLM self-critique (rejected in RFC-0003), unbounded re-entry, runtime
journal schema enforcement, memory attribution itself (US-0006 — this story only lands
the shared helper seam).

## Acceptance criteria

- [ ] Code structure mirrors RFC-0003's tree: QA review maps each branch of the diagram to
      one code path; no undeclared transitions (the PR description carries the mapping)
- [ ] A verdict with a hallucinated citation (evidence referencing no real observation)
      triggers re-entry; after re-entry with budget, a grounded verdict ships; with budget
      exhausted, the degraded path ships with `verdict_verification` recording the failure
- [ ] Re-entry happens at most once per run (pinned by test); loop remains absolutely
      bounded; never-crash preserved on every new path
- [ ] 6 consecutive failed/refused steps → `no_progress` termination with a verdict;
      a 5-miss-then-conclude run (high-persistence shape) still concludes itself
- [ ] Degenerate revise terminates `revise_exhausted`, verdict ships
- [ ] `terminated_reason` values and journal event names come from constants modules
      (grep: no bare string literals at emit/termination sites)
- [ ] `execute_tool` rejects args violating the tool's `args_schema` as an ok=false
      observation (not a crash); TI allowlist knob excludes configured org domains
- [ ] RFC-0003 success metrics measured and met on the re-recorded suite: citation
      validity 100%, Tier-1 green, judge mean ≥ 72, the re-entry golden case passes
      on retry, false re-entry ≤ 10% on benign cases, token overhead ≤ +15%
- [ ] `make check` 100% coverage; `make eval` + `make eval-replay` green; resume works
      across journals containing the new events/reasons (rebuild test)

## Success metric

The RFC-0003 metrics table is the acceptance gate, measured by the eval suite before/after
on the same recorded inputs. The wave report includes the per-metric numbers.
