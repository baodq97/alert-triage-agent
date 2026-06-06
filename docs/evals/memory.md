# Memory recall — measured behavior

The agent's context layer (ADR-0006, US-0003 §Memory, US-0006) gives it awareness
of prior incidents. This page reports what that layer actually does on the eval
suite — the numbers, not the intent.

## What memory does

- **L1 — entity-attributed finding atoms.** On persist, each finding is attributed
  to the alert entities it actually names (ADR-0006 resolution order: declared
  `related_entities`, validated against `entities ∪ context` scalars → text-scan
  fallback → otherwise persist nothing and journal `finding_unattributed`). An
  atom exists for an entity **iff** the claim names that entity.
- **L2 — entity dossiers.** Deterministic group-by over atoms, ranked by
  confidence/recency, capped — no LLM.
- **L3 — posture brief.** LLM synthesis on a cadence, with a deterministic
  top-N fallback (key-free).
- **Recall is entity-scoped.** The planner receives dossiers only for the current
  alert's entities, so precision rises with store size instead of degrading into
  cross-entity noise.

## Attribution measurement (the cartesian-noise reduction)

`_workspace/measure_attribution.py` replays every golden case and compares the
attributed persist path (ADR-0006) against the old cartesian fan-out (every
finding × every envelope entity → one atom), using the real `attribute_finding`.

| Metric (36-case replay suite) | Value |
|---|---|
| Findings produced | 139 |
| Atoms — cartesian fan-out (pre-ADR-0006) | 354 |
| Atoms — entity-attributed (shipped) | **114** |
| Reduction | **−67.8%** |
| Findings with no envelope-entity atom (audit-logged, not silently dropped) | 41 |

The reduction is the point: 240 cartesian atoms that named entities the finding
was not actually about never get written, so recall for any one entity returns
that entity's history rather than every co-occurring entity's. Findings that
resolve to no envelope entity are not lost silently — they emit
`finding_unattributed` (ADR-0006 §Consequences: "no silent path").

## Recall precision — the two seeded cases + the precision proof

Two golden cases exercise recall end-to-end through the live loop:

- **`medium-recall-elevates`** — a prior HIGH-confidence malicious finding for
  `user-finops-charlie` seeds memory; a new ambiguous alert for the same entity
  must conclude at least **medium** (recall informs and can elevate).
- **`medium-shared-entity-recall`** (US-0009) — the store holds two prior
  incidents: a malicious finding for the shared entity `user-payroll-erin` **and
  a distractor** for an unrelated entity `svc-batch-zeta`. The new alert names
  only `user-payroll-erin`; the verdict elevates from erin's recalled history
  while the distractor stays out. Proven stable across 4 consecutive live runs
  before gating.

The precision claim itself — *zero* cross-entity pollution — is pinned
deterministically (no LLM, no flake) by
`tests/test_memory.py::test_recall_shared_entity_precision_no_cross_pollution`:
two multi-entity incidents sharing exactly one entity, recall for the shared
entity surfaces only its atoms, none from the other incident. This is US-0006's
success metric made executable.
