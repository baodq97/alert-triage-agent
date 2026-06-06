---
id: US-0006
title: "Memory v2: entity-attributed finding atoms"
status: open
owner: TBD
date: 2026-06-06
priority: P1
---

# US-0006 — Memory v2: entity-attributed finding atoms

Parent: ADR-0006 (the attribution principle — normative), RFC-0001 §Memory.
Coordinates with US-0008 (the verify hook's entity-grounding check feeds attribution
quality) and US-0007 (shares the single improvement-wave replay re-record).

As a SOC analyst relying on recall, I want prior findings recalled only for the entities
they are actually about, so that an alert sharing one entity with an old incident surfaces
that entity's history — not every claim from every co-occurring entity — and recall
precision improves as the store grows instead of degrading.

## Scope

Apply ADR-0006's resolution order to the persist path:

- `Finding.related_entities: list[str]` (optional) on the LLM output model; prompt
  (`verdict.md`) instructs attribution; values validated ∩ alert entities in code.
- Deterministic text-scan fallback for undeclared findings — extracted into ONE shared
  attribution helper reused by `_filter_traceable_actions` (no second substring
  implementation).
- Unattributed findings persist nothing and emit `finding_unattributed` (journal).
- Both persist callers thread the same path: `_conclude_run` (core) and the eval seeder
  `_seed_memory` (runner) — eval `prior_runs` seeds declare entities explicitly.
- Existing stores: no migration (atoms are append-only facts; old cartesian atoms age out
  by confidence/recency ranking). Document this choice in the module docstring.

Out of scope: dossier/recall ranking changes (mechanism unchanged), L3 posture changes.

## Acceptance criteria

- [ ] A finding declaring `related_entities: [X]` persists atoms only for X (given X is an
      alert entity); hallucinated entity names persist nothing for those names
- [ ] An undeclared finding whose statement/evidence names alert entity Y persists exactly
      Y's atom (text-scan fallback); one not naming any entity persists nothing and emits
      `finding_unattributed`
- [ ] Cartesian fan-out is gone: a 4-entity / 4-finding verdict no longer yields 16 atoms
      unless every finding genuinely names all 4 entities
- [ ] `benign-after-flagged` and `medium-recall-elevates` golden cases still pass (their
      seeded recall semantics preserved via explicit entity declarations)
- [ ] One shared attribution helper serves persist AND action traceability (grep proves no
      duplicate substring matcher)
- [ ] `make check` green, 100% coverage; full suite re-recorded once (batched) and
      `make eval` + `make eval-replay` green

## Success metric

Recall noise on a constructed two-incident fixture (entity overlap of exactly one):
recalled items for the shared entity reference only that entity — 0 cross-entity items
(today: up to cap-10 polluted). Measured by a unit test pinning the scenario.
