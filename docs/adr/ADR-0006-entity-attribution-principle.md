---
id: ADR-0006
title: Entity-attribution principle — every persisted claim names its entity
status: proposed
owner: TBD
date: 2026-06-06
---

# ADR-0006 — Entity-attribution principle

Parent: RFC-0001 (§Memory), ADR-0005 (deterministic validation posture). Applied by
US-0006 (memory atoms) and RFC-0003's verify hook (verdict checks). Generalizes the
action-traceability rule shipped 2026-06-06.

## Context

Two seams attach LLM-authored claims to entities, and they drifted apart:

- **Actions** (verdict): since the quality wave, a recommended action must be traceable to
  a finding naming the same entity — enforced in code (`_filter_traceable_actions`).
- **Memory atoms** (persist): findings carry no entity reference, so every finding is
  persisted against **every** matchable alert entity (cartesian). A later alert sharing
  only one entity recalls findings about unrelated entities; with the recall cap at
  top-10, this noise displaces relevant atoms. The store degrades as it grows — the
  opposite of what memory is for.

The cheap fixes are both wrong long-term: keeping the cartesian fallback preserves the
noise forever; silently dropping unattributed findings loses memory whenever a weaker
model forgets to attribute (and nothing surfaces the loss).

## Decision

One principle, applied at every seam that binds a claim to an entity:

> **A persisted claim exists for an entity if and only if the claim names that entity.**

Resolution order, deterministic and code-enforced:

1. **Declared:** `Finding.related_entities` (new optional field on the LLM output model) —
   accepted only after validation against the alert's entities (declared ∩ alert entities;
   hallucinated entity names are dropped).
2. **Detected (fallback):** when a finding declares nothing, a deterministic text-scan of
   the finding's statement + evidence for alert-entity values (the same substring machinery
   the action-traceability filter uses — one shared helper, not a second implementation).
3. **Unattributed (no silent path):** when neither yields an entity, no atom is persisted
   and a `finding_unattributed` journal event records the finding — visible in the audit
   trail, never silently lost, never cartesian-fanned.

The verify hook's entity-grounding check (RFC-0003) applies the same rule at verdict time,
so attribution quality is corrected by re-entry before persist ever sees the finding.

## Alternatives considered

- **Cartesian fallback when undeclared** (status quo for memory) — rejected: precision
  never improves for weak models, noise compounds with store size, and the recall cap
  amplifies the damage. Was acceptable only while the store was small.
- **Strict drop when undeclared** — rejected: silent memory loss keyed to model quality;
  violates the audit posture (nothing in the journal says the finding vanished).
- **Primary-entity heuristic** (attach to the alert's first entity) — rejected: a wrong
  attribution is worse than noise — it poisons a specific entity's dossier with claims
  about another.

## Consequences

- (+) One concept governs actions and atoms; reviewers and prompts state a single rule
  ("name the entity or it does not bind").
- (+) Code-enforced at every tier — works with models that never emit the new field
  (detection), degrades visibly when text names nothing (journal event).
- (+) Recall precision becomes a function of finding quality, which the verify hook
  actively improves.
- (−) `Finding` schema change → prompt schema injection changes → every replay cache
  re-records once (batched with the other improvement-wave prompt edits).
- (−) Substring detection has false positives on overlapping entity values (e.g. an IP
  that is a substring of another string in evidence) — accepted: matches are validated
  against alert entities only, and the declared path is preferred; revisit with
  tokenized matching if real collisions appear.
- (−) `_seed_memory` (eval prior_runs) and persist share the attribution path — eval
  seeds must be updated to declare entities explicitly.
