---
id: US-0003
title: "Wave 3: eval harness (mandatory) + memory L1-L2 recall"
status: open
owner: TBD
date: 2026-06-05
priority: P0
---

# US-0003 — Wave 3: eval harness + memory L1–L2

Parent: RFC-0001 (§Eval, §Memory), PRD-0001 success metrics.

As the maintainer, I want behavioral evals over agent trajectories and entity-scoped memory recall, so that prompt changes are regression-tested and the agent gets sharper with every run.

## Scope

`evals/` (runner + 5 golden cases + replay mode), `memory/` (L1 finding atoms, L2 entity dossiers, entity-scoped recall into planner context).

## Acceptance criteria

- [ ] `make eval` runs the 5-case golden set (2 samples, unknown-event-type, benign, tool-failure) — all Tier-1 assertions pass
- [ ] Replay mode reruns evals key-free from recorded journals; a replay miss fails loudly
- [ ] Verdict findings persist as entity-keyed L1 atoms; L2 dossiers aggregate deterministically
- [ ] A second run mentioning a previously-flagged entity shows the prior finding in its planner context (visible in journal) — recall is entity-scoped, never the whole store
- [ ] Eval-runner and memory tests green under `make check`
