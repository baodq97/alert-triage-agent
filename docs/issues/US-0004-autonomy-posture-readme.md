---
id: US-0004
title: "Wave 4: watch mode, L3 threat posture, README"
status: done
owner: baodq97
date: 2026-06-05
priority: P1
---

# US-0004 — Wave 4: watch mode, L3 posture, README

Parent: RFC-0001 (§Runtime surfaces, §Memory L3), PRD-0001.

As a detection engineer, I want the agent to consume alerts autonomously from a drop folder and maintain an org-level threat posture, with a README that lets anyone run and extend the system, so the project stands as an OSS-ready product.

## Scope

`run.py --watch <dir>` + `--synthesize-posture` (on-demand L3 trigger), L3 posture synthesis (config cadence `MEMORY_SYNTHESIZE_EVERY_N_RUNS`, 0 = disabled, degradable to deterministic top-N), README, final QA sweep.

## Acceptance criteria
> **Scope note (2026-06-06, owner):** watch mode was cut per RFC-0001's sanctioned cut line ("watch-mode → README"); the README carries the design sketch. The recommend-and-hold watch AC moves with it. L3 posture, README, and the full-sweep QA shipped (PR #6).


- [ ] Dropping an alert JSON into the watched folder triggers a full autonomous run
- [ ] L3 posture brief regenerates per configured cadence and feeds planner recall; with no key/time, the deterministic fallback produces a usable brief
- [ ] README covers: what/why, architecture (+ diagram), setup, single-command run, assumptions (per PRD), evals, trade-offs & what-I'd-do-differently (router, LangGraph, connector roadmap, production HITL), requirements-traceability table
- [ ] No secrets anywhere in the repo; `.env.example` complete and in sync
- [ ] Full-sweep QA: `make check` + `make eval` + `npx govkit verify` all green
- [ ] Recommend-and-hold: a high-risk action in a watch-mode run never auto-executes — the run exits `awaiting_approval` (the watch adapter wires the resume-capable gate flow, not AutoGate's silent default-deny) and queues for a human `--resume --approve|--deny`
- [ ] `run.py --synthesize-posture` regenerates the L3 posture brief immediately, regardless of cadence — including when `MEMORY_SYNTHESIZE_EVERY_N_RUNS=0`
