---
id: US-0002
title: "Wave 2: run journal — audit trail, retry visibility, resume"
status: open
owner: baodq97
date: 2026-06-05
priority: P0
---

# US-0002 — Wave 2: run journal, audit trail, resume

Parent: RFC-0001 (§Run journal), ADR-0003.

As a security engineer, I want every agent action captured in an append-only journal and interrupted runs to be resumable, so that investigations are auditable and survive stops, crashes, and approval pauses.

## Scope

`journal.py` (emit + rebuild for resume), retry instrumentation in `llm.py`/`tools/`, `run.py --resume <run_id> [--approve|--deny]`.

## Acceptance criteria

- [ ] Every run writes `runs/<run_id>/journal.jsonl` covering all event types in the conventions schema (LLM calls with tokens/latency, every tool attempt, gate events, verdict, termination)
- [ ] A transient tool failure shows attempt 1 (error) + attempt 2 (retry) as separate journal events
- [ ] Kill the process after step 2 → `--resume <run_id>` completes the run without re-executing recorded steps → verdict produced
- [ ] Pending approval exits as `awaiting_approval`; `--resume --approve` executes the action, `--deny` records and concludes
- [ ] Journal resume/rebuild test green under `make check`
- [ ] On `--resume --approve`, a high-risk action executes only if no `action_executed` event exists for it (check → execute → record); killing the process between execute and record never double-executes on the next resume
