---
id: ADR-0003
title: Event-sourced JSONL run journal as the single runtime record
status: accepted
owner: baodq97
date: 2026-06-05
---

# ADR-0003 — Event-sourced JSONL run journal

Parent: RFC-0001.

## Context

Four needs point at runtime state: an audit trail of every LLM/tool call, retry visibility, stop/resume/recovery (including the approval pause), and an eval harness that asserts on agent trajectories. Solving each separately means four mechanisms to build and keep consistent.

## Decision

One append-only JSONL journal per run (`runs/<run_id>/journal.jsonl`) is the single runtime record. Every LLM call, plan, tool attempt, gate event, and verdict is an ordered event (`seq`). Resume rebuilds state from the journal — completed steps are never re-executed (LLM calls are non-deterministic; recorded results are reused). A step counts as completed only when its result event is written; a started step with no recorded result is the single re-entry point on resume; a torn final JSONL line is discarded. The approval flow rides on it: a pending gate exits as `awaiting_approval`; `--resume --approve|--deny` completes the run. Eval assertions read the journal directly.

## Alternatives considered

- **Framework checkpointing (LangGraph SqliteSaver)** — opaque snapshots; satisfies resume but not audit-grade readability or eval consumption. Rejected with ADR-0001.
- **Plain logging + separate state file** — two mechanisms that drift; logs alone cannot rebuild state. Rejected.
- **SQLite event store** — same model, heavier surface for a 4-day scope; JSONL is diffable, greppable, and reviewer-readable. Revisit for production retention/query needs.

## Consequences

- (+) One write path feeds audit, reliability evidence, resume, the HITL pause, and eval traces.
- (+) Replay mode gives key-free CI eval runs (cached LLM responses keyed by prompt hash).
- (−) Journal schema is a load-bearing contract: a renamed field breaks replay and evals together — schema lives in `triage-conventions` and QA checks emitter/reader lockstep.
- (−) Single-writer assumption (no concurrent runs on one run_id); acceptable, documented.
- (−) `seq` gives ordering, not tamper-evidence — a writer with access to `runs/` can renumber undetectably; per-entry hash-chaining (`prev_hash`) is a roadmap item for a future ADR.
