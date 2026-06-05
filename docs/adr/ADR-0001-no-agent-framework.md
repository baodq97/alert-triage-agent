---
id: ADR-0001
title: Raw Python agent loop — no agent framework
status: proposed
owner: TBD
date: 2026-06-05
---

# ADR-0001 — Raw Python agent loop, no agent framework

Parent: RFC-0001.

## Context

The requirements allow any agentic framework (LangGraph, LangChain, CrewAI, or raw code). The evaluation rubric weighs agent architecture at 30% — "clean separation of planning, tool execution, and reasoning; not a linear script". The design needs an audit-grade run journal, journal-driven resume, and eval assertions that read the trajectory.

## Decision

Implement the agent loop in raw Python (~100-line explicit state machine) on top of a thin OpenAI-compatible client. No agent framework dependency.

## Alternatives considered

- **LangGraph** — gives StateGraph, checkpointing (`SqliteSaver`), `interrupt()` for HITL. Rejected: its checkpoints are opaque state snapshots rather than a readable, append-only audit journal; tracing assumes LangSmith; and it would replace only the cheapest part of the system (the loop) while hiding the separation-of-concerns evidence the rubric grades. Revisit when durable multi-node execution or team standardization matters.
- **CrewAI / LangChain agents** — higher-level abstractions, weaker fit for a custom journal/eval contract; rejected for the same observability reasons plus heavier dependency surface.

## Consequences

- (+) Journal, resume, gate, and eval integrate directly with the loop — one mechanism, no adapter layers.
- (+) Architecture skill is demonstrable in first-party code; model swap stays pure configuration.
- (−) Retry/timeout/backoff and loop guards are first-party code — they must be tested (covered by the required reliability tests).
- (−) No ecosystem free-rides (tracing UIs, prebuilt tools); acceptable at this scope.
