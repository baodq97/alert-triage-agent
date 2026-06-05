---
id: PRD-0001
title: Autonomous security alert triage agent
status: approved
owner: baodq97
date: 2026-06-05
---

# PRD-0001 — Autonomous Security Alert Triage Agent

Source requirements: [`docs/requirements.md`](../requirements.md).

## Problem

Security teams receive alerts (SIEM, CloudTrail, API gateways) faster than humans can investigate them. Each alert needs the same expensive loop: pull context about the user, query logs, check reputations, assess the asset — then decide severity and response. The exercise simulates this: build an autonomous agent that investigates a security alert end-to-end and produces an actionable verdict, while keeping a human in control of any high-risk response action.

The product is positioned as an **autonomous worker on an event/ticket stream**: most alerts resolve zero-touch; only high-risk actions pause for human approval.

## Persona / audience

- **Primary (exercise):** the technical reviewer — runs the agent with a single command against the two sample alerts plus their own variations, and reads the code/README against the published rubric.
- **Product persona:** a SOC analyst (L1/L2) who consumes verdicts and approves/denies gated actions; a detection engineer who adds alert sources and tools without touching agent logic.

## Scope

In scope (hard requirements from the exercise):

1. Receive an alert as JSON (stable envelope; `entities`/`context` payloads vary by event type)
2. Plan an investigation via LLM reasoning — **not hardcoded**; new event types adapt without code changes
3. ≥3 mock tools returning realistic stubbed data (`lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`), plus `block_user` as the gated **Response Action** (post-verdict only — never an investigation tool)
4. Chain reasoning: each tool output feeds the decision about the next step
5. Structured verdict: severity, findings, recommended actions, confidence
6. Human-in-the-loop gate before any high-risk action
7. Python 3.11+, ≥1 real LLM API call, configurable max steps (default 15) with graceful termination, ≥3 tests (tool call / approval gate / tool error), README + `.env.example` + `pyproject.toml`, no secrets in repo, single-command run

Product-grade additions (differentiators, in scope):

- **Run journal** — append-only audit trail of every LLM call, tool call, retry, and gate decision; doubles as resume/recovery state and eval trace
- **Memory L0→L3** — runs feed finding atoms → entity dossiers → threat posture, so the agent gets smarter across runs (exercise bonus)
- **Two-tier eval** — deterministic behavioral assertions on trajectories + advisory LLM judge, so prompt changes are regression-tested
- **Autonomous adapters** — CLI one-shot and watch-mode folder ingestion
- **Threat Intel Agent (stretch — claims exercise bonus 1)** — a delegated specialist mini-loop for external IOCs returning a structured TIReport as one Observation (US-0005); core + eval are never sacrificed for it

### Non-goals

- Real integrations (SIEM/IdP/TI connectors) — interface ready, README roadmap only
- HTTP server, queue consumers, Slack/Jira approval surfaces — README roadmap only
- Workflow/playbook router for known alert patterns — deliberately excluded (conflicts with the "not hardcoded" requirement); recorded as a trade-off in the README

## Success metrics

- **Rubric coverage (primary):** every weighted area of the published evaluation rubric has a dedicated, demonstrable artifact — architecture 30% (module separation), reliability 25% (retry/timeout/guardrails visible in the journal), reasoning 20% (readable trace), code 15%, docs 10%. Target: 100% of hard requirements verifiably met (a requirements-traceability section in the README maps each to code/tests).
- **Behavioral eval pass rate:** 100% of blocking assertions pass on the golden set (2 sample alerts + 1 unknown event type + 1 benign + 1 tool-failure + 1 benign-after-flagged case) before submission.
- **Zero-touch rate (product KPI):** on the golden set, 100% of runs without high-risk actions complete with no human input; 0 high-risk actions execute without an approval event in the journal.
- **Adaptability:** an alert with a never-seen event type produces a sensible plan and verdict with 0 code changes.

## Assumptions

1. **Decided (2026-06-05):** the agent **executes** mock containment actions immediately after approval; denial is recorded and the verdict still ships.
2. The reviewer grades with their own LLM key — therefore the LLM client is OpenAI-compatible and provider choice is pure configuration (`.env`).
3. "High-risk" classification is owned by a config-file risk policy, defaulting to conservative (unclassified = high-risk) — not by code or by the LLM.
4. **Decided (2026-06-05): one approval gate per run.** All high-risk actions in a verdict pass through a single gate point before execution, batched into one approval request. Per-action approval and tiered gates (approver level by action reversibility, blast radius, and AI confidence) are roadmap items behind the `ApprovalGate` extension seam.

## Open questions

- None — all design questions raised during brainstorming were resolved on 2026-06-05 (see RFC-0001 § Open questions for the decision log). New questions land here as they appear.
