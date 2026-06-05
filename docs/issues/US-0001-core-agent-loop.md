---
id: US-0001
title: "Wave 1: core agent loop — alert in, verdict out, gated actions"
status: open
owner: TBD
date: 2026-06-05
priority: P0
---

# US-0001 — Wave 1: core agent loop

Parent: RFC-0001 (§Core loop), ADR-0001..0003.

As a SOC analyst, I want the agent to investigate any alert JSON end-to-end and produce a structured verdict, so that routine triage needs no human until a high-risk action requires my approval.

## Scope

`models.py`, `llm.py`, `tools/` (registry + 5 tools + fixture world), `planner.py`, `executor.py`, `gate.py`, `verdict.py`, `prompts/*.md`, `run.py --alert`, the 3 required tests.

## Acceptance criteria

- [ ] `python run.py --alert alerts/ALT-2026-04-7821-data-exfiltration.json` produces a verdict (severity, findings, recommended_actions, confidence) via ≥1 real LLM call
- [ ] Both sample alerts AND an unknown `event_type` alert produce sensible plans with zero code changes (no `event_type` branching anywhere)
- [ ] Each tool result observably influences the next step (plan revision or conclusion visible in output)
- [ ] High-risk action (e.g. `block_user`) pauses for approval: CLIGate prompts interactively; AutoGate default-denies; approved → executes, denied → recorded, verdict still ships
- [ ] `MAX_STEPS` (default 15) breach terminates gracefully with a partial verdict
- [ ] Tool error returns as an observation — run never crashes
- [ ] Tests: tool call, approval gate (deny path), tool-error edge case — all green under `make check`
