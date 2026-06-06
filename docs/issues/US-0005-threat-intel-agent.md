---
id: US-0005
title: "Stretch: Threat Intel Agent — delegated IOC enrichment"
status: in-progress
owner: baodq97
date: 2026-06-05
priority: P2
---

# US-0005 — Stretch: Threat Intel Agent collaboration

Parent: RFC-0001 (§Core loop), ADR-0005. Claims requirements bonus 1 (second specialized agent).

As a SOC analyst, I want external IOCs (public IPs, domains, hashes) enriched by a specialized Threat Intel agent during the investigation, so that the verdict reflects multi-source intelligence one shallow reputation call cannot gather.

**Stretch story:** implement only if D4 has slack — core + eval are never sacrificed for this bonus.

## Scope

A TI mini-loop (own prompt; own read-only TI tools: multi-source reputation, passive-DNS fixture, threat-feed fixture) invoked by the reasoner when an external IOC Entity appears; returns a structured `TIReport` consumed as one Observation. Journal events tagged `agent: "threat-intel"`.

## Acceptance criteria

- [ ] Delegation fires only for external IOC entities (public IP / domain / hash); internal entities never trigger it
- [ ] `TIReport` is schema-validated before the primary loop consumes it, and consumed as untrusted context (ADR-0005 property 4 labeling)
- [ ] The journal shows a readable hierarchical trace: primary events `agent: "triage"`, delegated events `agent: "threat-intel"`
- [ ] The TI result observably influences the next reasoner decision (plan revision or conclusion)
- [ ] With the TI agent disabled (config), the primary loop completes unchanged — delegation is purely additive
- [ ] TI-loop tests green under `make check` (FakeLLM, no live key)
