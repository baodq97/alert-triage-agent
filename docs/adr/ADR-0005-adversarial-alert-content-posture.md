---
id: ADR-0005
title: Adversarial alert content posture — prompt-injection containment
status: accepted
owner: baodq97
date: 2026-06-05
---

# ADR-0005 — Adversarial alert content posture

Parent: RFC-0001 (§Security & operational risks).

## Context

Alert content is attacker-controlled input: `description` and every value in `entities`/`context` reach the LLM in the same channel as the agent's instructions, making each alert an indirect prompt-injection vector (OWASP LLM01). Published attacks on AI SOC analysts suppress escalation 20–68% via persona hijack and reach 96% via context manipulation — corrupting exactly this agent's verdict surface. Fixture World ships benign data, but the roadmap connectors (Splunk, VirusTotal, Okta, CMDB) ingest hostile input — "mock data" retires the exercise's input, not the product's threat.

## Decision

Four structural containment properties, cheap enough to hold from wave-1 code:

1. **Separation:** every prompt template delimits and labels untrusted alert payload apart from instructions — a generic wrap, no per-event-type schema (consistent with RFC-0001's rejected alternatives).
2. **Deterministic verdict validation:** `Verdict.severity` is enum-checked, actions pass the RiskPolicy allowlist, and a targeted response action must reference an entity present in the alert (target-entity invariant) — enforced in code, never by LLM judgment.
3. **Read-only mid-loop:** the executor calls only read-only investigation tools; mutations (`block_user`) exist solely in the post-verdict gate flow.
4. **Untrusted recall:** memory injected at planning time is labeled like raw payload, carries source run-id + confidence, and is capped top-N — a poisoned finding from run A cannot silently steer run B.

Out of scope (roadmap): adversarial golden cases, deeper injection hardening, connector-side sanitization.

## Alternatives considered

- **Input sanitization / filtering as primary defense** — rejected: filters chase an open-ended attack space and conflict with "unknown alerts must parse"; separation + output validation bound the blast radius instead.
- **Declaring injection fully out of scope (status quo)** — rejected: the product is positioned as a production-posture OSS worker; the threat is owned in the doc chain, not a README footnote.

## Consequences

- (+) The verdict surface is bounded by deterministic checks even under successful prompt manipulation.
- (+) Properties 1–4 are structural, not model-dependent — they survive model swaps (ADR-0002).
- (−) Delimiting is mitigation, not a security boundary: no guarantee against injection; residual risk accepted for v1, revisited with adversarial evals on the roadmap.
- (−) Small token overhead per prompt from wrapping/labeling.
