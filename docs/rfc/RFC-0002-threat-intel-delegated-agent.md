---
id: RFC-0002
title: Threat Intel delegated agent — IOC enrichment mini-loop
status: accepted
owner: baodq97
date: 2026-06-06
---

# RFC-0002 — Threat Intel delegated agent

Parent: PRD-0001 (bonus 1 — second specialized agent), US-0005. Builds on RFC-0001
(§Core loop seams, §Run journal) and ADR-0005 (untrusted-context properties).

## Summary

A specialized **Threat Intel (TI) agent** enriches external IOCs (public IPs, domains,
hashes) during an investigation: a delegated mini-loop with its own prompt and its own
read-only TI tools, invoked from the primary loop when an external IOC Entity appears,
returning one schema-validated `TIReport` that the primary loop consumes as a single
Observation. The verdict then reflects multi-source intelligence one shallow
`check_reputation` call cannot gather (US-0005). Delegation is **purely additive**:
disabled by config, the primary loop completes unchanged.

## Decision

```
EXECUTOR step → entity is an external IOC? ──no──→ normal tool call
                     │ yes (and TI enabled)
                     ▼
        TI MINI-LOOP (agent: "threat-intel")
          own prompt (prompts/threat_intel.md)
          own read-only TI tools (fixture-backed):
            multi-source reputation · passive-DNS · threat-feed
          → structured TIReport (Pydantic, schema-validated)
                     │
                     ▼
        primary loop consumes TIReport as ONE Observation
        (untrusted-labeled, ADR-0005 property 4) → REASONER decides next
```

- **Trigger:** delegation fires **only** for external IOC entities — public IP /
  domain / hash, classified deterministically in code (private/internal ranges and
  org-internal identifiers never trigger it). The reasoner sees the TI result as an
  observation and may revise the plan or conclude (US-0005 AC: the TI result observably
  influences the next decision).
- **TI mini-loop:** same architectural pattern as the primary loop at smaller scale —
  its own prompt file, its own bounded step budget, the same `LLM` port, the same
  retry/repair policy (RFC-0001 §LLM boundary). TI tools are **read-only** and
  fixture-backed (`FixtureDataSource` extension or sibling TI fixture world), matching
  RFC-0001's read-only mid-loop rule (ADR-0005 property 3).
- **`TIReport` contract:** a strict Pydantic model validated **before** the primary
  loop consumes it; consumed as untrusted context with the same delimit-and-label wrap
  as alert payload and recall (ADR-0005 properties 1 & 4). A TI failure (tool miss, LLM
  error, validation failure) degrades to an `ok=false` Observation — a TI fault never
  crashes the primary Run.
- **Journal:** delegated events reuse the existing journal `agent` field — primary
  events stay `agent: "triage"`, TI events are tagged `agent: "threat-intel"`, giving
  a readable hierarchical trace in one journal stream (single-writer posture from
  RFC-0001 §Run journal is preserved; the TI loop emits through the same Run's journal).
- **Config:** an env knob (same pattern as `MAX_STEPS` / `MEMORY_SYNTHESIZE_EVERY_N_RUNS`)
  enables/disables delegation; default off ⇒ zero behavior change, existing replay
  caches stay valid (absent-by-default, the L3 posture precedent).
- **Eval:** TI behavior is covered by FakeLLM tests under `make check` (US-0005 AC) and
  at least one golden case exercising delegation end-to-end once recorded; existing
  34-case suite must stay green with TI disabled.

## Alternatives considered

- **Just add more reputation tools to the primary registry** — rejected: it widens the
  primary loop's tool surface and prompt for every run, while the bonus explicitly
  rewards a *second specialized agent* with its own reasoning context; a TI mini-loop
  keeps IOC expertise (and its token cost) out of runs that have no external IOC.
- **A fully independent TI service with its own journal** — rejected for this scope:
  two journals break the single-writer audit posture and the resume contract;
  tagging `agent:` inside one stream gives the hierarchical trace at zero new
  infrastructure.
- **LLM-decided delegation (the reasoner chooses when to delegate)** — rejected as the
  trigger: an injected alert could then steer delegation itself (ADR-0005 threat).
  The external-IOC classifier is deterministic code; the reasoner only consumes the
  result. Revisit if delegation targets multiply.

## Impact / rollout

One wave on top of the shipped system: TI models + classifier → TI tools/fixtures →
TI mini-loop + prompt → executor integration (trigger + observation consumption) →
journal tagging → tests + golden case → README/conventions sync. Cut line: the feature
is a stretch (US-0005) — core + eval are never sacrificed; if cut, this RFC stays
`draft` and nothing in the shipped system changes (delegation is additive and
default-off).

## Open questions

- TI mini-loop budget: fixed small step cap (e.g. 3) vs config knob — propose fixed
  cap first, knob only if a real need appears.
- Does the TI agent get its own memory (TI atoms) or stay stateless? Propose stateless
  v1 — recall/posture already carry entity history.
- Golden-case recording: one TI-enabled case (new cache) vs a TI-enabled re-record of an
  existing IOC-bearing case — decided at implementation by replay-cache economics.

## Security & operational risks

- TI tool outputs are attacker-influenceable in production (threat feeds ingest hostile
  data) — `TIReport` is consumed under the full ADR-0005 containment set: schema
  validation in code, untrusted labeling, read-only tools, and the unchanged
  verdict-side invariants (target-entity, risk policy, gate).
- Deterministic IOC classification keeps the delegation trigger out of LLM reach
  (no injection-steered delegation).
- Token/latency cost: a TI delegation adds one mini-loop of LLM calls to IOC-bearing
  runs only; bounded by the TI step cap.
