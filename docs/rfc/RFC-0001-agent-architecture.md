---
id: RFC-0001
title: Agent architecture — agentic core, run journal, memory, eval
status: accepted
owner: baodq97
date: 2026-06-05
---

# RFC-0001 — Agent Architecture

Parent: PRD-0001. Captures the design agreed during brainstorming (2026-06-05).

## Summary

A raw-Python autonomous triage agent with an explicit **Plan → ReAct + replan** loop, an OpenAI-compatible LLM boundary, an **event-sourced run journal** that simultaneously provides audit trail, retry capture, resume/recovery, and eval traces, a 4-level memory (journal → finding atoms → entity dossiers → threat posture), a config-driven HITL gate, and a two-tier eval harness. No agent framework.

## Decision

### Core loop (planning / execution / reasoning separated)

```
alert.json → validate → PLANNER (LLM: structured InvestigationPlan)
           → EXECUTOR (ReAct loop, max_steps guard):
               pick step → tool call → observation → REASONER (LLM: continue | revise plan | conclude)
           → VERDICT (LLM structured output: severity, findings[], recommended_actions[], confidence)
           → RiskPolicy → high-risk actions → ApprovalGate → execute | record denial
```

- **Alert contract:** Pydantic envelope (6 typed fields: `alert_id`, `timestamp`, `source`, `severity_hint`, `event_type`, `description`) + `entities`/`context` as pass-through dicts. New event types parse without code changes; the planner reads whatever keys exist. Strict per-event-type schemas were **rejected** — they reintroduce the hardcoding the exercise forbids.
- **LLM boundary:** the `openai` SDK as the single wire format; provider, base URL, and model are env config (`LLM_BASE_URL`, `LLM_MODEL`). Swapping in DeepSeek/Ollama/vLLM is configuration, not code (covers the local-model bonus). Retries ×3 with exponential backoff, per-call timeout, one repair attempt on malformed structured output.
- **Tools:** `ToolRegistry` of `Tool` (name, JSON schema, `risk_tier`) over a `DataSource` interface — **read-only investigation tools only** (`lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`); the executor can never mutate state mid-loop. `block_user` is a **response action**, executed exclusively in the post-verdict gate flow (decided 2026-06-05). The exercise ships `FixtureDataSource` — a consistent fixture world (the same entity tells the same story across every tool). Real connectors (Splunk, VirusTotal, Okta, CMDB) are an OSS roadmap item, interface-ready but explicitly not built.
- **HITL:** `RiskPolicy` is a config file mapping actions to risk tiers (unclassified ⇒ high-risk). `ApprovalGate` is a Protocol with two implementations: `CLIGate` (interactive) and `AutoGate` (policy-driven, default-deny — CI/headless). Production surfaces (ticket comment, Slack) are roadmap.

### Run journal (one mechanism, four jobs)

Append-only JSONL per run (`runs/<run_id>/journal.jsonl`): `run_started`, `llm_call` (model, tokens, latency, prompt hash), `plan_created`, `tool_called` (per attempt), `tool_result`, `gate_requested`, `gate_decision`, `verdict`, `run_terminated`.

1. **Audit trail** — every call captured, tamper-evident ordering (`seq`)
2. **Retry visibility** — each attempt is an event; transient tool errors retry with backoff, permanent errors return to the agent as observations (it adapts or concludes with lower confidence; never crashes)
3. **Resume/recovery** — `run.py --resume <run_id>` rebuilds state from the journal and continues from the last incomplete step; completed steps are never re-run (LLM calls are non-deterministic). Approval flow rides on this: a pending gate exits as `awaiting_approval`; `--resume --approve|--deny` completes the run
4. **Eval trace** — assertions read the journal directly; no extra instrumentation

### Memory (L0→L3, mirrors tencentdb-agent-memory)

| Level | Artifact | Mechanism |
|---|---|---|
| L0 | Run journals | already exists |
| L1 | Finding atoms (entity-keyed facts from verdicts) | persisted at verdict time — findings are the atoms |
| L2 | Entity dossiers (per IP/user/asset history) | deterministic group-by, no LLM |
| L3 | Threat posture (org-level brief) | config-driven cadence (`MEMORY_SYNTHESIZE_EVERY_N_RUNS`, 0 = disabled) + on-demand CLI trigger; degradation path: deterministic top-N summary |

Recall is **entity-scoped**, not a monolithic blob: alert entities → matching atoms/dossiers + L3 brief (~hundreds of tokens) into the planner context. A repeat offender IP measurably sharpens the second run's plan.

### Eval (two tiers, mirrors govkit's gate/eval split)

- **Tier 1 — blocking behavioral assertions:** golden cases (`evals/cases/*.yaml`) assert on trajectory (must-call tools, gate-before-high-risk, max-steps respected, no repeated identical calls) and verdict (severity range, entities referenced, confidence floor, schema validity). Ranges, not exact matches — LLM output varies.
- **Tier 2 — advisory LLM judge:** scores reasoning quality from the trace; tracked as trend, never blocks.
- Golden set: 2 sample alerts + 1 unknown event type + 1 benign (false-positive discipline) + 1 tool-failure. Prompts live in `prompts/*.md` files; `make eval` is the regression gate for any prompt change. Replay mode (cached LLM responses from journals) keeps CI key-free.

### Runtime surfaces

`triage(alert, deps)` is transport-agnostic. Adapters: CLI one-shot (`python run.py --alert …`, satisfies single-command run), watch mode (`--watch dir/` — autonomous folder ingestion), resume (`--resume <id> [--approve|--deny]`). Queue/webhook consumers are roadmap.

## Alternatives considered

- **LangGraph** — rejected. Its checkpointing is an opaque state snapshot rather than an audit-grade journal, tracing assumes LangSmith, and it would replace only the cheapest part of the system (the ~100-line loop) while hiding the architecture skill the rubric weighs at 30%. Revisit when durable multi-node execution or team standardization matters; recorded in the README trade-offs.
- **Workflow/playbook router** (standardized lanes for known event types, agentic fallback) — rejected for this scope. It optimizes token cost, which the exercise does not grade, and a predefined tool sequence directly violates "use output from one tool to decide what to do next". Kept as a production roadmap note.
- **Strict per-event-type alert schemas** — rejected; adapting to new alert types would require code changes, which the exercise explicitly forbids.
- **Full pause/resume HITL as a bespoke subsystem** — originally deferred as too costly; **reinstated cheaply** once the journal existed, since resume falls out of event-sourcing.

## Impact / rollout

4-day plan: D1–2 core (models, llm, planner, executor, tools, gate, verdict) + the 3 required tests · D2–3 journal + retry + resume · **D3 eval harness (mandatory — the functional acceptance gate, local `make eval` with replay mode)** + memory L0→L2 + entity-scoped recall · D4 L3 (degradable) + watch mode + README. Each cut line keeps a submittable artifact: core alone satisfies every hard requirement; journal and memory stack on top in risk order. Eval is **not** on the cut list — features that cannot pass their golden cases do not ship.

## Open questions

- ~~Execute-after-approval vs recommend-only~~ — **resolved 2026-06-05: approved actions execute immediately** (PRD assumption 1)
- ~~Gate topology: how many approval gates?~~ — **resolved 2026-06-05: one gate.** A single gate point after verdict batches all high-risk actions into one approval request. Per-action and tiered gates (approver level scales with risk tier / blast radius) stay on the roadmap — the `ApprovalGate` Protocol is the extension seam.
- ~~L3 synthesis cadence (every N runs vs on-demand)~~ — **resolved 2026-06-05: configuration-driven.** Cadence is config (e.g. `MEMORY_SYNTHESIZE_EVERY_N_RUNS`, `0` = disabled), plus an explicit on-demand trigger (CLI flag) — the same knob pattern as `MAX_STEPS`.
- ~~Whether eval replay mode ships in v1 or README-only~~ — **resolved 2026-06-05: the eval harness is a MANDATORY v1 deliverable and runs locally** (`make eval`). It is the functional acceptance gate — no submission without the golden set passing. Replay mode (cached LLM responses from journals) ships with it so eval runs deterministically and key-free; live mode remains for grading prompt changes.

## Security & operational risks

- Adversarial alert content (prompt injection via `description` and any `entities`/`context` value) is a real product threat: containment posture is recorded in **ADR-0005** (separation, deterministic verdict validation, read-only mid-loop, untrusted recall). Fixture World data is benign; roadmap connectors ingest hostile input.
- The journal contains investigation data — `runs/` is gitignored; production would need retention/PII policy.
