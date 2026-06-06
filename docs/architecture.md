# Architecture

How the alert-triage agent is built, how a run actually flows through it, and why
it is raw Python instead of an agent framework. This document expands the README's
architecture section; the normative decisions live in the doc chain
(RFC-0001/0002/0003, ADR-0001…0006).

---

## 1. The shape of the system

One transport-agnostic entry point:

```python
result = triage(alert, deps)   # src/triage/core.py
```

`TriageDeps` carries every port the run needs — LLM client, journal, tool registry,
data source, approval gate, risk policy, optional memory store. The CLI (`run.py`),
the eval runner, and every test construct the same `deps` object with different
implementations behind the same Protocols. Nothing in `src/triage/` imports `run.py`.

Dependency direction (enforced by review, visible in imports):

```
models.py  ←  everything (Pydantic contracts only, no logic imports)
journal / llm / tools / gate / rendering / attribution / verification   = leaves
planner / executor / verdict                                            = consumers
core.py                                                                 = orchestrator
```

The leaves never import each other's consumers; `verification.py` and
`attribution.py` import only `models` (plus the one shared matcher), which is what
lets the verify hook and the memory persist path share a single entity-matching
implementation without a dependency cycle.

## 2. Runtime flow — what one run does

```
alert JSON
  → Pydantic strict validation (Alert)
  → [optional] TI pre-steps: deterministic IOC classifier → threat-intel mini-loop
      (budget-free, journaled as agent="threat-intel", capped at 2 IOCs/run)
  → PLANNER (LLM): alert + entity-scoped memory recall → InvestigationPlan
  → EXECUTOR (ReAct loop, MAX_STEPS-bounded):
        pick step → validate args (args_schema) → tool call → Observation
        → REASONER (LLM): continue | revise_plan | conclude
        guards: repeat-call refusal, consecutive-miss notes (<guard_note>),
                no_progress backstop (K=6 consecutive ok=false),
                revise_exhausted (degenerate revisions)
  → VERDICT (LLM): observations → severity, findings(+related_entities),
        recommended_actions, confidence
        deterministic post-passes: zero-evidence confidence clamp,
        action-traceability filter
  → VERIFY HOOK (deterministic, RFC-0003): citation validity, confidence
        consistency, action traceability, entity coverage
        → journaled as verdict_verification
        → Phase 2 (VERIFY_REENTRY=true): on failure, one bounded re-plan with
          the gap note, verdict re-synthesized once
  → RiskPolicy classifies actions → ApprovalGate batches high-risk ones
        (CLI prompt / auto / deferred-to-resume)
  → MEMORY persist: each finding attributed to entities (ADR-0006) → L1 atoms;
        unattributable findings emit finding_unattributed, store nothing
  → result.json + journal.jsonl (every step above emitted as events)
```

Every box in that flow emits journal events; the journal is not a log *about* the
run, it **is** the run — resume rebuilds executor state purely from it (see §4).

### The reasoner's decision contract

The reasoner chooses one of three verbs after every observation, with explicit
gates (prompts/reasoner.md):

- **continue** — the queued plan is still right.
- **revise_plan** — supply one replacement step. Pivot rule: a failed lookup is a
  dead *path*, not a dead *question* — identity, activity logs, reputation, and
  asset context are four different routes to the same entity.
- **conclude** — allowed only after a coverage check: every alert entity either has
  an observation targeting it, a queued step, or every applicable tool family for
  it has failed. An aspect is "answered" only by an `ok: true` observation in the
  same question family.

Termination is always one of the value-preserving constants in
`src/triage/constants.py`: `completed`, `max_steps`, `no_progress`,
`revise_exhausted`, `error`, `awaiting_approval` — the executor owns the first
five, the gate owns the last.

## 3. The LLM boundary

One client (`llm.py`, ADR-0002): OpenAI-compatible chat completions. Provider,
base URL, and model are pure `.env` configuration — swapping DeepSeek/Ollama/vLLM
is not a code change.

Structured output is enforced in layers:

1. Prompt-instructed JSON schema (always), plus native `json_schema` response
   format when the provider supports it.
2. `_parse_into`: `json.loads` + Pydantic `model_validate`.
3. One repair re-prompt on malformed output (journaled as `llm_repair`), then fail.
4. Transport retries ×3 with exponential backoff (journaled as
   `llm_transport_retry`).

Model strictness is deliberate and asymmetric: contracts the LLM **produces**
(`Plan`, `Verdict`, `Finding`) are lax-validating (coerce, tolerate extras);
contracts only **we** produce (`ToolResult`, `GateDecision`, `RunResult`) are
strict/frozen — an internal contract violation should crash loudly in tests, an
LLM quirk should not crash a run.

Prompt rendering (`rendering.py`) is a shared seam: compact JSON dumps, 4000-char
truncation, `<observation>` tags with sanitized tool names (anti-injection,
ADR-0005), and an `{{END_OF_STABLE}}` split so the provider's prompt cache keeps
the stable prefix (system + alert) across the run's many reasoner calls.

## 4. Journal: event-sourced, resumable, single-writer

`journal.jsonl` is append-only JSONL, one event per line, monotonic `seq`
(ADR-0003). Event names and payload shapes are centralized in `constants.py`.

- **Resume** (`--resume [--approve|--deny]`): the journal is folded back into
  executor state — observations, step count, pending gate — and the loop re-enters
  through the same seam Phase-2 re-entry uses (`pre_observations` +
  `executor_pre_count` preserve the budget contract).
- **Delegated-agent awareness:** TI mini-loop events carry `agent="threat-intel"`;
  the rebuild folds only `agent="triage"` tool events into primary-loop state, so
  TI inner steps can never corrupt a resumed run's step numbering.
- **Verification audit:** every verdict's verify-hook outcome is journaled
  (`verdict_verification` — checks, failures, uncovered entities, action taken),
  which is also the telemetry that calibrated the hook (RFC-0003 §Phase-1
  measurement).

## 5. Memory: entity-attributed, three layers

- **L1 — finding atoms.** On persist, each finding is attributed to entities by
  ADR-0006's resolution order: declared `related_entities` (validated against the
  alert's entities ∪ context scalars) → deterministic text-scan fallback → if
  neither names an entity, persist nothing and journal `finding_unattributed`.
  The principle: *a persisted claim exists for an entity iff the claim names that
  entity.* This removed the old cartesian fan-out (277 → 108 atoms, −61% noise on
  the recorded suite).
- **L2 — entity dossiers.** Deterministic group-by over atoms (confidence/recency
  ranked, capped) — no LLM.
- **L3 — threat posture brief.** LLM synthesis on a cadence, with a deterministic
  top-N fallback so the path works key-free.

Recall is entity-scoped: the planner receives only dossiers for the alert's
entities, which is why precision improves rather than degrades as the store grows.

## 6. Verify hook: deterministic verdict grounding (RFC-0003)

Four checks run on every verdict — no LLM, no ground truth, only the run's own
trajectory:

| Check | Catches |
|---|---|
| Citation validity | findings whose evidence matches no called tool, no observed data value, no alert field, and no real failure citation |
| Confidence consistency | confidence outside the zero-evidence clamp band when every observation failed |
| Action traceability | targeted actions naming entities no finding covers (the canonical enforcement point — verdict synthesis delegates here) |
| Coverage | verdicts blind to *every* alert entity; partial gaps journal as telemetry without failing |

Phase 1 ran the hook in measure-only mode and used the measurements to calibrate
the checks (three deltas found and fixed — see RFC-0003 §Phase-1 measurement).
Phase 2 (`VERIFY_REENTRY=true`, both gates met: 0 false flags recorded, 8.6% live)
turns a failed hook into one bounded re-plan with the gap note before the verdict
is re-synthesized. The flag is the kill-switch.

## 7. Evals: the functional acceptance gate

Two tiers (US-0003/0007): Tier-1 blocking behavioral assertions over 35 golden
cases (trajectory + verdict ranges), Tier-2 advisory LLM judge (median-of-3,
anchored rubric) with per-case `judge_min` soft gates (exit 2, never blocks
Tier-1). Replay mode serves recorded responses keyed by prompt hash — key-free,
CI-safe, and loud on prompt drift (`ReplayMiss`). Current results live in the
README §Evaluation results and `docs/reports/`.

## 8. Why no agent framework (ADR-0001, expanded)

The decision: a ~100-line explicit state machine over a thin OpenAI-compatible
client. The reasons, in the order they actually mattered:

1. **The journal is the product.** Audit trail, resume, retry visibility, gate
   evidence, eval assertions, and the verify hook's calibration data all read the
   same append-only journal. Framework checkpointing (e.g. LangGraph's
   `SqliteSaver`) is an opaque state snapshot — it can restore a graph, but it
   cannot answer "which tool failed, with what error, before the verdict shipped?"
   without building a second, parallel record. Once the journal exists, the
   framework's main feature is redundant.
2. **The loop is the cheapest part.** Planner → executor → reasoner → verdict is
   ~100 lines of explicit control flow. The expensive parts — structured-output
   repair, replay-mode evals, entity attribution, deterministic verification,
   approval gating, resume — are domain mechanisms no framework ships. A framework
   would abstract the easy 5% and obstruct the hard 95%.
3. **Custom control flow at the seams.** The no-progress backstop counts *only*
   consecutive new ok=false observations (repeat-guard refusals don't count);
   Phase-2 re-entry enters the executor through the resume seam with a preserved
   budget; the gate can hold a run across process restarts. Each of these bends
   the loop's semantics in ways that fight a framework's fixed node/edge model
   and are trivial in first-party code.
4. **Observability without a vendor.** Framework tracing assumes its own UI
   (LangSmith et al.). Here the journal is greppable JSONL and the eval harness
   asserts on it directly.
5. **The trade we accepted:** retry/backoff, loop guards, and parsing are
   first-party code that must be tested — that's covered by the 100%-coverage gate
   (ADR-0004) and the reliability tests. We get no ecosystem free-rides; at this
   scope, there are none we need.

Revisit (per the ADR): durable multi-node execution, or a team standardizing on a
framework, would reopen the decision.

## 9. Where to look

| Question | Read |
|---|---|
| Product scope, success metrics | `docs/product/PRD-0001-*` |
| Core architecture decision record | `docs/rfc/RFC-0001-*`, `docs/adr/ADR-0001…0005` |
| TI delegated agent | `docs/rfc/RFC-0002-*` |
| Loop v2, verify hook, termination | `docs/rfc/RFC-0003-*`, `docs/issues/US-0008-*` |
| Entity attribution principle | `docs/adr/ADR-0006-*`, `docs/issues/US-0006-*` |
| Eval contract & judge soft gate | `docs/issues/US-0003-*`, `US-0007-*` |
| Latest measured quality | `docs/reports/2026-06-06-quality-loop-summary.md` |
