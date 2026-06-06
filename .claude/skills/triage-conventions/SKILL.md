---
name: triage-conventions
description: The single source of conventions for implementing alert-triage-agent — module map, journal event schema, alert/verdict contracts, prompt-file rules, risk policy format, env vars, naming. MUST be read before writing or reviewing ANY code in src/triage/, tests/, prompts/, evals/, or fixtures. Also use when checking code against RFC-0001, resolving "where does this go" questions, or auditing contract drift between modules.
---

# triage-conventions

Distilled from RFC-0001 (`docs/rfc/RFC-0001-agent-architecture.md`). If this file and the RFC conflict, the RFC wins — report the drift, don't silently pick one.

## Module map (who owns what)

```
run.py                      # entry/adapters: --alert <file> | --watch <dir> | --resume <run_id> [--approve|--deny]
src/triage/
├── models.py               # Alert, InvestigationPlan, PlanStep, Finding, Verdict, ToolResult, GateDecision (Pydantic)
├── core.py                 # triage(alert, deps) -> RunResult — transport-agnostic core flow; TriageDeps container; target-entity invariant
├── llm.py                  # OpenAI-compatible client: retry ×3 exp backoff, timeout, 1 repair attempt on bad structured output
├── planner.py              # alert (+ memory recall) → InvestigationPlan  (LLM, structured)
├── executor.py             # ReAct loop: step → tool → observation → reason (continue|revise|conclude); max-steps guard; repeat-call guard
├── journal.py              # append-only JSONL emit + rebuild state for resume
├── gate.py                 # RiskPolicy (YAML config) + ApprovalGate Protocol + CLIGate + AutoGate
├── verdict.py              # findings → structured Verdict (LLM)
├── rendering.py            # shared LLM-facing rendering primitives (leaf — no journal calls, no LLM calls):
│                           #   truncate, dump_compact, dump_alert, split_stable_dynamic,
│                           #   observation_tag (with tool-name attribute sanitization), journal_llm_callbacks.
│                           #   Rule: rendering helpers live here; journal keeps full data.
├── memory/                 # L1 atoms, L2 dossiers, L3 posture; entity-scoped recall
├── tools/                  # registry.py (4 read-only investigation tools), base.py (Tool + DataSource Protocol),
│                           # actions.py (response actions: block_user — post-gate only), fixture_source.py, fixtures/*.json
└── evals/                  # runner.py, cases/*.yaml (one dir, 34+ golden cases), assertions.py, replay.py, judge.py
prompts/*.md                # ALL LLM prompts (planner.md, reasoner.md, verdict.md, judge.md)
tests/test_{module}.py
alerts/*.json               # sample inputs
runs/<run_id>/              # runtime artifacts (gitignored): journal.jsonl (append-only event stream),
                            # result.json (versioned run record), alert.json (input copy — resume rebuilds without the original path)
```

Dependency direction: `models` ← everything; `journal`/`llm`/`tools`/`gate`/`rendering` are leaves consumed by `planner`/`executor`/`verdict`; nothing imports `run.py`. The core entrypoint `triage(alert, deps)` is transport-agnostic — adapters live only in `run.py`.

**Where does this go?** LLM-facing text transformations (truncation, compact JSON serialization, observation tag generation, prompt splitting, callback factories) live in `rendering.py`. Callers (`planner`, `executor`, `verdict`) import from there; they never re-implement these primitives. Journal *data* (full un-truncated payloads) stays in journal events — rendering may truncate for the *prompt* only.

## Alert contract

Typed envelope (required): `alert_id`, `timestamp`, `source`, `severity_hint`, `event_type`, `description`. **`severity_hint` is a free `str`** (required, non-empty, NOT an enum — upstream systems vary and unknown alerts must never fail validation at the door); only the agent's own `Verdict.severity` is the strict enum. Flexible payload: `entities: dict[str, Any]`, `context: dict[str, Any]` — passed through to the LLM untouched. **Never** branch on `event_type` in code; never define per-event-type schemas. Unknown event types must parse and plan without code changes.

## Investigation tools vs response actions (decided 2026-06-05)

- The `ToolRegistry` exposes **read-only investigation tools only**: `lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`. The executor can never mutate anything mid-loop.
- **`block_user` is a Response Action, not an investigation tool.** It is never callable by the executor; it executes only in the post-verdict flow: Verdict → RiskPolicy → Approval Gate → approved → execute (mock), denied → recorded. One gate per run.
- This makes the eval assertion `gate_before_high_risk` structurally sound: a high-risk `action_executed` event without a preceding `gate_decision(approved)` is impossible by construction, not by prompt discipline.
- **Target invariant:** `block_user` (and any targeted response action) must reference an entity present in the alert envelope/payload; a verdict whose action target is not an alert entity is rejected before the gate (`action_rejected`). The invariant applies to **targeted** actions only (`TARGETED_ACTIONS` in `tools/actions.py`): an untargeted recommendation (e.g. an advisory `notify_soc`) passes through to the RiskPolicy/gate untouched — a capability fact never decides whether a human sees a recommendation. An approved action with no registered executor is recorded as `action_skipped`, never executed and never a crash (decided 2026-06-05, wave-1 QA).
- `Tool` carries descriptive `risk_tier` metadata (RFC-0001 §Tools — all four investigation tools are `"read_only"`); it is planner-facing description only. RiskPolicy classifies `Action.name`, never tools.

## Verdict contract

`severity` (enum: `low|medium|high|critical`), `findings: list[Finding]` (each cites the tool observation it came from), `recommended_actions: list[Action]`, `confidence: float 0–1`, plus `terminated_reason` when ended early (max-steps, fatal error). Partial verdicts on graceful termination are mandatory — never exit without a verdict.

`Action = {name, params?, description?}`. `RiskPolicy` classifies on exact `Action.name` match; unmatched names default to high-risk.

**Severity / confidence decoupling contract:** severity rates the *threat pattern's potential impact if true*; confidence rates the *quality of gathered evidence*. They are independent axes. A high-severity verdict with low confidence is CORRECT calibration for an unverifiable threat — it is never a miscalibration. Case authors and the judge must apply this:

- `_clamp_by_evidence` (binary contract): when `ok_count == 0` (every tool returned `ok=False`), confidence is clamped to `[0.30, 0.40]` and all recommended actions are stripped. When `ok_count >= 1`, the LLM calibrates freely — no clamp applies.
- `_filter_traceable_actions` (quality heuristic, NOT a security boundary): for targeted actions (those in `TARGETED_ACTIONS`), at least one string param value must appear as a case-insensitive substring in some finding statement or evidence. Actions that fail this check are dropped and logged as `action_dropped_untraceable`. Untargeted advisory actions (e.g. `notify_soc`) are always passed through unchanged. This backstop drops ungrounded hallucinations; it does not defend against adversarial alert payloads (the actual security boundary is the target-entity invariant at the gate).

## Journal event schema

One JSON object per line, append-only, never mutated. Common fields: `seq` (monotonic int), `event_id` (uuid — adapters bind to ids, not log positions), `ts` (ISO-8601), `event`, `agent` (`"triage"` default; `"threat-intel"` for the US-0005 delegated loop). Event types and their payload fields:

| event | payload |
|---|---|
| `run_started` | `alert_id`, `config`, `schema_version` |
| `llm_call` | `purpose` (plan/reason/verdict/judge), `model`, `prompt_hash`, `tokens`, `latency_ms` |
| `plan_created` / `plan_revised` | `steps` |
| `tool_called` | `step`, `tool`, `args`, `attempt` |
| `tool_result` | `step`, `attempt`, `ok`, `data` \| `error` |
| `llm_transport_retry` | `purpose`, `attempt` (1-based, matches the retry counter), `error` (string) — fired before each sleep in the retry loop; journaled via `journal_llm_callbacks` from `rendering.py` |
| `llm_repair` | `purpose`, `error` (string, truncated to 500 chars before journal emit) — fired once when the one-repair-attempt fires on malformed structured output |
| `action_rejected` | `action`, `reason` — PRE-gate only: target-entity invariant ("missing required target" \| "target is not an alert entity"); always precedes `gate_requested` |
| `gate_requested` | `actions` (batched), `risk` |
| `gate_decision` | `decision` (approved/denied), `by` |
| `action_executed` | `action`, `result` |
| `action_skipped` | `action`, `reason` — POST-gate only: an approved action with no registered executor ("no executor for action"); per approved action, `action_executed` XOR `action_skipped` follows `gate_decision(approved)` |
| `action_dropped_untraceable` | `action`, `reason` — emitted by `verdict.py`'s `_filter_traceable_actions` when a targeted action's entity param cannot be found in any finding statement/evidence; this is a quality backstop (not a security boundary), applied on the `ok_count >= 1` path only |
| `verdict` | full verdict object |
| `run_terminated` | `reason` (completed/max_steps/awaiting_approval/error) |

A `tool_called`→`tool_result` pair shares the same `step` + `attempt` — reconstructable without positional inference (eval adapters depend on this).

Renaming a field here is a breaking change for resume rebuild AND eval assertions — update all three together.

**Resume forward compatibility:** `_RunBuilder.fold` dispatches on known event names only; an unknown event type (e.g. `llm_transport_retry`, `llm_repair`, `action_dropped_untraceable`) is stored in `ReconstructedRun.events` (the raw audit trail) but folds into no typed view. Resume never crashes on forward-compatible journal additions.

**`ReconstructedRun.steps_after_last_revision`:** the count of completed Tool Steps (i.e. `tool_result` events) recorded strictly after the last `plan_revised` event. Zero when no revision was recorded (the linear case). Resume uses this to index into the last revision's plan steps instead of the broken `steps_executed − n_revisions` arithmetic, which fails when a single revision fires at step ≥ 2. `_RunBuilder` resets this counter each time a new `plan_revised` event is seen.

## HITL gate

ONE gate per run, after verdict: all high-risk actions batched into a single approval request. Approved → execute immediately; denied → record, verdict still ships. Risk tiers come from `config/risk_policy.yaml` (action → tier); **unclassified actions default to high-risk**. `ApprovalGate` is a Protocol; impls: `CLIGate` (interactive), `AutoGate` (config-driven, default-deny — used in tests/CI), `DeferredGate` (emits `gate_requested`, returns the `HOLD` sentinel, no decision — the run exits `awaiting_approval` for `--resume --approve|--deny`; wired by non-interactive adapters). `GateOutcome = GateDecision | HOLD | None` (`None` = zero-touch). The gate is enforced by the run flow in code, never delegated to LLM judgment.

**Resume idempotency:** on `--resume --approve`, execute a high-risk action only if no `action_executed` event exists for it; order is check → execute → record, so a recorded result is reused, never re-applied.

## Ports-first (wave 1 lays every seam; later waves swap implementations only)

Wave 1 MUST define these boundaries even where the real implementation comes later — otherwise waves 2–4 refactor wave-1 code and churn the 100%-covered tests:

- **`LLM` port**: one Protocol the whole agent talks to; impls: `OpenAICompatibleLLM` (real) and `FakeLLM` (tests — see Test architecture).
- **`Journal` port + `NoopJournal`**: the executor/planner/gate emit events from day one; wave 2 only adds `JsonlJournal`. Never add emit calls retroactively.
- **`Planner.plan(alert, recall=None)`**: the recall parameter exists from wave 1 (always `None` until wave 3); deps (`llm`, `journal`, `tool_specs`) bind in the constructor.
- **Contracts in `models.py`**: `ReasonerDecision` (`continue | revise_plan | conclude` + rationale + next-step payload), `RunResult` (verdict + gate_decisions + executed_actions + run_id + terminated_reason — what `run.py` prints and evals read; persisted as a **versioned run record** at `runs/<run_id>/result.json`, which external eval adapters read instead of importing `src/triage`), `Action`, `GateDecision` (`{decision, by}`, mirrors the journal payload), alongside Alert/InvestigationPlan/PlanStep/Finding/Verdict/ToolResult.
- **Structured output**: request `response_format` JSON schema when the endpoint supports it, ALWAYS with the prompt-instructed-JSON + parse + one-repair-attempt fallback. The fallback is load-bearing (Ollama/some vLLM lack json_schema — it is how the local-model bonus works), not a rare path.
- **Risk policy file**: `config/risk_policy.yaml`, overridable via `RISK_POLICY_PATH` env.
- **`prompt_hash`**: sha256 over the full rendered message list (model-agnostic); used in `llm_call` events and as the Replay Mode key.

## Prompt-file rules (ADR-0005)

All prompts live in `prompts/*.md` — never inline strings. Every template that includes alert content **delimits and labels the untrusted payload apart from instructions** (a generic labeled block, e.g. `<alert_payload>…</alert_payload>`; no per-event-type schema). Recalled memory gets the same labeling (untrusted context, with source run-id + confidence). Verdict safety is never delegated to prompt discipline — the deterministic checks (severity enum, RiskPolicy allowlist, target-entity invariant) enforce it in code.

**`{{END_OF_STABLE}}` placement contract (prefix-cache boundary):**

- `planner.md`: sentinel goes BEFORE `<alert_payload>` — the stable part is the full instruction block including tool specs; the per-call data (alert + memory recall) is the dynamic part. Stable prefix is instructions-only (~constant across all runs).
- `reasoner.md` and `verdict.md`: sentinel goes AFTER `<alert_payload>` — the stable part includes instructions AND the alert payload (which is fixed for the duration of one run); per-step observations / findings are the dynamic part. This extends the effective cache hit for the many reasoner calls within a single run.
- Tests in `tests/test_prompts.py` pin the sentinel invariant for all three prompts — any placement change must update those tests.

**Rendering conventions (quality-wave standards):**
- JSON payloads rendered with `dump_compact` (no indent, `sort_keys=True`) — stable bytes, smaller prompts.
- Tool observations rendered as `<observation step="N" tool="T" ok="B">…</observation>` tags via `rendering.observation_tag`; the `tool` attribute value is sanitized to `[A-Za-z0-9_-]` before interpolation (XSS/attribute-injection guard — ADR-0005 threat).
- Observation body data is truncated to 4000 chars at the render seam (via `rendering.truncate`) before being embedded in the prompt; the journal stores the full un-truncated data.
- Tool lists wrapped in `<tools>…</tools>`; output schema wrapped in `<output_schema>…</output_schema>` for unambiguous untrusted-content boundaries.

## Test architecture (resolves the 100%-coverage × real-LLM × no-key triangle)

- **Tier A — deterministic suite (feeds the coverage gate):** all unit/integration tests run against `FakeLLM` with canned structured responses. `make check` stays green with no key and no network.
- **Tier B — live smoke (`@pytest.mark.live`):** the "≥1 real LLM call" requirement; auto-**skipped when `LLM_API_KEY` is unset**, run manually before submission. Never counted on for coverage.
- Unit tests assert **structural** properties only (valid plan schema, no crash, gate ordering); "plans sensibly" is LLM behavior — judged by the wave-3 live eval, never unit-asserted.

## Reliability rules

- LLM calls: retry ×3 exponential backoff + per-call timeout + exactly 1 repair attempt on malformed structured output, then raise.
- Tool errors: transient (timeout / 5xx / connection reset) → exactly 1 retry (2 attempts total) with short backoff, each attempt journaled; permanent (schema / not-found / auth) → no retry, return as `ToolResult(ok=False, error=...)` observation — the agent adapts; tool errors never crash the run.
- `MAX_STEPS` (env, default **15**): on breach, emit partial verdict + `run_terminated(reason="max_steps")`.
- Repeat-call guard: identical tool+args twice → force the reasoner to change course.

## Config / env vars (names are a contract — keep `.env.example`, code, Makefile, README in sync)

`LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`, `MAX_STEPS` (15), `RISK_POLICY_PATH` (default `config/risk_policy.yaml`), `MEMORY_DIR` (default `.memory/`, gitignored), `MEMORY_SYNTHESIZE_EVERY_N_RUNS` (0 = disabled).

## Memory

L0 = journals (free). L1 = finding atoms persisted at verdict time, keyed by entity. L2 = entity dossiers (deterministic group-by, no LLM). L3 = threat posture brief (LLM, cadence by config; degradation path = deterministic top-N). Recall is **entity-scoped**: only atoms/dossiers matching the current alert's entities + the L3 brief go into planner context — never the whole store.

## Quality bar (ADR-0004 — machine-enforced, read before coding)

- **Coverage 100% + branch**, gated in `make check` (`fail_under=100`, `--cov-branch`). `# pragma: no cover` ONLY on `__main__` guards / `TYPE_CHECKING` / defensive-unreachable, each with a one-line reason — QA audits every pragma. Integration tests via replay count toward coverage where unit mocks are meaningless.
- **ruff `ALL`**: write code that passes it; if a rule must be ignored, add it to the pyproject ignore list WITH a reason comment — never inline `# noqa` without a rule code and reason.
- **ty `error-on-warning`**: warnings are errors. Fix types, don't suppress; `ty: ignore[rule]` needs the same justification discipline as pragmas.
- **Pydantic strict mode** on alert envelope fields (no implicit coercion); payload dicts stay flexible.
- **Typed errors with boundary conversion** (`errors.py`: `TriageError` → `LLMError`, `ToolError(transient|permanent)`, `GateError`, `JournalError`, `ConfigError`). Raise only inside the owning module; convert at every seam (tool failure → `ToolResult(ok=False)`; LLM retries exhausted → `run_terminated(error)` + partial verdict). No exception crosses two module boundaries — QA checks this seam.

## Naming — ubiquitous language

`UBIQUITOUS_LANGUAGE.md` (repo root) is the canonical vocabulary. Identifiers, journal event names, prompt wording, docstrings, and test names use those exact terms — e.g. `Finding` not "insight", `Observation` not "tool output", **Resume** (state rebuild) vs **Replay Mode** (eval cache) are different things, `Plan Step` vs executor `Step` are different counters. When a new domain concept appears, add it there first, then code it.

## Style

- Python ≥3.11 syntax only (ruff/ty target py311 even though dev runs 3.12).
- `make check` green is the definition of "compiles": ruff + format + ty + pytest-with-coverage.
- English everywhere: code, comments, docstrings, commit messages, docs.
- No secrets in the repo, ever; `runs/` and `.env` are gitignored.

## When implementing the eval harness

Read the `eval-authoring` skill — golden case format, assertion semantics, and replay mode live there.
