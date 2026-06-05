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
├── models.py               # Alert, InvestigationPlan, PlanStep, Finding, Verdict, ToolResult (Pydantic)
├── llm.py                  # OpenAI-compatible client: retry ×3 exp backoff, timeout, 1 repair attempt on bad structured output
├── planner.py              # alert (+ memory recall) → InvestigationPlan  (LLM, structured)
├── executor.py             # ReAct loop: step → tool → observation → reason (continue|revise|conclude); max-steps guard; repeat-call guard
├── journal.py              # append-only JSONL emit + replay/rebuild state
├── gate.py                 # RiskPolicy (YAML config) + ApprovalGate Protocol + CLIGate + AutoGate
├── verdict.py              # findings → structured Verdict (LLM)
├── memory/                 # L1 atoms, L2 dossiers, L3 posture; entity-scoped recall
├── tools/                  # registry.py (4 read-only investigation tools), base.py (Tool + DataSource Protocol),
│                           # actions.py (response actions: block_user — post-gate only), fixture_source.py, fixtures/*.json
└── evals/                  # runner.py, cases/*.yaml, replay
prompts/*.md                # ALL LLM prompts (planner.md, reasoner.md, verdict.md, judge.md)
tests/test_{module}.py
alerts/*.json               # sample inputs
runs/<run_id>/journal.jsonl # runtime artifacts (gitignored)
```

Dependency direction: `models` ← everything; `journal`/`llm`/`tools`/`gate` are leaves consumed by `planner`/`executor`/`verdict`; nothing imports `run.py`. The core entrypoint `triage(alert, deps)` is transport-agnostic — adapters live only in `run.py`.

## Alert contract

Typed envelope (required): `alert_id`, `timestamp`, `source`, `severity_hint`, `event_type`, `description`. **`severity_hint` is a free `str`** (required, non-empty, NOT an enum — upstream systems vary and unknown alerts must never fail validation at the door); only the agent's own `Verdict.severity` is the strict enum. Flexible payload: `entities: dict[str, Any]`, `context: dict[str, Any]` — passed through to the LLM untouched. **Never** branch on `event_type` in code; never define per-event-type schemas. Unknown event types must parse and plan without code changes.

## Investigation tools vs response actions (decided 2026-06-05)

- The `ToolRegistry` exposes **read-only investigation tools only**: `lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`. The executor can never mutate anything mid-loop.
- **`block_user` is a Response Action, not an investigation tool.** It is never callable by the executor; it executes only in the post-verdict flow: Verdict → RiskPolicy → Approval Gate → approved → execute (mock), denied → recorded. One gate per run.
- This makes the eval assertion `gate_before_high_risk` structurally sound: a high-risk `action_executed` event without a preceding `gate_decision(approved)` is impossible by construction, not by prompt discipline.

## Verdict contract

`severity` (enum: `low|medium|high|critical`), `findings: list[Finding]` (each cites the tool observation it came from), `recommended_actions: list[Action]`, `confidence: float 0–1`, plus `terminated_reason` when ended early (max-steps, fatal error). Partial verdicts on graceful termination are mandatory — never exit without a verdict.

## Journal event schema

One JSON object per line, append-only, never mutated. Common fields: `seq` (monotonic int), `ts` (ISO-8601), `event`. Event types and their payload fields:

| event | payload |
|---|---|
| `run_started` | `alert_id`, `config` |
| `llm_call` | `purpose` (plan/reason/verdict/judge), `model`, `prompt_hash`, `tokens`, `latency_ms` |
| `plan_created` / `plan_revised` | `steps` |
| `tool_called` | `step`, `tool`, `args`, `attempt` |
| `tool_result` | `step`, `ok`, `data` \| `error` |
| `gate_requested` | `actions` (batched), `risk` |
| `gate_decision` | `decision` (approved/denied), `by` |
| `action_executed` | `action`, `result` |
| `verdict` | full verdict object |
| `run_terminated` | `reason` (completed/max_steps/awaiting_approval/error) |

Renaming a field here is a breaking change for journal replay AND eval assertions — update all three together.

## HITL gate

ONE gate per run, after verdict: all high-risk actions batched into a single approval request. Approved → execute immediately; denied → record, verdict still ships. Risk tiers come from `config/risk_policy.yaml` (action → tier); **unclassified actions default to high-risk**. `ApprovalGate` is a Protocol; impls: `CLIGate` (interactive), `AutoGate` (config-driven, default-deny — used in tests/CI). The gate is enforced by the run flow in code, never delegated to LLM judgment.

## Ports-first (wave 1 lays every seam; later waves swap implementations only)

Wave 1 MUST define these boundaries even where the real implementation comes later — otherwise waves 2–4 refactor wave-1 code and churn the 100%-covered tests:

- **`LLM` port**: one Protocol the whole agent talks to; impls: `OpenAICompatibleLLM` (real) and `FakeLLM` (tests — see Test architecture).
- **`Journal` port + `NoopJournal`**: the executor/planner/gate emit events from day one; wave 2 only adds `JsonlJournal`. Never add emit calls retroactively.
- **`planner(alert, recall=None)`**: the recall parameter exists from wave 1 (always `None` until wave 3).
- **Contracts in `models.py`**: `ReasonerDecision` (`continue | revise_plan | conclude` + rationale + next-step payload), `RunResult` (verdict + gate_decisions + executed_actions + run_id + terminated_reason — what `run.py` prints and evals read), alongside Alert/InvestigationPlan/PlanStep/Finding/Verdict/ToolResult.
- **Structured output**: request `response_format` JSON schema when the endpoint supports it, ALWAYS with the prompt-instructed-JSON + parse + one-repair-attempt fallback. The fallback is load-bearing (Ollama/some vLLM lack json_schema — it is how the local-model bonus works), not a rare path.
- **Risk policy file**: `config/risk_policy.yaml`, overridable via `RISK_POLICY_PATH` env.
- **`prompt_hash`**: sha256 over the full rendered message list (model-agnostic); used in `llm_call` events and as the Replay Mode key.

## Test architecture (resolves the 100%-coverage × real-LLM × no-key triangle)

- **Tier A — deterministic suite (feeds the coverage gate):** all unit/integration tests run against `FakeLLM` with canned structured responses. `make check` stays green with no key and no network.
- **Tier B — live smoke (`@pytest.mark.live`):** the "≥1 real LLM call" requirement; auto-**skipped when `LLM_API_KEY` is unset**, run manually before submission. Never counted on for coverage.
- Unit tests assert **structural** properties only (valid plan schema, no crash, gate ordering); "plans sensibly" is LLM behavior — judged by the wave-3 live eval, never unit-asserted.

## Reliability rules

- LLM calls: retry ×3 exponential backoff + per-call timeout + exactly 1 repair attempt on malformed structured output, then raise.
- Tool errors: transient → retry per tool policy (each attempt journaled); permanent → return as `ToolResult(ok=False, error=...)` observation — the agent adapts; tool errors never crash the run.
- `MAX_STEPS` (env, default **15**): on breach, emit partial verdict + `run_terminated(reason="max_steps")`.
- Repeat-call guard: identical tool+args twice → force the reasoner to change course.

## Config / env vars (names are a contract — keep `.env.example`, code, Makefile, README in sync)

`LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`, `MAX_STEPS` (15), `MEMORY_SYNTHESIZE_EVERY_N_RUNS` (0 = disabled).

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
