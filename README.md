# Alert Triage Agent

An autonomous security-alert triage agent that investigates JSON alerts end-to-end,
produces a structured verdict, and keeps a human in the loop before any high-risk
containment action executes.

Built as a raw-Python system with an explicit Plan → ReAct + replan loop, an
event-sourced run journal, an entity-attributed three-level memory hierarchy, and a
two-tier eval harness — no agent framework.

---

## What and why

Security teams receive alerts (SIEM, CloudTrail, API gateways) faster than humans can
investigate them. Every alert demands the same expensive loop: pull context about the
user, query logs, check reputations, assess the asset — then decide severity and
response. This agent performs that loop autonomously:

- **Zero-touch for benign alerts** — most runs complete with no human input.
- **One approval gate for high-risk actions** — a human approves or denies before
  any containment action executes. Approval can happen interactively (CLI) or
  asynchronously (`--resume --approve|--deny`).
- **Adapts to any alert type** — the planner reads whatever fields exist in the alert
  envelope; new event types need no code changes.
- **Gets smarter across runs** — an entity-attributed memory hierarchy (see
  [Memory](#memory)) feeds prior findings back into the planner context.

---

## How this was built

This repository was built with an **agentic workflow** — Claude Code driving the
implementation inside a harness I designed: govkit governance gates
(PRD → RFC → ADR → US, enforced by `npx govkit verify`), a two-tier eval gate,
and dedicated QA agents between waves.

The split is deliberate and worth stating plainly, because for an *Agentic AI
Engineer* role the workflow itself is part of the demonstration:

- **The agents wrote** most of the code and tests, under the gates above.
- **I own** every architecture decision (ADR-0001…0006 — raw-Python loop,
  OpenAI-compatible boundary, event-sourced journal, quality bar, adversarial
  posture, entity attribution), the calibration constants (the no-progress
  backstop `K=6`, the `[0.30, 0.40]` zero-evidence confidence band, the
  zero-covered coverage rule), the accept/reject call on every code-review and
  assessment finding, and the eval-contract design.

The governance trail (`docs/`), the eval results ([docs/evals/](docs/evals/)),
and the per-round quality-loop measurements are the evidence that the decisions —
not just the code — were owned.

---

## Architecture

Deep dive — runtime flow, module seams, journal/resume mechanics, and the full
no-framework rationale: **[docs/architecture.md](docs/architecture.md)**.

```mermaid
flowchart TD
    A["alert JSON\n(run.py --alert)"] --> B["validate\n(Pydantic strict)"]
    B --> C["PLANNER\nLLM → InvestigationPlan\n(+ memory recall)"]
    C --> D["EXECUTOR — ReAct loop"]
    D --> E["pick Plan Step\n→ tool call"]
    E --> F["FixtureDataSource\n(lookup_user / query_logs /\ncheck_reputation / get_asset_info)"]
    F --> G["Observation\n(ToolResult)"]
    G --> H["REASONER\nLLM → continue | revise | conclude"]
    H -->|"continue / revise"| D
    H -->|"conclude / max_steps"| I["VERDICT\nLLM → severity, findings,\nactions, confidence"]
    I --> J["RiskPolicy\n(config/risk_policy.yaml)"]
    J -->|"high-risk actions"| K["ApprovalGate\nCLIGate / DeferredGate"]
    K -->|"approved"| L["execute action\n(block_user mock)"]
    K -->|"denied"| M["record denial"]
    L --> N["journal.jsonl\n(append-only JSONL)"]
    M --> N
    I --> N
    N --> O["result.json\n(runs/<run_id>/)"]
    O --> P["Memory L1\nfinding atoms\n(entity-keyed)"]
    P --> Q["Memory L2\nentity dossiers\n(deterministic group-by)"]
    Q --> R["Memory L3\nthreat posture brief\n(LLM cadence / deterministic fallback)"]
    R -->|"entity-scoped recall"| C
```

### Module map

| Module | Responsibility |
|---|---|
| `run.py` | CLI adapter — `--alert`, `--resume [--approve\|--deny]`, `--synthesize-posture` |
| `src/triage/core.py` | Transport-agnostic `triage(alert, deps)` — orchestrates planner → executor → verdict → gate |
| `src/triage/models.py` | Pydantic contracts: `Alert`, `InvestigationPlan`, `Verdict`, `RunResult`, `GateDecision`, … |
| `src/triage/llm.py` | OpenAI-compatible client — retry ×3 exp backoff + 1 repair attempt on malformed output |
| `src/triage/planner.py` | Alert + memory recall → `InvestigationPlan` (structured LLM) |
| `src/triage/executor.py` | ReAct loop — step → tool → observation → reason; max-steps and repeat-call guards |
| `src/triage/verdict.py` | Findings → structured `Verdict` (LLM); deterministic confidence clamp + action filters |
| `src/triage/journal.py` | Append-only JSONL event emitter + state rebuilder for resume |
| `src/triage/gate.py` | `RiskPolicy` (YAML config) + `ApprovalGate` Protocol + `CLIGate` / `AutoGate` / `DeferredGate` |
| `src/triage/rendering.py` | LLM-facing rendering primitives: truncation, compact JSON, observation tags, prompt split |
| `src/triage/memory/` | L1 atoms, L2 dossiers, L3 posture; entity-scoped recall |
| `src/triage/tools/` | `ToolRegistry` (4 read-only tools), `DataSource` Protocol, `FixtureDataSource`, `block_user` response action |
| `src/triage/evals/` | Runner, 36 golden cases, assertion engine, replay mode, LLM judge |
| `prompts/*.md` | Every LLM prompt (planner, reasoner, verdict, judge, posture) |

Dependency direction: `models` ← everything; `journal` / `llm` / `tools` / `gate` / `rendering`
are leaves consumed by `planner` / `executor` / `verdict`. Nothing imports `run.py`.

**Verdict verify hook (RFC-0003).** Every verdict passes through four deterministic
grounding checks (citation validity, confidence-evidence consistency, action
traceability, entity coverage) before shipping; the outcome is journaled as
`verdict_verification`. With `VERIFY_REENTRY=true` (Phase 2 — both calibration gates
measured and met: 0 false flags on the recorded suite, 8.6% ≤ 10% live), a failed
hook triggers one bounded re-plan with the verification gap note before the verdict
is re-synthesized; without it, failures degrade-and-ship exactly as before.

---

## Setup

### Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) — used for all dependency management and running

### Install

```bash
git clone <repo>
cd alert-triage-agent
uv sync
```

### Environment

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `LLM_API_KEY` | *(required)* | API key for any OpenAI-compatible provider |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | Provider base URL — swap for DeepSeek, Ollama, vLLM, OpenRouter, etc. |
| `LLM_MODEL` | `gpt-4o-mini` | Model name sent to the provider |
| `MAX_STEPS` | `15` | Maximum executor steps per run; graceful termination on breach |
| `TI_ENABLED` | `false` | Enable Threat Intel delegated IOC enrichment (RFC-0002); accepts `true`, `1`, `yes` |
| `MEMORY_DIR` | `.memory` | Base directory for L1/L2/L3 memory artifacts (gitignored) |
| `MEMORY_SYNTHESIZE_EVERY_N_RUNS` | `0` | Regenerate the L3 posture brief every N runs; `0` = disabled (use `--synthesize-posture` for on-demand) |
| `RISK_POLICY_PATH` | `config/risk_policy.yaml` | Path to the risk policy YAML that classifies actions as high/low risk |

`runs/` (runtime artifacts) and `.env` are gitignored. No secrets ever reach the repo.

---

## Running

### Single alert (the primary mode)

```bash
# Data-exfiltration sample alert
make run

# Privilege-escalation sample alert
make run ALERT=alerts/ALT-2026-04-7835-privilege-escalation.json

# Any custom alert JSON
make run ALERT=path/to/your-alert.json

# Watch the agent think — narrate plan / tool calls / reasoning / verdict /
# gate live to stderr (stdout keeps just the summary; the journal is unchanged)
uv run python run.py --alert alerts/ALT-2026-04-7821-data-exfiltration.json --verbose
```

This prints a human-readable verdict summary and writes the versioned run record to
`runs/<run_id>/result.json`. `--verbose` also works with `--resume`.

### Resume flow (asynchronous approval)

When the agent reaches a high-risk verdict in a non-interactive context (or exits mid-run),
it parks the run as `awaiting_approval`. Resume it with:

```bash
# Approve the pending high-risk action batch
uv run python run.py --resume <run_id> --approve

# Deny the pending high-risk action batch
uv run python run.py --resume <run_id> --deny

# Continue an interrupted investigation (killed mid-run, no gate yet)
uv run python run.py --resume <run_id>
```

The `run_id` appears in the summary printed at the end of each run and in
`runs/<run_id>/` on disk.

### On-demand L3 posture synthesis

```bash
uv run python run.py --synthesize-posture
```

Regenerates the org-level threat posture brief immediately, regardless of the cadence
configured by `MEMORY_SYNTHESIZE_EVERY_N_RUNS` (including when it is `0`). The brief
is written to `$MEMORY_DIR/posture.md`. This path is key-free — it uses the
deterministic fallback (top-N atom aggregation) without an LLM call.

---

## Memory

The context layer the JD calls "awareness of past incidents." Three levels, all
**entity-attributed** (ADR-0006) so recall precision rises with the store instead
of degrading:

- **L1 — finding atoms.** Every persisted finding is attributed to the alert
  entities it actually names (declared `related_entities` validated against the
  alert, then a deterministic text-scan fallback). An atom exists for an entity
  **iff** the claim names that entity; a finding that names none persists nothing
  and emits a `finding_unattributed` audit event — never a silent drop.
- **L2 — entity dossiers.** Deterministic group-by over atoms (confidence/recency
  ranked, capped). No LLM.
- **L3 — posture brief.** LLM synthesis on a cadence, with a key-free
  deterministic top-N fallback.

**Recall is entity-scoped:** the planner sees prior findings only for the current
alert's entities. This is what removed the old cartesian fan-out — measured
**354 → 114 atoms (−67.8%)** on the eval suite, with zero cross-entity pollution
pinned by a deterministic test. Full measurement and the two seeded recall cases:
[docs/evals/memory.md](docs/evals/memory.md).

---

## Tests & quality gates

```bash
make check       # the full gate: lint + typecheck + tests (run this before committing)
make test        # pytest only
make lint        # ruff check + format --check
make typecheck   # ty
```

`make check` is the local mirror of CI: `ruff` (lint + format), `ty` (types), and
`pytest` with a **100% line+branch coverage floor** (ADR-0004). The suite is
deterministic and key-free — it runs `FakeLLM` / replay doubles, never a live
model — so it needs no API key. Live-model tests are marked `@pytest.mark.live`
and are opt-in.

---

## Evals

The eval harness is the functional acceptance gate — a prompt change that breaks a
golden case does not ship. Full guide: **[docs/evals/](docs/evals/)**.

### Two tiers

**Tier 1 — blocking behavioral assertions** (`make eval-replay` / `make eval`):
Each of the 36 golden cases (`src/triage/evals/cases/*.yaml`) asserts on:
- Trajectory: required tools called, gate-before-high-risk ordering, max-steps
  respected, no repeated identical calls.
- Verdict: severity in the allowed range, entities referenced, confidence floor,
  schema validity.

Ranges are used, not exact matches — LLM output varies run to run.

**Tier 2 — advisory LLM judge** (embedded in `make eval`):
Scores reasoning quality from the run trace using a median-of-3 call strategy (three
independent judge calls, median score taken) to reduce noise. Tracked as a trend;
never blocks. Only Tier-1 carries acceptance weight.

### Running evals

```bash
# Replay — deterministic, key-free, CI-safe (serves cached LLM responses)
make eval-replay

# Live — real LLM calls on the configured model (requires .env with LLM_API_KEY)
make eval
```

Replay mode uses prompt-hash-keyed cached responses stored in `.replay.json` files
alongside each case. When you change a prompt, the cache misses loudly (`ReplayMiss`).

**Re-record / multi-model sweep** (US-0009) — run the suite on any model from an
isolated env file, judge pinned to the baseline so Tier-2 scores stay comparable:

```bash
# Re-record the canonical baseline caches (next to each YAML)
uv run python -m triage.evals.sweep --env-file .env --out _workspace/evalrun

# Evaluate another model — config only, no code change (caches kept in --out)
make eval-sweep ENV=.env.llama    OUT=_workspace/evalrun-llama
make eval-sweep ENV=.env.deepseek OUT=_workspace/evalrun-deepseek WORKERS=1 SECS=60
```

Full eval guide (settings, flags, model matrix, memory recall): **[docs/evals/](docs/evals/)**.

### Golden case coverage

36 cases span the core behavioral envelope:

| Category | Cases |
|---|---|
| Confirmed threat (data exfil, priv-esc) | `exfil-prod`, `priv-esc` |
| Benign / false-positive discipline | `benign`, `benign-after-flagged`, `benign-*` (7 variants) |
| Unknown event type (zero code changes needed) | `unknown-event-type` |
| Tool failure handling | `tool-failure`, `tool-failure-*` (4 variants) |
| Edge cases | `edge-contradictory-signals`, `edge-empty-entities`, others |

### Evaluation results (2026-06-06, live)

Full results, the three-model comparison, and reproduction commands:
**[docs/evals/results.md](docs/evals/results.md)**. Headline state on the
calibrated baseline model (`gpt-5.4-mini`):

| Signal | Value | Weight |
|---|---|---|
| **Tier-1 behavioral assertions** | **36/36 pass** (live and replay) | the acceptance gate |
| **Verify-hook false flags** | **0/35** recorded; 8.6% live (≤ 10% Phase-2 gate) | deterministic |
| **Coverage-gap telemetry** | 3/35 cases (was 10/35 before the loop) | judge-independent |
| **Memory cartesian-noise reduction** | 354 → 114 atoms (−67.8%) | measured |
| Tier-2 judge mean | 84.1 / 100 (stdev 2.6, min 78; pre-loop 73.8) | advisory |

The acceptance weight sits on the top four — deterministic, judge-independent
signals. The **judge mean (84.1) is advisory and self-graded**: a median-of-3
score against a rubric in this repo, where round 5 of the quality loop calibrated
the *judge* itself. Read it as a trend, not an absolute — the rows above are what
actually gate.

The judge mean moved 73.8 → 84.1 through five audited rounds (coverage gate,
limitation ledger, pivot playbook, aspect completeness, judge anchors). Rounds 1–4
changed real agent behavior — the verify hook's own coverage telemetry (10 → 3)
confirms it independently of the judge; round 5 calibrated the measuring
instrument. Full per-round trail:
[docs/evals/2026-06-06-quality-loop-summary.md](docs/evals/2026-06-06-quality-loop-summary.md).

**Model portability** ([results.md](docs/evals/results.md)): the same agent runs
on `gpt-5.4-mini`, `Llama-3.3-70B`, and `deepseek-v4-flash` — three families,
three endpoints, only `.env` changed (ADR-0002). Tier-1 36/36 holds on the
calibrated model and degrades gracefully (33, 27) on the others, never crashing.

### Three worked examples (from the final live run)

**1. `exfil-prod` — confirmed threat path (judge 85/100).**
*Input:* alert `data_exfiltration` — service account `svc-deploy-prod` called
`/admin/users/export` 847 times from `10.200.3.47`, outside the expected caller
range. *Trajectory:* `lookup_user` → `query_logs` (account) → `query_logs` (IP) —
all ok. *Output:* severity **high**, confidence 0.78, 4 findings (each citing exact
tool data; the fourth explicitly flags that the 847-call volume claim is only
partially resolved), 3 recommended actions (`review_access`, …) — batched through
the approval gate before execution. *Judge audit:* "each key claim tied to concrete
tool output … keeps severity high while limiting confidence — correct decoupling."

**2. `benign` — false-positive discipline (judge 86/100).**
*Input:* off-hours console login by `dev-intern-jpark` from `203.0.113.22`.
*Trajectory:* `lookup_user` → `query_logs` (user) → `get_asset_info` (fails: no
record) → `query_logs` (IP). *Output:* severity **low**, confidence 0.78, no
actions; two limitation findings explicitly name what could NOT be verified (device
context, off-hours framing) with `related_entities: []` so run limitations never
pollute entity memory. *Judge audit:* "the failed get_asset_info call was handled
honestly rather than ignored."

**3. `tool-failure-all-unknown-ip` — zero-evidence honesty (judge 85/100).**
*Input:* port-scan alert with three source IPs; the fixture world has no record of
any of them (by design). *Trajectory:* 4 calls across `query_logs` /
`check_reputation`, every one fails. *Output:* severity **medium** (threat pattern
unchanged — severity never downgraded for missing evidence), confidence **0.35**
(zero-evidence clamp band), no actions, one finding per IP stating it remains
unverified. *Judge audit:* "adapted appropriately … ending with an explicitly
unverified, low-confidence verdict rather than inventing results."

---

## Assumptions

As decided on 2026-06-05 (PRD-0001 §Assumptions):

1. **Approved actions execute immediately.** The agent executes mock containment
   actions (e.g. `block_user`) right after approval; denial is recorded and the
   verdict still ships.
2. **The reviewer grades with their own LLM key.** The LLM client is
   OpenAI-compatible — provider, base URL, and model are pure configuration (`.env`).
   Swapping in DeepSeek, Ollama, or vLLM is configuration, not code.
3. **"High-risk" classification is owned by `config/risk_policy.yaml`**, defaulting
   to conservative (unclassified = high-risk). The LLM never decides what is
   high-risk.
4. **One approval gate per run.** All high-risk actions in a verdict are batched into
   a single approval request. Per-action and tiered gates are roadmap (the
   `ApprovalGate` Protocol is the extension seam).

---

## Trade-offs and what I would do differently

### LangGraph (or any agent framework) — why rejected

LangGraph was considered and rejected (ADR-0001). Its checkpointing is an opaque
state snapshot rather than an audit-grade journal, its tracing assumes LangSmith, and
it would replace only the cheapest part of the system (the ~100-line loop) while
hiding the architecture skill the rubric weighs at 30%. The hand-rolled loop is
transparent: the journal, the ReAct dispatch, and the gate are all plain Python that
a reviewer can read in one sitting. Revisit when durable multi-node execution or team
standardization matters. The decision was made from framework fluency, not
avoidance — [docs/architecture.md §8](docs/architecture.md#8-why-no-agent-framework-adr-0001-expanded)
maps this design node-for-node onto a LangGraph `StateGraph` (nodes, conditional
edges, `interrupt()` gate, checkpointer) and explains why the journal contract is
the reason to hand-roll.

### Synchronous single-process — by design, with a scale-out path

The agent runs synchronously in one process. Triaging *one* alert is inherently
sequential — each step depends on the previous observation (ReAct) — so there is no
intra-run concurrency to exploit. Scale is *across* alerts, and the seams already
allow it without touching the loop: `triage(alert, deps)` is a pure function over
injected dependencies, and the journal is event-sourced per run. The production
path is a queue with one worker per alert (the journal makes each run independently
recoverable), `async` LLM calls as the first concurrency win, and the file-backed
memory store swapped for a database before multi-writer access. None of that
changes agent logic — it changes the adapter around `triage()`.

### Workflow/playbook router — deliberately excluded

A predefined tool-sequence router per known event type would reduce token cost. It was
rejected because a fixed sequence directly violates "use output from one tool to
decide what to do next." Recorded as a roadmap note: a hybrid router (standardized
lanes for very high-volume known types, agentic fallback for everything else) is the
production optimization, but not for a rubric that weights reasoning at 20%.

### Connector roadmap (fixture world → real integrations)

The four investigation tools (`lookup_user`, `query_logs`, `check_reputation`,
`get_asset_info`) currently run against a consistent fixture world. The `DataSource`
Protocol is the seam: real connectors (Splunk, Okta, VirusTotal, AWS IAM, CMDB) drop
in behind it. The `ToolError(transient|permanent)` contract already handles the retry
semantics real integrations need.

### Production HITL (CLI gate → ticketing/Slack)

The current `CLIGate` blocks on stdin. Production needs `DeferredGate` (already
shipped for watch mode) wired to a ticketing system or a Slack approval workflow:
the run exits `awaiting_approval`, the approval surface sends `--resume --approve|--deny`
back on confirmation. The `ApprovalGate` Protocol is the extension seam — no core
changes needed.

### Watch mode — cut this wave, design sketch

Watch mode (`--watch <dir>`) was cut from wave 4 scope (the RFC-0001 sanctioned cut
line). The system shipped is event-driven via `--alert`. To add watch mode:

1. Add a file-system watcher (e.g. `watchdog`) that detects new `.json` files in the
   drop folder.
2. For each file: mint a `run_id`, call `_run_fresh()` with `interactive=False`, which
   wires `DeferredGate` — a high-risk verdict exits as `awaiting_approval` instead of
   blocking on stdin.
3. The operator runs `python run.py --resume <run_id> --approve|--deny` to complete
   the gate. The journal is the state; no extra database is needed.
4. Serial ingestion (one run at a time) preserves the single-writer journal/memory
   posture. Concurrent ingestion (parallel runs writing to shared memory) is a later
   locking/partitioning problem.

The `DeferredGate` and resume machinery are already production-ready. Watch mode is
a thin adapter loop, not a core change.

---

## Requirements traceability

| PRD requirement | Where satisfied |
|---|---|
| Receive alert as JSON (stable envelope) | `models.Alert` (Pydantic strict) — `src/triage/models.py` |
| LLM reasoning — not hardcoded; new event types adapt | `planner.py` + `prompts/planner.md`; no `event_type` branching anywhere |
| ≥3 mock tools with realistic data | `src/triage/tools/registry.py` (`lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`) + `tools/fixtures/` |
| Chain reasoning: each output feeds next decision | `executor.py` ReAct loop; `prompts/reasoner.md` consumes all prior observations |
| Structured verdict: severity, findings, actions, confidence | `models.Verdict`; `verdict.py`; US-0001 AC |
| Human-in-the-loop gate before high-risk action | `gate.py` — `RiskPolicy` + `CLIGate`; `core.py` enforces ordering |
| Python 3.11+, ≥1 real LLM call | `pyproject.toml` `requires-python = ">=3.11"`; `@pytest.mark.live` tests (US-0001) |
| Configurable max steps with graceful termination | `MAX_STEPS` env; `executor.py`; `tests/test_executor.py:test_max_steps_*` |
| ≥3 tests (tool call / approval gate / tool error) | `tests/test_core.py`, `tests/test_executor.py`, `tests/test_verdict.py` |
| Run journal (audit trail, resume, retry visibility) | `journal.py` + `ADR-0003`; US-0002 |
| Memory L0→L3 (entities, dossiers, posture) | `src/triage/memory/`; US-0003, US-0004 |
| Two-tier eval harness (blocking + advisory judge) | `src/triage/evals/`; 36 golden cases; US-0003 AC |
| README + `.env.example` + `pyproject.toml` | This file; repo root |
| No secrets in repo | `.gitignore` covers `runs/`, `.env`, `.memory/`; `.env.example` has only placeholders |
| Single-command run | `make run` |
