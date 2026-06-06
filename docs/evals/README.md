# Evaluation

The eval harness is the functional acceptance gate (RFC-0001 §Eval, US-0003,
US-0007, US-0009). Two tiers:

- **Tier 1 — blocking behavioral assertions.** Each golden case
  (`src/triage/evals/cases/*.yaml`) asserts on the trajectory (tools called,
  gate-before-high-risk ordering, max-steps, no repeated calls, termination
  reason) and the verdict (severity range, entities referenced, confidence
  floor, schema validity). Ranges, not exact matches — LLM output varies.
- **Tier 2 — advisory LLM judge.** Scores reasoning quality from the run trace,
  median-of-3 to tame noise. Never gates; a per-case `judge_min` only ever
  exits 2 (a distinct, overridable signal). Tier-1 always wins.

## Settings (disclosed)

| Setting | Value |
|---|---|
| Primary / baseline model | `gpt-5.4-mini` on **Azure AI Foundry** (OpenAI-compatible endpoint) |
| Judge model | same as the agent by default; **pinned** to the baseline for cross-model sweeps |
| Judge sampling | median-of-3 |
| Env contract | `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` — never committed (`.env*` gitignored) |

The model is pure configuration (ADR-0002): provider, base URL, and model name
come from the env. Swapping DeepSeek, Llama, Ollama, or vLLM is a `.env` change,
not a code change — proven in [results.md](./results.md).

## Running

```bash
# Replay — deterministic, key-free, CI-safe (serves recorded responses)
make eval-replay

# Live — real LLM calls on the configured model (needs .env with LLM_API_KEY)
make eval

# Single live run with the full agent narration
uv run python run.py --alert alerts/ALT-2026-04-7821-data-exfiltration.json --verbose
```

Replay caches (`<case>.replay.json`, next to each YAML) are keyed by prompt hash.
A prompt change misses loudly (`ReplayMiss`); re-record the suite with the
multi-model sweep (below) writing to the canonical location.

## Multi-model sweep (US-0009)

`triage.evals.sweep` runs the suite on any model from an isolated env file, with
the judge pinned to the baseline so Tier-2 scores stay comparable across models.

```bash
# Baseline re-record (writes canonical caches next to the YAMLs) — omit --scratch-caches
uv run python -m triage.evals.sweep --env-file .env --out _workspace/evalrun-gpt

# Cross-model sweep: agent on another model, judge pinned to baseline, caches kept
# in --out so the committed baseline caches are never overwritten.
make eval-sweep ENV=.env.llama OUT=_workspace/evalrun-llama
make eval-sweep ENV=.env.deepseek OUT=_workspace/evalrun-deepseek WORKERS=1 SECS=60
```

Flags (`python -m triage.evals.sweep --help`): `--env-file` (agent model),
`--judge-env-file` (pin the judge; its `LLM_*` load as `JUDGE_*`),
`--scratch-caches` (write caches into `--out`, never the baseline),
`--min-case-seconds` (RPM throttle for rate-limited serverless models — e.g. a
20-RPM model: `--workers 1 --min-case-seconds 60`), `--workers`, `--out`.

The sweep prints a Markdown comparison row per model; collected rows live in
[results.md](./results.md).

## Operational note — content filters

Running a security-triage agent on serverless models surfaces a real deployment
constraint: Azure AI Foundry's **default Responsible-AI content filter** returns
HTTP 400 on security alert content (exfiltration, privilege escalation,
credential abuse) for some deployments until the filter policy is relaxed. This
is an environment policy, not an agent or model failure — but it is exactly the
kind of guardrail interaction to plan for when deploying on managed inference.

## Memory recall

How memory affects evaluation — entity-scoped recall, the two seeded recall
cases, and the measured atom counts — is documented in [memory.md](./memory.md).

## Reports

- [results.md](./results.md) — per-model comparison table.
- [memory.md](./memory.md) — memory recall measurement.
- [2026-06-06-quality-loop-summary.md](./2026-06-06-quality-loop-summary.md) —
  the five-round reasoning-quality loop (judge 73.8 → 84.1) + full HTML report.
