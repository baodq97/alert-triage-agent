# Evaluation results

## Baseline (gpt-5.4-mini, the calibrated model)

The committed replay caches and all acceptance gates run on `gpt-5.4-mini`
(Azure AI Foundry). Current state after the five-round reasoning-quality loop
([summary](./2026-06-06-quality-loop-summary.md)):

| Metric | Value |
|---|---|
| Tier-1 behavioral assertions | **36/36 pass** (live and replay) |
| Tier-2 judge mean | **84.1 / 100** (median-of-3; pre-loop baseline 73.8) |
| Judge spread | stdev 2.6, min 78 |
| Verify-hook false flags | 0/35 recorded; 8.6% live (≤ 10% Phase-2 gate) |
| Memory atoms (entity attribution) | 354 → 114 cartesian-noise reduction (−67.8%) |

(36 = the 35-case suite + the `medium-shared-entity-recall` case added in US-0009.)

## Cross-model comparison (model-swap proof)

Same agent, three model families, three endpoints — only `.env` changed, zero
`src/triage` edits (ADR-0002). The judge is **pinned to gpt-5.4-mini** for all
three so Tier-2 scores are comparable; the model under test is the *agent*.

Run over the full 36-case suite via the shipped `make eval-sweep` (US-0009),
judge pinned to gpt-5.4-mini. Full per-case breakdown for this run:
[2026-06-06-cross-model-run.md](./2026-06-06-cross-model-run.md).

| Model | Endpoint | Tier-1 | Judge (pinned) | stdev | wall/case | tok/case |
|---|---|---|---|---|---|---|
| gpt-5.4-mini | Azure AI Foundry | **36/36** | 83.9 | 2.5 | 11.6s | 14.2k |
| Llama-3.3-70B-Instruct | Azure AI Foundry | 33/36 | 78.7 | 6.4 | 17.1s | 12.1k |
| deepseek-v4-flash | OpenRouter | 27/36 | 82.2 | 4.3 | 82.2s | 16.9k |

(gpt-5.4-mini reproduces 36/36 with judge 83.9 — within noise of the standalone
baseline 84.1 — confirming the quality-loop gains are stable across independent
runs. Llama/DeepSeek Tier-1 counts move a few cases run-to-run, the expected
variance of a stochastic model against ranges calibrated for a different model.)

### How to read this

- **The swap works.** The full agent loop — plan, ReAct tool use, verdict,
  verify hook, gate, memory — runs end-to-end on all three models with no code
  change. That is the requirements-bonus claim, demonstrated.
- **Tier-1 36/36 holds only on the calibrated model.** The golden cases' ranges
  were tuned against gpt-5.4-mini; Llama and DeepSeek **degrade gracefully**
  (33, 27) rather than crashing — the never-crash verdict, the zero-evidence
  confidence clamp, and the verify hook keep every run shipping a valid verdict.
  This is honest portability data, not a "every model is perfect" claim.
- **Why deterministic Tier-1 gates and the judge only advises.** DeepSeek's
  judge score (82.2) is close to gpt's (83.9) — its *reasoning* is strong —
  yet its Tier-1 is 27/36. The failures cluster on `confidence_min` /
  `severity_in` / `must_reference_entities`: confidence/severity band drift and
  the occasional missed entity reference. The holistic judge forgives these; the
  deterministic Tier-1 checks catch them. A stochastic judge must never be the
  merge gate — this run is the live argument for that design.

### Operational finding — content filters

Azure AI Foundry's default Responsible-AI content filter initially returned HTTP
400 (`content_filter`) on the security alert content (exfiltration, privilege
escalation, credential abuse) for the DeepSeek and Llama deployments, collapsing
those runs into `error` fallbacks until the filter policy was relaxed. The
gpt-5.4-mini deployment was unaffected. This is an environment-policy interaction,
not an agent or model failure — and a concrete deployment lesson for running
security agents on managed/serverless inference. (DeepSeek was then run via
OpenRouter, where no such filter applied.)

## Reproduce

```bash
# Baseline (canonical caches):  uv run python -m triage.evals.sweep --env-file .env --out _workspace/evalrun-gpt
make eval-sweep ENV=.env.llama    OUT=_workspace/evalrun-llama
make eval-sweep ENV=.env.deepseek OUT=_workspace/evalrun-deepseek WORKERS=1 SECS=60
```

Each sweep prints its comparison row; the judge stays pinned via
`--judge-env-file` (defaulting to `.env`). See [README](./README.md) for flags.
