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

| Model | Endpoint | Tier-1 | Judge (pinned) | stdev | wall/case | tok/case |
|---|---|---|---|---|---|---|
| gpt-5.4-mini | Azure AI Foundry | **35/35** | 83.8 | 3.1 | 12.0s | 14.8k |
| Llama-3.3-70B-Instruct | Azure AI Foundry | 31/35 | 78.6 | 5.7 | 17.3s | 11.6k |
| deepseek-v4-flash | OpenRouter | 29/35 | 83.3 | 3.4 | 80.4s | 19.6k |

(The cross-model matrix was run over the original 35 cases, before the US-0009
memory case was added; the baseline column reproduces the gpt-5.4-mini result on
that same 35-case set — 35/35, judge 83.8 — confirming the quality-loop gains are
stable across independent runs.)

### How to read this

- **The swap works.** The full agent loop — plan, ReAct tool use, verdict,
  verify hook, gate, memory — runs end-to-end on all three models with no code
  change. That is the requirements-bonus claim, demonstrated.
- **Tier-1 35/35 holds only on the calibrated model.** The golden cases' ranges
  were tuned against gpt-5.4-mini; Llama and DeepSeek **degrade gracefully**
  (31, 29) rather than crashing — the never-crash verdict, the zero-evidence
  confidence clamp, and the verify hook keep every run shipping a valid verdict.
  This is honest portability data, not a "every model is perfect" claim.
- **Why deterministic Tier-1 gates and the judge only advises.** DeepSeek's
  judge score (83.3) is essentially gpt's (83.8) — its *reasoning* is strong —
  yet its Tier-1 is 29/35. The failures cluster on `confidence_min` /
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
