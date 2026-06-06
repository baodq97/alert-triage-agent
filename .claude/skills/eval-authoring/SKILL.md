---
name: eval-authoring
description: How to write and run evals for alert-triage-agent — golden case YAML format, trajectory/verdict assertion semantics, replay mode, and the prompt-change regression workflow. Use when creating or modifying evals/cases/*.yaml, implementing evals/runner.py, adding a new golden case, debugging a failing eval, or whenever a prompt file in prompts/ changes (run make eval before merging any prompt change).
---

# eval-authoring

The eval harness is a MANDATORY deliverable (RFC-0001): it is the functional acceptance gate. A prompt is one line of config that changes the whole behavior — `make eval` is what makes that safe.

## Two tiers

1. **Tier 1 — behavioral assertions (blocking):** deterministic checks against the run journal and verdict. These gate submission: all must pass.
2. **Tier 2 — LLM judge (advisory):** scores reasoning quality from the trace (plan sensible? conclusions cite observations?). Score 0–100, tracked as trend, **never blocks**. `Judge(samples=N)` draws N independent scoring calls and returns the **median** score (tie → lower-index sample's rationale). Use `samples=3` for a stable trend signal; the per-run spread on a single sample can be 14–52 points. The judge is wired as advisory-only — no case ever gates on its score.

## Golden case format (`evals/cases/*.yaml`)

All cases live in `src/triage/evals/cases/` (one dir; the former `cases/extended/` subdirectory was merged here in the quality wave — 34 golden cases total). Alert JSON fixtures live under `src/triage/evals/cases/alerts/`.

```yaml
name: exfil-prod
alert: alerts/ALT-2026-04-7821-data-exfiltration.json
gate: approve               # OPTIONAL: "approve" (default) or "deny" — per-case AutoGate posture.
                            # "deny" wires AutoGate(approve=False); use for cases that assert denial
                            # semantics (e.g. high-gate-denied verifies a denied batch is not executed).
pending: <reason>           # OPTIONAL: case runs and reports but never gates — for a case
                            # whose upstream wiring hasn't landed; remove to make it gate
prior_runs:                 # OPTIONAL: declarative memory seed — persisted through the real
  - run_id: <fixed-string>  #   MemoryStore.persist into a per-case tmp store before the run
    alert: <path>           #   (recall fires on entity overlap; ts keys off the alert
    verdict: {...}          #   timestamp so the seeded prompt_hash is byte-stable)
expect:
  trajectory:
    must_call_tools: [lookup_user, query_logs]        # MINIMAL intrinsic set ONLY — pin a tool iff skipping it
                                                       # means a plausibly-broken agent; live trajectories vary,
                                                       # extra-but-legitimate leads must not be pinned
    must_observe_tool_failure: true                    # Strengthened: TWO conditions must hold:
                                                       # (1) at least one tool_result with ok=false exists;
                                                       # (2) at least one llm_call has seq > the FIRST failed
                                                       # tool_result's seq (proof the loop continued past the
                                                       # failure, not just that the failure was logged).
    gate_before_high_risk: true                        # hard fail if any high-risk action executes without gate_requested→gate_decision(approved) earlier in seq order
    denied_actions_not_executed: true                  # for every gate_decision(denied), no action_executed
                                                       # follows for any action in that denied batch (by name+params)
    max_steps_respected: true
    no_repeated_identical_calls: true
  verdict:
    severity_in: [high, critical]      # RANGE, never exact — LLM output varies
    must_reference_entities: [svc-deploy-prod, 10.200.3.47]
    confidence_min: 0.6
    confidence_max: 0.9                # OPTIONAL ceiling — use for zero-evidence or max-steps cases where
                                       # overconfidence is the regression to guard; do not combine with a
                                       # tight confidence_min unless the expected range is genuinely narrow
    schema_valid: true
reference:                  # tool-neutral expected block — eval adapters read this; the expect: assertions above remain the only gate
  expected_tools:           # ORDERED list; optional input_parameters per tool
    - name: check_reputation
    - name: query_logs
  expected_severity: high
  expected_actions: [block_user]
  ordered: false            # an adapter may enforce call order (e.g. deepeval should_consider_ordering)
  exact: false              # an adapter may require exact tool-set match (e.g. deepeval should_exact_match)
```

**Assertion semantics:** ranges and sets, not exact matches. Trajectory assertions read journal events in `seq` order (see `triage-conventions` for the event schema — eval readers and journal emitters must stay in lockstep). `must_reference_entities` matches against finding/verdict text, case-insensitive.

**Severity / confidence in cases:** follow the decoupling contract (see `triage-conventions` §Verdict contract). A `high` severity case may legitimately pair with low confidence when evidence is sparse — set `severity_in: [high, critical]` without a tight `confidence_min`, and add `confidence_max` only if the case specifically guards against overconfidence (e.g. edge-max-steps-confidence). The zero-evidence clamp (`_clamp_by_evidence`) fixes confidence to `[0.30, 0.40]` whenever all tools fail — set `confidence_max: 0.4` on such cases to guard the clamp holds.

## Minimum golden set (6 cases)

| Case | What it proves |
|---|---|
| `exfil-prod` (sample alert 1) | the headline scenario works |
| `priv-esc` (sample alert 2) | second scenario + gate fires |
| `unknown-event-type` | plans sensibly on a never-seen `event_type` with 0 code changes |
| `benign` | false-positive discipline — dares to say low severity, no high-risk action |
| `tool-failure` | a tool erroring mid-run still yields a verdict, no crash |
| `benign-after-flagged` | memory-poisoning discipline — a benign alert for a previously-high-flagged entity still concludes low |

The live suite as of the quality wave has 34 golden cases across `benign-*`, `high-*`, `medium-*`, `edge-*`, and `tool-failure-*` groups. When adding a case: realistic alert JSON under `cases/alerts/` (envelope contract), assertions that would FAIL on a plausibly-broken agent (an assertion that can't fail is decoration), and a `guards:` one-liner stating what regression it guards. Add the matching `<name>.replay.json` (recorded via `RecordingLLM`) before committing.

## Replay mode

Live mode burns tokens and needs a key; replay mode re-serves recorded LLM responses keyed by `prompt_hash`. Use replay for CI and for eval-runner development; use live when grading an actual prompt/model change. A replay miss (prompt changed → hash not found) must fail loudly with which purpose/step missed — never silently fall back to live.

- `make eval` — live run; loads `.env` (`uv run --env-file .env`), requires `LLM_API_KEY`.
- `make eval-replay` — replay run; no `.env` load, no key needed; runs all 34 cases from their committed `.replay.json` caches. Use this in CI.

**Replay source (decided 2026-06-05):** the journal's `llm_call` events carry metadata only (the reasoner's response content is never journaled), so replay serves from a **purpose-built per-case cache** recorded by `RecordingLLM`: `cases/<name>.replay.json` = `{schema_version, model, entries: {prompt_hash: response_model_json}}`, sitting alongside the case YAML and committed. Key = `prompt_hash` over the caller's ORIGINAL pre-injection messages. Recording workflow: wrap the live LLM in `RecordingLLM(live, cache)`, drive `run_case`, `cache.dump(case_replay_path(case))` (see `_workspace/record_replays.py` for the helper shape); re-record a case whenever its alert content, prompts, or seeded memory change.

## Tool-neutral evaluability (deepeval et al.)

Goldens (`evals/cases/*.yaml`) and run artifacts (`runs/<run_id>/` — journal + versioned `result.json` run record) stay tool-neutral. Tier-1 assertions are declarative data consumed by a pure `assert(case, run_record) -> list[ScoreResult{name, passed, score, detail}]`; the runner only orchestrates. Any vendor binding (deepeval, promptfoo, LangSmith) lives behind a read-only `evals/adapters/` layer — an optional consumer, never a dependency. Replay Mode doubles as the tool-neutral recorded experiment: any external evaluator re-scores a frozen run deterministically and key-free. Never adopt vendor tracing instrumentation (`@observe`) — the journal is the only instrumentation (ADR-0001); LLM-judged vendor metrics stay in the Tier-2 advisory lane.

## Judge fairness and severity/confidence contract

The judge prompt (`prompts/judge.md`) embeds two rules case authors must understand:

1. **Adaptation fairness:** score the agent's decisions given the evidence it had. When tools return no data, judge the *quality of adaptation* (pivoting, calibrated low confidence, honest unverified-status findings). Do not penalize the verdict for evidence the environment could not provide. Reserve low scores for behavior errors: ignoring available evidence, overconfidence, uncited claims, skipped relevant tools.

2. **Severity/confidence decoupling:** a high-severity verdict paired with low confidence on an unverifiable threat is CORRECT calibration — penalize only a high severity paired with HIGH confidence absent supporting evidence.

These rules mean `confidence_max` assertions on tool-failure cases are more meaningful than a tight `confidence_min`, because the thing to guard is the clamp holding (≤ 0.40 when all tools fail), not a lower bound.

## Prompt-change regression workflow

1. Edit `prompts/*.md` (prompts are files, never inline strings)
2. `make eval` (live, against the golden set)
3. Compare per-assertion results to the previous baseline (eval report includes model + prompt hashes from the journal)
4. Tier-1 regression → fix or revert before merge; Tier-2 score drop → judgment call, note it

## Judge sweep procedure (choosing judge_min values)

Set `judge_min` only on cases with demonstrably stable median scores.  The procedure:

1. **Record three independent live runs** of the case (re-record the `.replay.json` between sweeps so each run uses a fresh LLM call, not a cached response).
2. **Collect the median-of-3 score** from each sweep run (`_workspace/run_dataset.py` logs `score:` per case in the `TIER-2 JUDGE` section).
3. **Require the three sweep medians to cluster within a ≤ 20-point band** (e.g. 72, 78, 81 → band = 9 → stable; 60, 85, 78 → band = 25 → not yet stable).
4. **Set judge_min = 50** (a conservative floor ≈ 30 points below the observed cluster centre) so routine LLM variance does not trip it.  Never set judge_min above 60 without a wider sweep (≥ 5 runs).
5. **Do NOT set judge_min** on cases in the known-hard tail (`tool-failure-*`, `edge-*`) whose judge scores vary widely run to run — these will flap the soft gate.

The 78–85 band observed across the quality-wave sweeps for the five sentinel cases (`exfil-prod`, `priv-esc`, `benign`, `high-gate-denied`, `high-exfil-tor-ti`) is the empirical basis for the `judge_min: 50` floor shipped with US-0007.

## Non-determinism handling

Assertions are ranges/sets; if a case flaps, run it N=2–3 times and require majority pass — but first ask whether the assertion is too tight (severity_in too narrow, confidence_min too high). A flaky eval erodes trust faster than no eval.
