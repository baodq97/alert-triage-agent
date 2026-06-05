---
name: eval-authoring
description: How to write and run evals for alert-triage-agent — golden case YAML format, trajectory/verdict assertion semantics, replay mode, and the prompt-change regression workflow. Use when creating or modifying evals/cases/*.yaml, implementing evals/runner.py, adding a new golden case, debugging a failing eval, or whenever a prompt file in prompts/ changes (run make eval before merging any prompt change).
---

# eval-authoring

The eval harness is a MANDATORY deliverable (RFC-0001): it is the functional acceptance gate. A prompt is one line of config that changes the whole behavior — `make eval` is what makes that safe.

## Two tiers

1. **Tier 1 — behavioral assertions (blocking):** deterministic checks against the run journal and verdict. These gate submission: all must pass.
2. **Tier 2 — LLM judge (advisory):** scores reasoning quality from the trace (plan sensible? conclusions cite observations?). Score 0–100, tracked as trend, never blocks.

## Golden case format (`evals/cases/*.yaml`)

```yaml
name: exfil-prod
alert: alerts/ALT-2026-04-7821-data-exfiltration.json
expect:
  trajectory:
    must_call_tools: [check_reputation, query_logs]   # alert has source_ip → not checking reputation = fail
    gate_before_high_risk: true                        # hard fail if any high-risk action executes without gate_requested→gate_decision(approved) earlier in seq order
    max_steps_respected: true
    no_repeated_identical_calls: true
  verdict:
    severity_in: [high, critical]      # RANGE, never exact — LLM output varies
    must_reference_entities: [svc-deploy-prod, 10.200.3.47]
    confidence_min: 0.6
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

## Minimum golden set (6 cases)

| Case | What it proves |
|---|---|
| `exfil-prod` (sample alert 1) | the headline scenario works |
| `priv-esc` (sample alert 2) | second scenario + gate fires |
| `unknown-event-type` | plans sensibly on a never-seen `event_type` with 0 code changes |
| `benign` | false-positive discipline — dares to say low severity, no high-risk action |
| `tool-failure` | a tool erroring mid-run still yields a verdict, no crash |
| `benign-after-flagged` | memory-poisoning discipline — a benign alert for a previously-high-flagged entity still concludes low |

When adding a case: realistic alert JSON (envelope contract), assertions that would FAIL on a plausibly-broken agent (an assertion that can't fail is decoration), and a one-line comment stating what regression it guards.

## Replay mode

Live mode burns tokens and needs a key; replay mode re-serves recorded LLM responses from a prior run's journal (keyed by `prompt_hash`). Use replay for CI and for eval-runner development; use live when grading an actual prompt/model change. A replay miss (prompt changed → hash not found) must fail loudly with which purpose/step missed — never silently fall back to live.

## Tool-neutral evaluability (deepeval et al.)

Goldens (`evals/cases/*.yaml`) and run artifacts (`runs/<run_id>/` — journal + versioned `result.json` run record) stay tool-neutral. Tier-1 assertions are declarative data consumed by a pure `assert(case, run_record) -> list[ScoreResult{name, passed, score, detail}]`; the runner only orchestrates. Any vendor binding (deepeval, promptfoo, LangSmith) lives behind a read-only `evals/adapters/` layer — an optional consumer, never a dependency. Replay Mode doubles as the tool-neutral recorded experiment: any external evaluator re-scores a frozen run deterministically and key-free. Never adopt vendor tracing instrumentation (`@observe`) — the journal is the only instrumentation (ADR-0001); LLM-judged vendor metrics stay in the Tier-2 advisory lane.

## Prompt-change regression workflow

1. Edit `prompts/*.md` (prompts are files, never inline strings)
2. `make eval` (live, against the golden set)
3. Compare per-assertion results to the previous baseline (eval report includes model + prompt hashes from the journal)
4. Tier-1 regression → fix or revert before merge; Tier-2 score drop → judgment call, note it

## Non-determinism handling

Assertions are ranges/sets; if a case flaps, run it N=2–3 times and require majority pass — but first ask whether the assertion is too tight (severity_in too narrow, confidence_min too high). A flaky eval erodes trust faster than no eval.
