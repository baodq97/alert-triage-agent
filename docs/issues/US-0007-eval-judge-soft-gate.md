---
id: US-0007
title: "Eval hardening: judge soft-gate, flake hardening, suite hygiene"
status: done
owner: baodq97
date: 2026-06-06
priority: P2
---

# US-0007 — Eval hardening: judge soft-gate + flake hardening + hygiene

Parent: RFC-0001 §Eval (two-tier contract), US-0003. Builds on the judge stabilization
shipped 2026-06-06 (median-of-N sampling, fairness + contract rules — judge spread tamed
from 14–52 to stdev ≈ 9 across the suite). Shares the improvement-wave re-record with
US-0006/US-0008.

As a maintainer changing prompts or loop behavior, I want the advisory judge to catch
reasoning-quality regressions that Tier-1 trajectory checks cannot see — without giving a
stochastic LLM the power to hard-block a merge — so quality regressions surface in CI as a
distinct, overridable signal.

## Scope

- **`judge_min` (per-case, opt-in)** verdict-tier assertion: a case may declare a minimum
  Tier-2 score (median-of-3). Failing `judge_min` NEVER affects Tier-1: the runner exits
  with a DISTINCT code (2) and a clearly-separated WARN section in the report; Tier-1
  failures keep exit 1 and always win. **Consumer scope: `make eval` (the local/developer
  gate) — the repo's CI runs only the govkit doc gates today and does not invoke the
  Python eval suite; wiring the suite into CI is out of scope** (the exit-code contract is
  designed for it when that lands). Wire point: `evaluate_case` (the single seam where
  assertions and judge meet) + `main`'s exit-code logic. Choose initial `judge_min` values
  only for cases whose scores are stable (≥ 60 band, per the 2026-06-06 sweep); never for
  the known-hard tail.
- **exfil-prod live-flake hardening:** one planner-prompt line — network entities (IPs)
  warrant log/reputation coverage — closing the observed trajectory variance (1 failure in
  6 logged live runs) where the IP was never queried and `must_reference_entities` failed.
- **Hygiene:** normalize the 6 original cases' alert paths to the `cases/alerts/`
  convention; consolidate the duplicated capturing-LLM test doubles into one shared test
  helper (conftest); document the judge sweep procedure (median-of-3 over replay records)
  in the eval-authoring skill.

Out of scope: judge as a hard gate (explicitly rejected — LLM flap must not block merges);
new golden cases (US-0008 adds the verify-hook cases).

## Acceptance criteria

- [x] A case with `judge_min: 50` whose median-of-3 score is below 50 → `make eval`
      exits 2, WARN section names the case and scores; Tier-1-only failures still exit 1;
      both failing → exit 1 (Tier-1 wins); all passing → exit 0
- [x] `judge_min` absent → zero behavior change (gating identical to today)
- [x] exfil-prod: 5 consecutive live runs pass `must_reference_entities` (was 1 failure
      in 6 logged live runs); no other case's Tier-1 regresses on the shared re-record
- [x] All 6 original cases' `alert:` paths use the `cases/alerts/` convention; suite green
- [x] One shared capturing-LLM test double; duplicates removed (grep proves it)
- [x] `make check` + `make eval` + `make eval-replay` green after the batched re-record

## Success metric

A deliberate reasoning regression (re-score the suite with the pre-fairness judge prompt,
or an injected low-quality verdict fixture) trips `judge_min` on ≥1 sentinel case with
exit 2, while Tier-1 stays green — proving the soft gate catches what Tier-1 cannot.
