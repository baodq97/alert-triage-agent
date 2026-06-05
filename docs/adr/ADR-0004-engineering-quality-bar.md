---
id: ADR-0004
title: Engineering quality bar — strictest lint/type gates, 100% coverage, typed error model
status: accepted
owner: baodq97
date: 2026-06-05
---

# ADR-0004 — Engineering quality bar

Parent: RFC-0001. Applies to all code written under US-0001..0004.

## Context

The codebase is small but graded hard on code quality (15%) and reliability (25%), and is positioned as an OSS-ready product. Quality rules adopted after code exists are retrofits; the bar must be machine-enforced before the first module lands.

## Decision

1. **Coverage: 100% with a pragma policy.** `pytest-cov` gates `make check` at `fail_under = 100` with **branch coverage** enabled. `# pragma: no cover` is allowed only on: CLI `__main__` guards, `TYPE_CHECKING` blocks, and defensive-unreachable code — each pragma carries a one-line reason. Integration tests (end-to-end via journal replay, key-free) count toward coverage where unit mocks would be meaningless. QA audits every pragma as a seam.
2. **Strictest static gates.** ruff `select = ["ALL"]` with a short ignore list, one reason comment per ignore (only rule-conflicts and formatter-conflicts). ty runs with `error-on-warning`; tests may relax specific rules via scoped overrides (e.g. `S101`). Pydantic **strict mode** on alert envelope fields; payload dicts stay flexible per RFC-0001.
3. **Typed error model with boundary conversion.** `src/triage/errors.py` defines `TriageError` → `LLMError`, `ToolError` (transient/permanent), `GateError`, `JournalError`, `ConfigError`. An exception may only be raised inside the module that owns it; at every seam it is converted (tool failure → `ToolResult(ok=False)` observation; LLM retries exhausted → `run_terminated(error)` + partial verdict). No exception crosses two module boundaries. ruff TRY/BLE/EM rules enforce the mechanical part; QA checks the boundary rule.

## Alternatives considered

- **Absolute 100% with zero pragmas** — rejected: spends real schedule on subprocess-testing `__main__` boilerplate instead of behavior.
- **Split bar (core 100% / adapters 90%)** — rejected: two standards in one small repo invite drift and review debate.
- **Result types (Ok/Err) instead of exceptions** — rejected: not idiomatic Python; the boundary-conversion rule achieves the same explicitness at the seams.
- **Curated ruff groups instead of ALL** — rejected as the default, since the requirement is "strictest"; the documented ignore list keeps ALL workable.

## Consequences

- (+) Quality is enforced by `make check`, not by reviewer vigilance; every exception to a rule is visible and justified in `pyproject.toml` or a pragma comment.
- (+) The error-boundary rule makes "tool failure never crashes the run" structurally checkable.
- (−) Wave 1 lands ~10–15% slower (lint noise, branch tests). Accepted: the rubric rewards exactly this.
- (−) ruff ALL pulls in opinionated rules; the ignore list will grow slightly during wave 1 — each addition needs a reason comment, reviewed by QA.
