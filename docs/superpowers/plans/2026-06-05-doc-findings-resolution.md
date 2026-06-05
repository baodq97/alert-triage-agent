# Doc-Findings Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the 18 confirmed doc-audit findings + US-0005 stretch + 8 eval-portability contracts across 3 governance waves, per the approved spec (`docs/superpowers/specs/2026-06-05-doc-findings-resolution-design.md`).

**Architecture:** Doc-only changes on branch `initial`. Wave 1 edits ungoverned files + open US stories (no governance gate); wave 2 authors ADR-0005 + US-0005 (`proposed`/`open`, `owner: TBD` — Bao flips); wave 3 amends accepted/approved docs (Bao reviews per doc before commit). Cross-doc wording groups land atomically in one commit.

**Tech Stack:** Markdown edits, `npx govkit verify` after every commit, `grep` consistency sweeps, `swe-flow:spec-author` for governed artifacts, `swe-flow:reviewer` for the final pass.

**Non-negotiable constraints (AGENTS.md):** English-only artifacts; no AI-attribution trailers in commits; never flip `status:`/`owner:`; halt if govkit fails.

**Human gates:** after wave 1 (Bao reviews diff) · after wave 2 (Bao flips ADR-0005 status, assigns US-0005 owner) · before each wave-3 commit (Bao approves per-doc diffs) · before any push.

---

### Task 1: Wave 1a — glossary + AGENTS.md edits

**Files:**
- Modify: `UBIQUITOUS_LANGUAGE.md` (3 edits)
- Modify: `AGENTS.md` (1 edit)

- [ ] **Step 1: Glossary — add the L0 row** (decision 3: L0 = raw run telemetry). In the `## Memory` table, insert ABOVE the `Finding Atom (L1)` row:

```markdown
| **Run Journal (L0)** | The raw telemetry of a Run — every recorded event (LLM requests/responses, tool calls/results, gate decisions, lifecycle) as written to the Journal; the substrate L1–L3 derive from | logs, trace (alone) |
```

- [ ] **Step 2: Glossary — fix the "memory" ambiguity line.** Replace:

```markdown
- **"memory"** means the product's L1–L3 layer; the developer-tooling memory plugin is out of domain scope and always named in full (tencentdb-agent-memory).
```

with:

```markdown
- **"memory"** means the product's L0–L3 layer (L0 = Run Journal telemetry); the developer-tooling memory plugin is out of domain scope and always named in full (tencentdb-agent-memory).
```

- [ ] **Step 3: Glossary — backtick fix.** In the `Recommended Action` row, replace `(e.g. `block_user`, rotate key)` with ``(e.g. `block_user`, `rotate_key`)``.

- [ ] **Step 4: AGENTS.md — front-matter note.** In `## Doc chain`, replace:

```markdown
Each carries front-matter
(`id, title, status, owner, date`) and a row in its `INDEX.md`.
```

with:

```markdown
Each carries front-matter
(`id, title, status, owner, date`; User Stories add `priority` — `govkit.yml` holds the
authoritative per-type `required` list) and a row in its `INDEX.md`.
```

- [ ] **Step 5: Verify** — Run: `npx govkit verify`. Expected: `OK — 10 doc(s) checked, 0 violations.` (No commit yet — commit 1a lands after Task 3.)

### Task 2: Wave 1a — triage-conventions edits

**Files:**
- Modify: `.claude/skills/triage-conventions/SKILL.md` (6 edits)

- [ ] **Step 1: Journal common fields — event_id + agent.** Replace:

```markdown
One JSON object per line, append-only, never mutated. Common fields: `seq` (monotonic int), `ts` (ISO-8601), `event`. Event types and their payload fields:
```

with:

```markdown
One JSON object per line, append-only, never mutated. Common fields: `seq` (monotonic int), `event_id` (uuid — adapters bind to ids, not log positions), `ts` (ISO-8601), `event`, `agent` (`"triage"` default; `"threat-intel"` for the US-0005 delegated loop). Event types and their payload fields:
```

- [ ] **Step 2: Journal table — schema_version + result pairing.** Replace the `run_started` row payload `alert_id`, `config` with `alert_id`, `config`, `schema_version`. Replace the `tool_result` row payload `` `step`, `ok`, `data` \| `error` `` with `` `step`, `attempt`, `ok`, `data` \| `error` `` and append this line directly under the table (above the "Renaming a field" line):

```markdown
A `tool_called`→`tool_result` pair shares the same `step` + `attempt` — reconstructable without positional inference (eval adapters depend on this).
```

- [ ] **Step 3: Response-action target invariant.** In `## Investigation tools vs response actions`, append a 4th bullet:

```markdown
- **Target invariant:** `block_user` (and any targeted response action) must reference an entity present in the alert envelope/payload; a verdict whose action target is not an alert entity is rejected before the gate.
```

- [ ] **Step 4: Action shape + RunResult run record.** In `## Verdict contract`, after the existing paragraph, append:

```markdown
`Action = {name, params?, description?}`. `RiskPolicy` classifies on exact `Action.name` match; unmatched names default to high-risk.
```

In `## Ports-first`, in the `Contracts in models.py` bullet, change `RunResult (verdict + gate_decisions + executed_actions + run_id + terminated_reason — what run.py prints and evals read)` to:

```markdown
`RunResult` (verdict + gate_decisions + executed_actions + run_id + terminated_reason — what `run.py` prints and evals read; persisted as a **versioned run record** at `runs/<run_id>/result.json`, which external eval adapters read instead of importing `src/triage`), `Action`,
```

- [ ] **Step 5: Concrete tool retry policy.** In `## Reliability rules`, replace:

```markdown
- Tool errors: transient → retry per tool policy (each attempt journaled); permanent → return as `ToolResult(ok=False, error=...)` observation — the agent adapts; tool errors never crash the run.
```

with:

```markdown
- Tool errors: transient (timeout / 5xx / connection reset) → exactly 1 retry (2 attempts total) with short backoff, each attempt journaled; permanent (schema / not-found / auth) → no retry, return as `ToolResult(ok=False, error=...)` observation — the agent adapts; tool errors never crash the run.
```

- [ ] **Step 6: Resume idempotency rule.** In `## HITL gate`, append:

```markdown
**Resume idempotency:** on `--resume --approve`, execute a high-risk action only if no `action_executed` event exists for it; order is check → execute → record, so a recorded result is reused, never re-applied.
```

- [ ] **Step 7: Verify** — Run: `npx govkit verify`. Expected: OK, 0 violations.

### Task 3: Wave 1a — eval-authoring edits + commit 1a

**Files:**
- Modify: `.claude/skills/eval-authoring/SKILL.md` (3 edits)

- [ ] **Step 1: Golden format — tool-neutral reference block.** In the YAML example, after the `verdict:` block (after `schema_valid: true`), add at the `expect:` sibling level:

```yaml
reference:                  # tool-neutral expected block — eval adapters read this; the expect: assertions above remain the only gate
  expected_tools:           # ORDERED list; optional input_parameters per tool
    - name: check_reputation
    - name: query_logs
  expected_severity: high
  expected_actions: [block_user]
  ordered: false            # an adapter may enforce call order (e.g. deepeval should_consider_ordering)
  exact: false              # an adapter may require exact tool-set match (e.g. deepeval should_exact_match)
```

- [ ] **Step 2: Golden set 5 → 6.** Change heading `## Minimum golden set (5 cases)` to `## Minimum golden set (6 cases)` and add a table row:

```markdown
| `benign-after-flagged` | memory-poisoning discipline — a benign alert for a previously-high-flagged entity still concludes low |
```

- [ ] **Step 3: New section — tool-neutral evaluability.** Append before `## Prompt-change regression workflow`:

```markdown
## Tool-neutral evaluability (deepeval et al.)

Goldens (`evals/cases/*.yaml`) and run artifacts (`runs/<run_id>/` — journal + versioned `result.json` run record) stay tool-neutral. Tier-1 assertions are declarative data consumed by a pure `assert(case, run_record) -> list[ScoreResult{name, passed, score, detail}]`; the runner only orchestrates. Any vendor binding (deepeval, promptfoo, LangSmith) lives behind a read-only `evals/adapters/` layer — an optional consumer, never a dependency. Replay Mode doubles as the tool-neutral recorded experiment: any external evaluator re-scores a frozen run deterministically and key-free. Never adopt vendor tracing instrumentation (`@observe`) — the journal is the only instrumentation (ADR-0001); LLM-judged vendor metrics stay in the Tier-2 advisory lane.
```

- [ ] **Step 4: Verify + commit 1a**

```bash
npx govkit verify
git add UBIQUITOUS_LANGUAGE.md AGENTS.md .claude/skills/triage-conventions/SKILL.md .claude/skills/eval-authoring/SKILL.md
git commit -m "docs: canonize L0 telemetry, tool retry policy, block_user target invariant, eval-portability contracts"
```

Expected: govkit OK; commit succeeds.

### Task 4: Wave 1b — acceptance criteria for open US docs + commit 1b

**Files:**
- Modify: `docs/issues/US-0001-core-agent-loop.md`
- Modify: `docs/issues/US-0002-run-journal-resume.md`
- Modify: `docs/issues/US-0003-eval-harness-memory.md`
- Modify: `docs/issues/US-0004-autonomy-posture-readme.md`

- [ ] **Step 1: US-0001 — malformed-output repair AC.** Append to `## Acceptance criteria`:

```markdown
- [ ] A malformed LLM structured-output response triggers exactly one repair re-prompt; a second malformed response degrades to a lower-confidence/partial verdict — the run never crashes (deterministically testable with `FakeLLM`, no journal-event wording: US-0001 ships `NoopJournal` only)
```

- [ ] **Step 2: US-0002 — resume idempotency AC.** Append:

```markdown
- [ ] On `--resume --approve`, a high-risk action executes only if no `action_executed` event exists for it (check → execute → record); killing the process between execute and record never double-executes on the next resume
```

- [ ] **Step 3: US-0003 — 6th case, assertion purity, adapters seam.** Replace the scope line:

```markdown
`evals/` (runner + 5 golden cases + replay mode), `memory/` (L1 finding atoms, L2 entity dossiers, entity-scoped recall into planner context).
```

with:

```markdown
`evals/` (runner + 6 golden cases + replay mode + read-only `evals/adapters/` seam — external eval tools are optional consumers, never dependencies), `memory/` (L1 finding atoms, L2 entity dossiers, entity-scoped recall into planner context).
```

In AC 1, change `the 5-case golden set (2 samples, unknown-event-type, benign, tool-failure)` to `the 6-case golden set (2 samples, unknown-event-type, benign, tool-failure, benign-after-flagged)`. Append two ACs:

```markdown
- [ ] Golden case `benign-after-flagged`: a benign alert for a previously-high-flagged entity still concludes low severity — recalled memory informs, never dictates
- [ ] Tier-1 assertions are declarative data consumed by a pure `assert(case, run_record) -> list[ScoreResult]`; the runner only orchestrates (a foreign tool reuses the checks without importing the runner)
```

- [ ] **Step 4: US-0004 — watch posture + on-demand synthesis.** Replace the scope line's `run.py --watch <dir>`, with `run.py --watch <dir>` + `--synthesize-posture` (on-demand L3 trigger), and append two ACs:

```markdown
- [ ] Recommend-and-hold: a high-risk action in a watch-mode run never auto-executes — the run exits `awaiting_approval` (the watch adapter wires the resume-capable gate flow, not AutoGate's silent default-deny) and queues for a human `--resume --approve|--deny`
- [ ] `run.py --synthesize-posture` regenerates the L3 posture brief immediately, regardless of cadence — including when `MEMORY_SYNTHESIZE_EVERY_N_RUNS=0`
```

- [ ] **Step 5: Verify + commit 1b**

```bash
npx govkit verify
git add docs/issues/
git commit -m "docs: acceptance criteria — repair path, resume idempotency, watch hold, on-demand synthesis, eval purity"
```

- [ ] **Step 6: HUMAN GATE — present the wave-1 diff (`git diff 3253be6..HEAD --stat` + summary) to Bao; wait for approval before wave 2.**

### Task 5: Wave 2 — ADR-0005 + US-0005 via spec-author + commit

**Files:**
- Create: `docs/adr/ADR-0005-adversarial-alert-content-posture.md`
- Create: `docs/issues/US-0005-threat-intel-agent.md`
- Modify: `docs/adr/INDEX.md`, `docs/issues/INDEX.md`
- Modify: `UBIQUITOUS_LANGUAGE.md` (2 TI rows)
- Modify: `docs/rfc/RFC-0001-agent-architecture.md` (line 84 cross-ref)

- [ ] **Step 1: Author ADR-0005.** Invoke the `swe-flow:spec-author` skill (artifact type: ADR) with the content below. Fallback if the skill is unavailable: write the file verbatim and add the INDEX row by hand. Front-matter MUST stay `status: proposed`, `owner: TBD`.

```markdown
---
id: ADR-0005
title: Adversarial alert content posture — prompt-injection containment
status: proposed
owner: TBD
date: 2026-06-05
---

# ADR-0005 — Adversarial alert content posture

Parent: RFC-0001 (§Security & operational risks).

## Context

Alert content is attacker-controlled input: `description` and every value in `entities`/`context` reach the LLM in the same channel as the agent's instructions, making each alert an indirect prompt-injection vector (OWASP LLM01). Published attacks on AI SOC analysts suppress escalation 20–68% via persona hijack and reach 96% via context manipulation — corrupting exactly this agent's verdict surface. Fixture World ships benign data, but the roadmap connectors (Splunk, VirusTotal, Okta, CMDB) ingest hostile input — "mock data" retires the exercise's input, not the product's threat.

## Decision

Four structural containment properties, cheap enough to hold from wave-1 code:

1. **Separation:** every prompt template delimits and labels untrusted alert payload apart from instructions — a generic wrap, no per-event-type schema (consistent with RFC-0001's rejected alternatives).
2. **Deterministic verdict validation:** `Verdict.severity` is enum-checked, actions pass the RiskPolicy allowlist, and a targeted response action must reference an entity present in the alert (target-entity invariant) — enforced in code, never by LLM judgment.
3. **Read-only mid-loop:** the executor calls only read-only investigation tools; mutations (`block_user`) exist solely in the post-verdict gate flow.
4. **Untrusted recall:** memory injected at planning time is labeled like raw payload, carries source run-id + confidence, and is capped top-N — a poisoned finding from run A cannot silently steer run B.

Out of scope (roadmap): adversarial golden cases, deeper injection hardening, connector-side sanitization.

## Alternatives considered

- **Input sanitization / filtering as primary defense** — rejected: filters chase an open-ended attack space and conflict with "unknown alerts must parse"; separation + output validation bound the blast radius instead.
- **Declaring injection fully out of scope (status quo)** — rejected: the product is positioned as a production-posture OSS worker; the threat is owned in the doc chain, not a README footnote.

## Consequences

- (+) The verdict surface is bounded by deterministic checks even under successful prompt manipulation.
- (+) Properties 1–4 are structural, not model-dependent — they survive model swaps (ADR-0002).
- (−) Delimiting is mitigation, not a security boundary: no guarantee against injection; residual risk accepted for v1, revisited with adversarial evals on the roadmap.
- (−) Small token overhead per prompt from wrapping/labeling.
```

INDEX row to append to `docs/adr/INDEX.md`:

```markdown
| [ADR-0005](./ADR-0005-adversarial-alert-content-posture.md) | Adversarial alert content posture — prompt-injection containment | proposed | TBD | 2026-06-05 |
```

- [ ] **Step 2: Author US-0005.** Same route (spec-author, artifact type: US; fallback verbatim). Front-matter MUST stay `status: open`, `owner: TBD`, `priority: P2`.

```markdown
---
id: US-0005
title: "Stretch: Threat Intel Agent — delegated IOC enrichment"
status: open
owner: TBD
date: 2026-06-05
priority: P2
---

# US-0005 — Stretch: Threat Intel Agent collaboration

Parent: RFC-0001 (§Core loop), ADR-0005. Claims requirements bonus 1 (second specialized agent).

As a SOC analyst, I want external IOCs (public IPs, domains, hashes) enriched by a specialized Threat Intel agent during the investigation, so that the verdict reflects multi-source intelligence one shallow reputation call cannot gather.

**Stretch story:** implement only if D4 has slack — core + eval are never sacrificed for this bonus.

## Scope

A TI mini-loop (own prompt; own read-only TI tools: multi-source reputation, passive-DNS fixture, threat-feed fixture) invoked by the reasoner when an external IOC Entity appears; returns a structured `TIReport` consumed as one Observation. Journal events tagged `agent: "threat-intel"`.

## Acceptance criteria

- [ ] Delegation fires only for external IOC entities (public IP / domain / hash); internal entities never trigger it
- [ ] `TIReport` is schema-validated before the primary loop consumes it, and consumed as untrusted context (ADR-0005 property 4 labeling)
- [ ] The journal shows a readable hierarchical trace: primary events `agent: "triage"`, delegated events `agent: "threat-intel"`
- [ ] The TI result observably influences the next reasoner decision (plan revision or conclusion)
- [ ] With the TI agent disabled (config), the primary loop completes unchanged — delegation is purely additive
- [ ] TI-loop tests green under `make check` (FakeLLM, no live key)
```

INDEX row to append to `docs/issues/INDEX.md`:

```markdown
| [US-0005](./US-0005-threat-intel-agent.md) | Stretch: Threat Intel Agent — delegated IOC enrichment | open | TBD | 2026-06-05 |
```

- [ ] **Step 3: Glossary — TI rows.** In the `## Investigation` table of `UBIQUITOUS_LANGUAGE.md`, append after the `Fixture World` row:

```markdown
| **TI Agent** | The delegated specialist mini-loop a Reasoner may invoke for an external IOC Entity — own prompt, own read-only TI tools, Journal Events tagged `agent: "threat-intel"` | sub-agent, second agent |
| **TIReport** | The schema-validated structured result a TI Agent returns, consumed by the primary loop as one Observation (untrusted context) | intel report, enrichment (alone) |
```

- [ ] **Step 4: RFC line 84 cross-ref.** In `docs/rfc/RFC-0001-agent-architecture.md` `## Security & operational risks`, replace:

```markdown
- Prompt injection via alert `description` is acknowledged and out of scope for the exercise (mock data); a production note in the README covers input sanitization and tool-result quoting.
```

with:

```markdown
- Adversarial alert content (prompt injection via `description` and any `entities`/`context` value) is a real product threat: containment posture is recorded in **ADR-0005** (separation, deterministic verdict validation, read-only mid-loop, untrusted recall). Fixture World data is benign; roadmap connectors ingest hostile input.
```

- [ ] **Step 5: Verify + commit**

```bash
npx govkit verify
git add docs/adr/ docs/issues/ UBIQUITOUS_LANGUAGE.md docs/rfc/RFC-0001-agent-architecture.md
git commit -m "docs: ADR-0005 adversarial alert content posture (proposed) + US-0005 TI agent stretch (open)"
```

Expected: govkit now reports **12 doc(s) checked, 0 violations** (10 + ADR-0005 + US-0005).

- [ ] **Step 6: HUMAN GATE — ask Bao to review ADR-0005 + US-0005, flip ADR-0005 `status:` and assign US-0005 `owner:` (human acts; never do this for him).**

### Task 6: Wave 3a — resume/replay wording sweep (atomic commit)

**Files:**
- Modify: `docs/rfc/RFC-0001-agent-architecture.md` (1 edit)
- Modify: `docs/adr/ADR-0003-event-sourced-run-journal.md` (1 edit)
- Modify: `docs/issues/US-0002-run-journal-resume.md` (2 edits)
- Modify: `.claude/skills/triage-conventions/SKILL.md` (1 edit)

- [ ] **Step 1: RFC.** Replace `` `run.py --resume <run_id>` replays the journal to rebuild state and continues from the last incomplete step `` with `` `run.py --resume <run_id>` rebuilds state from the journal and continues from the last incomplete step ``.

- [ ] **Step 2: ADR-0003.** Replace `Resume replays the journal to rebuild state — completed steps are never re-executed (LLM calls are non-deterministic; recorded results are replayed).` with `Resume rebuilds state from the journal — completed steps are never re-executed (LLM calls are non-deterministic; recorded results are reused).`

- [ ] **Step 3: US-0002.** Replace `` `journal.py` (emit + replay) `` with `` `journal.py` (emit + rebuild for resume) ``; replace `Journal replay test green under `make check`` with `Journal resume/rebuild test green under `make check``.

- [ ] **Step 4: conventions module map.** Replace `journal.py              # append-only JSONL emit + replay/rebuild state` with `journal.py              # append-only JSONL emit + rebuild state for resume`.

- [ ] **Step 5: Consistency grep.** Run: `grep -rni "replay" docs/ .claude/skills/ UBIQUITOUS_LANGUAGE.md`. Expected: every remaining hit is eval **Replay Mode** context (glossary Replay Mode row + flagged-ambiguity line, eval-authoring replay section, RFC §Eval/open-questions, ADR-0003 consequence "Replay mode gives key-free CI", conventions eval pointer). Zero hits describing resume.

- [ ] **Step 6: HUMAN GATE — show Bao the 4-file diff; on approval:**

```bash
npx govkit verify
git add docs/rfc/ docs/adr/ docs/issues/ .claude/skills/triage-conventions/SKILL.md
git commit -m "docs: reserve 'replay' for eval Replay Mode; resume rebuilds state"
```

### Task 7: Wave 3b — remaining amendments to RFC / ADR-0003 / PRD

**Files:**
- Modify: `docs/rfc/RFC-0001-agent-architecture.md` (7 edits)
- Modify: `docs/adr/ADR-0003-event-sourced-run-journal.md` (2 edits)
- Modify: `docs/product/PRD-0001-security-alert-triage-agent.md` (4 edits)

- [ ] **Step 1: RFC §Run journal — drop "tamper-evident".** Replace `1. **Audit trail** — every call captured, tamper-evident ordering (`seq`)` with `1. **Audit trail** — every call captured, append-only with monotonic ordering (`seq`)`.

- [ ] **Step 2: RFC §Memory — untrusted recall.** After the Recall paragraph (`...sharpens the second run's plan.`), append:

```markdown
Recalled atoms/dossiers are **untrusted context**: labeled and delimited like raw alert payload (ADR-0005), carrying source run-id + verdict confidence so the planner can discount them — memory informs, never dictates. L2 dossier injection is capped top-N per alert.
```

- [ ] **Step 3: RFC §Eval — judge caveat + golden set + run record.** Replace `- **Tier 2 — advisory LLM judge:** scores reasoning quality from the trace; tracked as trend, never blocks.` with:

```markdown
- **Tier 2 — advisory LLM judge:** scores reasoning quality from the trace; tracked as trend, never blocks. The judge reads the agent's own narration, so the trend is directional only — spot-checked against a few human-labeled traces; Tier-1 carries all acceptance weight.
```

In the golden-set line, replace `Golden set: 2 sample alerts + 1 unknown event type + 1 benign (false-positive discipline) + 1 tool-failure.` with `Golden set: 2 sample alerts + 1 unknown event type + 1 benign (false-positive discipline) + 1 tool-failure + 1 benign-after-flagged (memory-poisoning discipline).` Then append to the section:

```markdown
- The versioned run record (`runs/<run_id>/result.json`) + Replay Mode form a tool-neutral recorded-experiment substrate: external evaluators (deepeval et al.) re-score frozen runs deterministically and key-free via the read-only `evals/adapters/` seam — optional consumers, never dependencies.
```

- [ ] **Step 4: RFC §Core loop — Action shape.** In the `**HITL:**` bullet, after `unclassified ⇒ high-risk`, insert: `Verdict actions are `Action {name, params?, description?}`; the policy classifies on exact `Action.name` match.` (keep the rest of the bullet unchanged).

- [ ] **Step 5: RFC §Runtime surfaces — watch posture.** Replace `watch mode (`--watch dir/` — autonomous folder ingestion)` with:

```markdown
watch mode (`--watch dir/` — autonomous folder ingestion; **serial**, one run at a time, preserving the single-writer journal/memory posture — concurrent ingestion is roadmap; the watch adapter wires the resume-capable gate flow: a high-risk action exits as `awaiting_approval` for `--resume --approve|--deny`, never auto-executed)
```

- [ ] **Step 6: RFC open questions — gate axes.** Replace `Per-action and tiered gates (approver level scales with risk tier / blast radius) stay on the roadmap` with `Per-action and tiered gates (approver level scales with action reversibility, blast radius, and AI confidence) stay on the roadmap`.

- [ ] **Step 7: ADR-0003 — completed-step rule + seq risk.** In `## Decision`, after `recorded results are reused).` (wording from Task 6), append:

```markdown
A step counts as completed only when its result event is written; a started step with no recorded result is the single re-entry point on resume; a torn final JSONL line is discarded.
```

In `## Consequences`, append:

```markdown
- (−) `seq` gives ordering, not tamper-evidence — a writer with access to `runs/` can renumber undetectably; per-entry hash-chaining (`prev_hash`) is a roadmap item for a future ADR.
```

- [ ] **Step 8: PRD — scope wording (reviewer P1), stretch item, gate axes, golden count.** Replace scope item 3:

```markdown
3. ≥3 mock tools returning realistic stubbed data (`lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`, plus `block_user` as the gated action)
```

with:

```markdown
3. ≥3 mock tools returning realistic stubbed data (`lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`), plus `block_user` as the gated **Response Action** (post-verdict only — never an investigation tool)
```

Append to the `Product-grade additions` list:

```markdown
- **Threat Intel Agent (stretch — claims exercise bonus 1)** — a delegated specialist mini-loop for external IOCs returning a structured TIReport as one Observation (US-0005); core + eval are never sacrificed for it
```

In assumption 4, replace `(approver level by risk tier / blast radius)` with `(approver level by action reversibility, blast radius, and AI confidence)`. In success metrics, replace `(2 sample alerts + 1 unknown event type + 1 benign + 1 tool-failure case)` with `(2 sample alerts + 1 unknown event type + 1 benign + 1 tool-failure + 1 benign-after-flagged case)`.

- [ ] **Step 9: HUMAN GATE — show Bao three per-doc diffs (RFC, ADR-0003, PRD); on approval:**

```bash
npx govkit verify
git add docs/rfc/ docs/adr/ docs/product/
git commit -m "docs: journal ordering wording, untrusted recall, watch posture, gate axes, PRD stretch + vocabulary sync"
```

### Task 8: Final verification + review

**Files:** none (read-only checks)

- [ ] **Step 1: Consistency greps.**

```bash
grep -rni "tamper" docs/ .claude/skills/ UBIQUITOUS_LANGUAGE.md      # expect: only ADR-0003's "not tamper-evidence" risk bullet
grep -rn "L0" docs/ UBIQUITOUS_LANGUAGE.md .claude/skills/            # expect: every hit consistent with glossary L0 = Run Journal telemetry
grep -rn "5-case\|5 golden\|(5 cases)" docs/ .claude/skills/          # expect: zero hits (all counts say 6)
grep -rn "blast radius" docs/                                          # expect: identical axes wording in PRD + RFC
```

- [ ] **Step 2: Full gate.** Run: `npx govkit verify`. Expected: 12 docs, 0 violations.

- [ ] **Step 3: Dispatch `swe-flow:reviewer`** over `3253be6..HEAD` (same brief as the wave-0 review: deterministic floor, change-class lifecycle, domain invariants, agent constraints). Expected: APPROVE or SHIP-WITH-CAVEATS with no P1 left open.

- [ ] **Step 4: HUMAN GATE — report reviewer verdict to Bao; push to `origin/initial` only on his go.**
