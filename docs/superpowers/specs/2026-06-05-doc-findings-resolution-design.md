# Design: Doc-Findings Resolution (2026-06-05)

Resolve the 18 confirmed findings from the multi-agent doc audit (full report:
`.raws/doc-audit-2026-06-05.md`). Implementation has not started; the governed docs are the
product. `govkit verify` already passes — every change below is content, not metadata.

## Decisions locked (owner: Bao)

1. Pre-existing working-tree edits committed separately first → done, `3253be6`.
2. Prompt-injection posture → new **ADR-0005** (`proposed`, `owner: TBD`) via `spec-author`;
   RFC-0001 line 84 gets a one-line cross-reference instead of the "mock data" dismissal.
3. **L0 is canonical**, defined in the glossary as raw run telemetry: every event of a run
   (LLM request/response, tool call/result, gate decision, run lifecycle) as recorded in the
   journal. L1–L3 derive from it. PRD/RFC keep "L0→L3" unchanged.
4. Watch-mode posture → **recommend-and-hold**: a high-risk action in watch mode exits the run
   at `awaiting_approval` and queues for a human `--resume --approve|--deny`; watch mode never
   auto-executes a high-risk action.

## Constraints

- All committed artifacts in English; no AI attribution in commit messages.
- The agent never flips `status:`/`owner:`; ADR-0005 ships `proposed`/`TBD`, Bao flips.
- `npx govkit verify` after every commit.
- Cross-doc wording groups land atomically in one commit. The US-0002 resume/replay rewording
  therefore moves to wave 3a (with RFC + ADR-0003); its idempotency AC stays in wave 1.

## Wave 1 — editorial + open US docs (2 commits, no governance gate)

Commit 1a (`UBIQUITOUS_LANGUAGE.md`, `AGENTS.md`, `triage-conventions/SKILL.md`):
- [ ] Glossary: add row **L0 — Run Journal (telemetry)** per decision 3; line 105 "L1–L3" → "L0–L3".
- [ ] Glossary: "(e.g. `block_user`, rotate key)" → "(e.g. `block_user`, `rotate_key`)".
- [ ] AGENTS.md §Doc chain: note US docs also require `priority`; point to `govkit.yml` as the
      authoritative per-type `required` list.
- [ ] Conventions, reliability rules: tool retry policy — transient errors (timeout / 5xx /
      connection reset) retry once (2 attempts total) with short backoff; permanent errors
      (schema / not-found / auth) never retry, recorded as a failed Observation.
- [ ] Conventions, response actions: **target invariant** — `block_user` (and any targeted
      response action) must reference an entity present in the alert envelope/payload; a verdict
      whose action target is not an alert entity is rejected before the gate.
- [ ] Conventions, HITL gate: resume idempotency — on `--resume --approve`, execute a high-risk
      action only if no `action_executed` event exists for it; order check → execute → record.
- [ ] Conventions, contracts: `Action = {name, params?, description?}`; RiskPolicy classifies on
      exact `Action.name` match (unmatched ⇒ high-risk); add `Action` to the `models.py` ports list.

Commit 1b (US docs, all `open` — normal authoring):
- [ ] US-0001 AC: a malformed LLM structured-output response triggers exactly one repair
      re-prompt; a second malformed response degrades to a lower-confidence/partial verdict; the
      run never crashes. (No journal-event wording — US-0001 has `NoopJournal` only.)
- [ ] US-0002 AC: resume idempotency (mirror of the conventions rule above).
- [ ] US-0003 AC: 6th golden case — benign alert for a previously-high-flagged entity; the
      verdict can still conclude low (guards memory-poisoning bias).
- [ ] US-0004 AC: recommend-and-hold per decision 4, naming which gate the watch adapter wires.
- [ ] US-0004 scope + AC: on-demand L3 synthesis flag (e.g. `run.py --synthesize-posture`)
      works regardless of cadence, including `MEMORY_SYNTHESIZE_EVERY_N_RUNS=0`.

## Wave 2 — ADR-0005 (1 commit, authored via `spec-author`)

- [ ] ADR-0005 "Adversarial alert content posture", `status: proposed`, `owner: TBD`, INDEX row.
  - Context: alert `description` + all `entities`/`context` values are attacker-controlled LLM
    input; published attacks: persona hijack suppresses escalation 20–68%, context manipulation
    96%. Fixture World is benign; roadmap connectors are hostile — "mock data" retires the
    exercise's input, not the product's threat.
  - Decision — four structural properties from wave-1 code: (1) prompts delimit + label untrusted
    payload apart from instructions (generic wrap; no per-event schema); (2) deterministic verdict
    validation (severity enum, RiskPolicy action allowlist, target-entity invariant);
    (3) read-only tools mid-loop (records `3253be6`); (4) recalled memory treated as untrusted,
    labeled + capped top-N.
  - Out of scope: adversarial eval cases, deeper injection hardening → roadmap.
  - Consequences: delimiting is mitigation, not a security boundary; no injection guarantee;
    small token overhead per prompt.
- [ ] RFC-0001 line 84: replace the "out of scope (mock data)" wording with a cross-reference to
      ADR-0005.
- Human gate: Bao reviews and flips ADR-0005 status.

## Wave 3 — amendments to accepted/approved docs (2 commits, per-doc review by Bao)

Commit 3a — resume/replay wording sweep (atomic across 3 docs):
- [ ] RFC-0001 line 40: "replays the journal" → "rebuilds state from the journal".
- [ ] ADR-0003 line 19: "Resume rebuilds state from the journal — recorded results are reused."
- [ ] US-0002 lines 18, 26: "emit + rebuild for resume" / "resume/rebuild test".
- "Replay" is thereafter reserved for the eval Replay Mode (glossary rule).

Commit 3b — remaining amendments:
- [ ] RFC-0001 §Memory: recalled atoms/dossiers are untrusted context — labeled/delimited like
      raw payload, carried with source run-id + verdict confidence ("memory informs, never
      dictates"); L2 dossier injection capped top-N.
- [ ] RFC-0001 watch-mode clause: serial processing (single-writer; no cross-run locking for
      L1/L2; concurrent ingestion stays roadmap) + which gate the watch adapter wires.
- [ ] RFC-0001 line 78: tiered-gate axes → "action reversibility, blast radius, and AI confidence".
- [ ] RFC-0001 near line 31: `Action` contract (mirror conventions).
- [ ] RFC-0001 §Eval Tier-2: judge reads the agent's own narration → directional trend only,
      spot-checked against a few human-labeled traces; Tier-1 carries all acceptance weight.
- [ ] ADR-0003 (+ RFC line 38 if present): "tamper-evident" → "append-only with monotonic
      ordering (`seq`)"; risk bullet: `seq` gives ordering, not tamper-evidence; per-entry
      hash-chaining (`prev_hash`) is a roadmap item for a future ADR.
- [ ] ADR-0003 completed-step rule: a step counts completed only when its result event is
      written; a started step with no recorded result is the single re-entry point on resume; a
      torn final JSONL line is discarded.
- [ ] PRD-0001 Non-goals: decline the requirements bonus "second specialized agent" — single-agent
      depth over multi-agent breadth; the ToolRegistry/DataSource seam keeps a future
      collaborating agent additive.
- [ ] PRD-0001 assumption 4: sync tiered-gate axes wording with RFC line 78.
- PRD memory numbering needs no edit (L0 canonized in glossary, wave 1).

## Verification

- `npx govkit verify` after every commit (PreToolUse `audit-write` hook also active).
- Post-wave-3 consistency greps: "replay" only in eval Replay Mode context; "tamper" gone except
  the hash-chain roadmap bullet; "L0" matches the glossary definition everywhere; gate-axes
  wording identical in PRD and RFC.
- Final: `swe-flow:reviewer` over the full diff from `3253be6` (change-class lifecycle gates,
  domain invariants) → APPROVE / SHIP-WITH-CAVEATS / BLOCK before any push.

## Human gates

1. Bao reviews wave-1 diff.
2. Bao flips ADR-0005 status after review.
3. Bao reviews wave-3 diffs per doc.
4. Push to `origin/initial` only on Bao's go.
