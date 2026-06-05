# Ubiquitous Language

Canonical vocabulary for the alert-triage-agent. Every doc, prompt, identifier, journal event, and conversation uses these terms — agents and humans alike. Source of truth alongside PRD-0001/RFC-0001; the `triage-conventions` skill carries the technical contracts behind these words.

## Alert intake

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Alert** | A JSON-described suspicious event submitted for investigation | incident, ticket, event (alone) |
| **Envelope** | The six stable, typed Alert fields (`alert_id`, `timestamp`, `source`, `severity_hint`, `event_type`, `description`) | header, metadata |
| **Payload** | The flexible per-alert dicts `entities` and `context`, passed to the LLM untouched | body, details |
| **Entity** | A concrete subject named in the Payload (user, IP, asset, endpoint) that tools and memory key on | subject, IOC, asset (alone) |
| **Severity Hint** | The upstream system's severity guess in the Envelope — input, never the conclusion | severity (when meaning the hint) |

## Investigation

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Run** | One complete investigation of one Alert, identified by `run_id` | session, execution, job |
| **Investigation Plan** | The LLM-generated, structured sequence of intended Plan Steps for a Run | playbook, workflow, strategy |
| **Plan Step** | One intended tool action within an Investigation Plan | task, stage |
| **Step** | One iteration of the executor loop, counted against `MAX_STEPS` | turn, cycle |
| **Tool** | A callable capability with a JSON schema and a Risk Tier (`lookup_user`, `query_logs`, `check_reputation`, `get_asset_info`, `block_user`) | function, action (for lookups) |
| **Observation** | The result of one tool call as seen by the agent, including errors (`ToolResult`) | output, response |
| **Reasoner** | The LLM decision after each Observation: continue, revise the plan, or conclude | judge (reserved for evals) |
| **Fixture World** | The internally-consistent mock dataset behind all tools — every Entity tells the same story everywhere | stub data, mocks (alone) |

## Verdict and actions

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Finding** | One evidence-backed fact derived from Observations, citing its source | insight, result |
| **Verdict** | The structured conclusion of a Run: Severity, Findings, Recommended Actions, Confidence (and `terminated_reason` when early) | report, summary, output |
| **Severity** | The agent's concluded rating: `low / medium / high / critical` | priority, level |
| **Confidence** | The agent's 0–1 self-assessment attached to the Verdict | certainty, score (alone) |
| **Recommended Action** | A response the Verdict proposes (e.g. `block_user`, rotate key) | remediation, fix |
| **High-risk Action** | A Recommended Action whose Risk Tier requires the Approval Gate before execution | dangerous action, critical action |

## Human-in-the-loop

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Risk Policy** | The YAML config mapping actions to Risk Tiers; unclassified defaults to high-risk | rules, allowlist |
| **Risk Tier** | An action's risk class assigned by the Risk Policy | risk level, category |
| **Approval Gate** | The single per-Run pause where all High-risk Actions are batched for a human decision (one gate per Run, after the Verdict) | HITL (alone), checkpoint, review |
| **Gate Decision** | The human outcome at the Approval Gate: approved (execute immediately) or denied (recorded; Verdict still ships) | sign-off, confirmation |
| **Zero-touch** | A Run that completes with no Approval Gate because no High-risk Action was recommended | auto-resolved, unattended |

## Runtime record

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Journal** | The append-only JSONL record of one Run — every LLM call, tool attempt, gate event, and the Verdict | log, audit trail, history |
| **Journal Event** | One ordered (`seq`) line in the Journal | entry, record |
| **Resume** | Continuing an interrupted Run by rebuilding state from its Journal; completed work is never re-executed | restart, retry (of a run) |
| **Awaiting Approval** | The persisted Run state between a Gate request and its Gate Decision (`--resume --approve\|--deny` completes it) | paused, pending (alone) |
| **Trajectory** | The ordered sequence of Journal Events of a Run, as read by evals | trace, path |

## Memory

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Finding Atom (L1)** | One Entity-keyed fact persisted from a Verdict's Findings | memory, note |
| **Entity Dossier (L2)** | The deterministic aggregation of all Finding Atoms for one Entity | profile, history |
| **Threat Posture (L3)** | The org-level synthesized brief (known-bad entities, recurring patterns), cadence set by config | global memory, summary |
| **Recall** | Injecting only the Finding Atoms / Dossiers matching the current Alert's Entities (plus the Posture brief) into planner context | context loading, RAG |

## Evals

| Term | Definition | Aliases to avoid |
| --- | --- | --- |
| **Golden Case** | One YAML eval case: an Alert plus expected Trajectory and Verdict assertions | test case (for evals), scenario |
| **Behavioral Assertion** | A deterministic, blocking (Tier-1) check on a Trajectory or Verdict — ranges and sets, never exact matches | validation, check (alone) |
| **Judge** | The advisory (Tier-2) LLM scoring of reasoning quality from a Trajectory — never blocks | reviewer, grader |
| **Replay Mode** | Serving recorded LLM responses (keyed by prompt hash) so evals run key-free and deterministically | cache mode, offline mode |

## Relationships

- An **Alert** starts exactly one **Run**; a **Run** produces exactly one **Verdict** (partial on early termination).
- An **Investigation Plan** contains **Plan Steps**; the executor consumes them as **Steps**, and a **Reasoner** decision follows every **Observation**.
- A **Verdict** contains **Findings** and **Recommended Actions**; **High-risk Actions** pass through the single **Approval Gate**.
- Every **Run** writes one **Journal**; **Resume**, **Trajectory**, and **Replay Mode** all read it.
- **Findings** become **Finding Atoms**, which aggregate into **Entity Dossiers** and synthesize into the **Threat Posture**; **Recall** feeds them back into planning.

## Example dialogue

> **Dev:** "Alert 7821 came in — does the **Severity Hint** decide if we gate?"
> **Domain expert:** "No. The hint is intake input. The **Verdict**'s **Severity** is the agent's own conclusion, and gating isn't about severity at all — only a **High-risk Action** under the **Risk Policy** triggers the **Approval Gate**."
> **Dev:** "If `check_reputation` times out mid-**Run**, do we fail it?"
> **Domain expert:** "Never. The timeout comes back as an **Observation** with an error; the **Reasoner** adapts — maybe a different **Plan Step**, maybe conclude with lower **Confidence**. Every attempt lands in the **Journal** either way."
> **Dev:** "And if the analyst goes home before deciding?"
> **Domain expert:** "The Run persists as **Awaiting Approval**. Tomorrow they **Resume** with a **Gate Decision** — nothing re-executes, the Journal already holds the completed work."
> **Dev:** "How do I know my prompt change didn't break this flow?"
> **Domain expert:** "Run the **Golden Cases**. The **Behavioral Assertions** check the **Trajectory** — gate-before-execution, tools called, severity range — in **Replay Mode**, no key needed."

## Flagged ambiguities

- **"replay"** was used for two things: rebuilding Run state when resuming, and serving cached LLM responses in evals. Canonical: the first is **Resume** (never "replay"); only the eval mechanism is **Replay Mode**.
- **"step"** collided: a planned tool action vs an executor-loop iteration (what `MAX_STEPS` counts). Canonical: **Plan Step** for the former, **Step** for the latter.
- **"agent"** means the triage product in all repo docs. The Claude Code build agents (`triage-implementer`, `triage-qa`) are **build agents** — never plain "agent" in repo prose.
- **"eval"** means the agent eval harness (`make eval`). The docs-governance gate is always called **govkit eval** in full.
- **"severity"** alone was ambiguous between intake hint and conclusion. Canonical: **Severity Hint** (input) vs **Severity** (Verdict field).
- **"memory"** means the product's L1–L3 layer; the developer-tooling memory plugin is out of domain scope and always named in full (tencentdb-agent-memory).
