// .claude/workflows/sdlc.js — the SDLC capstone workflow.
// Orchestrates the doc chain PRD -> RFC -> ADR -> US -> (Foundation) -> Code as a
// deterministic script, one reviewer-gated phase at a time.
//
// MANDATORY FALLBACK — workflows are research-preview and globally disableable
// (disableWorkflows / CLAUDE_CODE_DISABLE_WORKFLOWS=1), and cannot be bundled in a
// plugin (no `workflows` field in plugin.json). If this script does not run, drive
// the same order BY HAND: invoke the swe-flow spec-author skill for each artifact,
// then fan out implementers. Nothing is lost — the govkit PreToolUse hook + CI
// `govkit verify` enforce every gate regardless. The workflow is an accelerant,
// not the source of truth.
//
// VERIFIED CONSTRAINT (a): this script has NO filesystem/shell access. Every read
// and write is done by a dispatched agent; the script only sequences them.
// VERIFIED CONSTRAINT (b): this script NEVER shells out to govkit. Determinism lives
// in the PreToolUse hook + CI. The in-band gate here is the reviewer agent's verdict,
// which controls CONTROL FLOW only (does the workflow advance?) — it never flips a
// doc `status:` (that stays a human act; root AGENTS.md § Agent constraints).
//
// AGENT DISPATCH: plugin-namespaced types only. Project .claude/agents are NOT in the
// workflow agentType registry (verified empirically) — only built-in + plugin agents
// are. So the swe-flow plugin must be installed for swe-flow:* to resolve. The
// authoring phases dispatch a default agent guided to follow the spec-author skill's
// rules (a skill is not a dispatchable agentType).

export const meta = {
  name: "sdlc",
  description:
    "Drive the doc chain PRD -> RFC -> ADR -> US -> Foundation -> Code, one " +
    "reviewer-gated phase at a time; fan out file-disjoint implementer packages " +
    "in dependency-ordered waves during the Code phase.",
  phases: ["PRD", "RFC", "ADR", "US", "Foundation", "Code"],
  // args (global): { feature, skipPrd, skipAdr }
  //   feature  — one-line feature/problem statement seeding the chain.
  //   skipPrd  — true when there is no revenue/legal/compliance impact (PRD optional).
  //   skipAdr  — true when no arch/vendor/runtime decision is needed.
};

const REVIEWER = "swe-flow:reviewer";
const IMPLEMENTER = "swe-flow:implementer";
const feature = args?.feature || "the requested change";

// Reviewer verdict. APPROVE/SHIP-WITH-CAVEATS advance; BLOCK halts the workflow.
// proposedNextStatus is a PROPOSAL only — a human doc owner flips status, never this.
const reviewerSchema = {
  type: "object",
  required: ["verdict", "findings"],
  properties: {
    verdict: { enum: ["APPROVE", "SHIP-WITH-CAVEATS", "BLOCK"] },
    findings: { type: "array", items: { type: "string" } },
    proposedNextStatus: { type: "string" },
  },
};

// What an authoring phase returns: the artifact it wrote (so the reviewer can verify
// front-matter without the workflow touching the filesystem).
const artifactSchema = {
  type: "object",
  required: ["path", "id", "startStatus"],
  properties: {
    path: { type: "string" },
    id: { type: "string" },
    startStatus: { type: "string" },
    owner: { type: "string" }, // must be "TBD"
  },
};

// US backlog: each story carries its priority, the ids it blocks, and its disjoint
// allowed paths — the inputs the Code phase needs to schedule a safe fan-out.
const backlogSchema = {
  type: "object",
  required: ["stories"],
  properties: {
    stories: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "priority", "allowedPaths"],
        properties: {
          id: { type: "string" },
          priority: { enum: ["P0", "P1", "P2"] },
          blocks: { type: "array", items: { type: "string" } },
          allowedPaths: { type: "array", items: { type: "string" } },
        },
      },
    },
  },
};

// FIX (reviewer P1 #1): the gate is PHASE-AWARE. Doc phases verify front-matter /
// start-status / INDEX sync; the Code phase verifies delivery semantics instead.
// One generic prompt asking doc-status questions of a code fan-out was the bug.
async function reviewGate(label, phase, criteria, payload) {
  const verdict = await agent(
    `You are swe-flow:reviewer (read-only). Gate the ${phase} phase. ${criteria}\n\n` +
      `You classify and return a verdict; you do NOT edit, approve as code-owner, ` +
      `merge, or flip any status. Subject: ${JSON.stringify(payload)}`,
    { label, phase, schema: reviewerSchema, agentType: REVIEWER },
  );
  if (verdict.verdict === "BLOCK") {
    throw new Error(`Phase ${phase} BLOCKED: ${verdict.findings.join("; ")}`);
  }
  return verdict;
}

// An authoring phase: dispatch a default agent guided to follow the spec-author
// skill's rules (owner: TBD, START status only, INDEX row, govkit verify), then gate.
async function authorArtifact(type, phaseName, criteria) {
  const art = await agent(
    `Follow the swe-flow spec-author skill to author a ${type} for: "${feature}". ` +
      `Discover the doc dir + required front-matter from the consumer's govkit.yml. ` +
      `Set owner: TBD and the START status for a ${type} (never advanced). Add the ` +
      `INDEX.md row. Then run \`npx govkit verify\` and fix until clean. Return the ` +
      `artifact descriptor.`,
    { label: `author:${type}`, phase: phaseName, schema: artifactSchema },
  );
  await reviewGate(`gate:${type}`, phaseName, criteria, art);
  return art;
}

const DOC_CRITERIA =
  "Confirm: correct START status for the type, owner: TBD (no self-assign), every " +
  "required front-matter key present, and an INDEX.md row whose status matches. " +
  "BLOCK on a missing required artifact for the change class or a self-flipped status.";

// FIX (reviewer P1 #2): order the fan-out by `blocks:` into dependency waves. A story
// that blocks another lands in an earlier wave; within a wave, P0 first. Two stories
// in the same wave must be file-disjoint (they were specified that way) — a blocks:
// coupling forces them into different waves rather than a single racing parallel().
function buildWaves(stories) {
  const blockedBy = new Map(stories.map((s) => [s.id, new Set()]));
  for (const s of stories) {
    for (const t of s.blocks || []) {
      if (blockedBy.has(t)) blockedBy.get(t).add(s.id);
    }
  }
  const order = { P0: 0, P1: 1, P2: 2 };
  const done = new Set();
  const waves = [];
  let remaining = stories.slice();
  while (remaining.length > 0) {
    const ready = remaining.filter((s) => [...blockedBy.get(s.id)].every((b) => done.has(b)));
    const wave = (ready.length > 0 ? ready : remaining) // fall back to all on a cycle
      .slice()
      .sort((a, b) => order[a.priority] - order[b.priority]);
    waves.push(wave);
    for (const s of wave) done.add(s.id);
    remaining = remaining.filter((s) => !done.has(s.id));
  }
  return waves;
}

// ---- Run -------------------------------------------------------------------

phase("PRD");
if (!args?.skipPrd) {
  await authorArtifact("PRD", "PRD", DOC_CRITERIA);
} else {
  log("[PRD] skipped — no revenue/legal/compliance impact declared.");
}

phase("RFC");
const rfc = await authorArtifact("RFC", "RFC", DOC_CRITERIA);

phase("ADR");
if (!args?.skipAdr) {
  await authorArtifact("ADR", "ADR", DOC_CRITERIA);
} else {
  log("[ADR] skipped — no arch/vendor/runtime decision declared.");
}

phase("US");
const backlog = await agent(
  `Follow the swe-flow spec-author skill to break "${feature}" (RFC ${rfc.id}) into a ` +
    `User Story backlog. Emit each US doc (owner: TBD, status: open, priority, INDEX row) ` +
    `and run \`npx govkit verify\`. Return the structured backlog: for each story its id, ` +
    `priority, the ids it blocks, and its file-disjoint allowedPaths.`,
  { label: "author:US", phase: "US", schema: backlogSchema },
);
await reviewGate("gate:US", "US", DOC_CRITERIA, { count: backlog.stories.length });

// FIX (reviewer P1 #3): an explicit in-band Foundation step. The lead authors the
// shared domain core + the contracts members code against + a test skeleton BEFORE any
// fan-out — "until this exists there is nothing stable to fan out from" (swe-flow.md).
phase("Foundation");
const foundation = await agent(
  `You are swe-flow:implementer. Author ONLY the shared FOUNDATION for "${feature}": the ` +
    `domain core / public contracts every US package will code against, plus a test ` +
    `harness skeleton that defines "green". Write files only; never run bun/git/govkit ` +
    `(the lead integrates). Return a files-written summary.`,
  { label: "foundation", phase: "Foundation", agentType: IMPLEMENTER },
);
await reviewGate(
  "gate:Foundation",
  "Foundation",
  "Confirm the foundation defines the contracts + test harness members will rely on, " +
    "is internally coherent, and leaves no member needing to invent shared scaffolding.",
  foundation,
);

// Code: fan out file-disjoint implementer packages in dependency-ordered waves.
phase("Code");
const waves = buildWaves(backlog.stories);
log(`[Code] ${backlog.stories.length} stories across ${waves.length} wave(s).`);
const CODE_CRITERIA =
  "Judge DELIVERY, not doc status: every P0 story in this wave delivered => may advance; " +
  "any missing P0 => BLOCK; missing P1 => SHIP-WITH-CAVEATS. Confirm a production-parity " +
  "test for any services/*/src or apps/*/src writes, allowed-paths honoured, and surface " +
  "any halted member.";
for (let w = 0; w < waves.length; w++) {
  const wave = waves[w];
  await parallel(
    wave.map(
      (story) => () =>
        agent(
          `You are swe-flow:implementer. Build US ${story.id} (${story.priority}). Edit ONLY ` +
            `its allowed paths: ${JSON.stringify(story.allowedPaths)} — disjoint from the other ` +
            `members in this wave. Write files only; never run bun/git/govkit. Match neighbour ` +
            `style; halt-and-document if blocked. Return a files-written summary.`,
          { label: `code:${story.id}`, phase: "Code", agentType: IMPLEMENTER },
        ),
    ),
  );
  await reviewGate(`gate:Code:w${w + 1}`, "Code", CODE_CRITERIA, {
    wave: w + 1,
    stories: wave.map((s) => s.id),
  });
}

log(
  "[sdlc] chain complete — lead now integrates: bun install, bun run check (govkit verify), commit.",
);
