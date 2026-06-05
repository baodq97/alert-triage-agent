#!/usr/bin/env node
// SessionStart freshness advisory — guards the stale-branch class: a session that
// starts on a branch N commits behind its upstream can have whole waves of work
// invalidated (aiquinta retro RC4: 28-commits-behind wiped a parallel-agent wave).
//
// Advisory ONLY, by design (AGENTS.md invariant: enforcing hooks are the govkit
// CLI's job). Every failure path — not a repo, offline, no remote, no upstream,
// detached HEAD, fetch timeout — is a silent exit 0; this hook must never block
// or delay a session for long. Node (not shell) so Windows checkouts behave
// identically (CRLF/quoting), matching the audit-write hook's invocation style.
import { execFileSync } from "node:child_process";

function git(args, timeout = 5_000) {
  return execFileSync("git", args, {
    timeout,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

try {
  git(["rev-parse", "--is-inside-work-tree"]);
  // Bounded network call; offline/no-remote must not block session start.
  git(["fetch", "--quiet"], 15_000);
  const branch = git(["rev-parse", "--abbrev-ref", "HEAD"]);
  const [behind, ahead] = git(["rev-list", "--left-right", "--count", "@{upstream}...HEAD"])
    .split(/\s+/)
    .map(Number);
  if (behind > 0) {
    // stdout from a SessionStart hook is injected into the session context.
    console.log(
      `FRESHNESS WARNING: branch '${branch}' is ${behind} commit(s) BEHIND its upstream` +
        (ahead > 0 ? ` (and ${ahead} ahead)` : "") +
        `. Reconcile (pull/rebase) before building on it — work layered on a stale branch can be invalidated wholesale.`,
    );
  }
} catch {
  // Advisory hook: any git/network failure is a no-op, never an error surface.
}
process.exit(0);
