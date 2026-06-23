/**
 * Beads (bd) tool — typed interface for beads operations.
 *
 * Wraps bd CLI with policy enforcement.
 * Used by:
 *   - `prx tools bd exec` (CLI entry point, replaces scripts/bd-safe)
 *   - Internal callers (direct function calls)
 *
 * @module
 */

import { z } from "zod";

import { getEnv, processEnv } from "@bounded-systems/env";
import {
  captureFailureDetail,
  isCaptureFailure,
  spawnCapture,
  type SpawnCaptureFn,
  type SpawnCaptureResult,
} from "@bounded-systems/proc";
import {
  checkPolicy,
  isBlocked,
  type PolicyState,
  type PolicyRole,
  type PolicyDecision,
} from "@bounded-systems/policy";

import {
  bdShowOutputSchema,
  bdDuplicatesClusterMemberSchema,
  bdDuplicatesClusterSchema,
  bdDoctorIssueSchema,
  bdDoctorReportSchema,
  bdMergeResultSchema,
} from "./schemas.js";
import type {
  BdShowOutput,
  BdDuplicatesClusterMember,
  BdDuplicatesCluster,
  BdDoctorIssue,
  BdDoctorReport,
  BdMergeResultPayload,
} from "./types.generated.js";

// Re-export public types from dependencies
export type { SpawnCaptureResult, SpawnCaptureFn } from "@bounded-systems/proc";
export type {
  PolicyState,
  PolicyRole,
  PolicyDecision,
} from "@bounded-systems/policy";

// Re-export generated types
export type {
  BdShowOutput,
  BdDuplicatesClusterMember,
  BdDuplicatesCluster,
  BdDoctorIssue,
  BdDoctorReport,
  BdMergeResultPayload,
};

/**
 * Result from executing a bd subcommand with optional policy enforcement.
 * Contains exit code, stdout/stderr, and the policy decision that was made.
 */
export type BdExecResult = {
  /** Exit code from the bd process. */
  exitCode: number;
  /** Standard output from bd. */
  stdout: string;
  /** Standard error from bd or the wrapper. */
  stderr: string;
  /** Policy decision for this operation, or null if no policy was checked. */
  policy: PolicyDecision | null;
};

/**
 * Options for executing a bd subcommand via execBd.
 */
export type BdExecOptions = {
  /** The bd subcommand to execute (e.g., "show", "update", "list"). */
  subcommand: string;
  /** Arguments to pass to the subcommand. */
  args: string[];
  /** Working directory for the bd process. */
  cwd?: string | undefined;
  /** Optional policy state to enforce; defaults to env.PRX_CAPABILITY_STATE or "validating". */
  state?: PolicyState | undefined;
  /** Optional policy role to enforce; defaults to env.PRX_AGENT_ROLE or "executor". */
  role?: PolicyRole | undefined;
};

/**
 * Environment variables that control bd execution and policy enforcement.
 */
export type BdExecEnv = {
  /** Serialized policy state (e.g., "validating", "planning", "implementing"). */
  PRX_CAPABILITY_STATE?: string;
  /** Policy role identifier (e.g., "planner", "executor", "reviewer"). */
  PRX_AGENT_ROLE?: string;
  /** Base directory for beads data (cleared during spawn to isolate from ~/.config/worktrunk). */
  BEADS_DIR?: string;
  /**
   * The beadsd door name, set by the box profile (prx-asr / prx-634). Its
   * presence flips {@link execBd} into door mode: no local `bd` binary is
   * spawned — bd-backed work routes through the door or fails closed. Empty /
   * unset = host profile (spawn `bd` as before).
   */
  PRX_BEADS_DOOR?: string;
  /** Arbitrary environment variables passed to the bd process. */
  [key: string]: string | undefined;
};

const ALLOWED_SUBCOMMANDS = [
  "ready",
  "list",
  "show",
  "view",
  "create",
  "update",
  "claim",
  "reopen",
  // GH-1874: `assign` is the bd-canonical write for the assignee column —
  // shorthand for `bd update <id> --assignee <name>` (empty string clears).
  // Trust class matches `update`/`create`/`claim`: planner-only at the
  // policy layer (src/tools/policy.ts). The bd→GH mirror's `push()` projects
  // the bd assignee through the normal sync cadence.
  "assign",
  // GH-1003: memory surface — recall (read by key), remember (upsert),
  // memories (list/search). `forget` (destructive) is intentionally absent.
  "recall",
  "remember",
  "memories",
  // GH-1351: typed dep edges (parent-child / blocks). Required by
  // `prx triage promote-children` to wire manifest-declared edges. The
  // bd `dep` group itself contains read+write subcommands; per-arg policy
  // remains in tools/policy.ts.
  "dep",
  // GH-1573: read-only SQL projection over the beads store. `bd sql` accepts
  // raw SQL; the wrapper enforces read-only by injecting `--readonly` below
  // before spawn, so the safety boundary is owned here rather than at every
  // caller. Used by `prx triage status` for the scoped GH↔bd join.
  "sql",
  // GH-1513: bd admin maintenance group. Per-arg gated in tools/policy.ts to
  // admit `compact` only — `bd admin cleanup` (deletes closed records) and
  // `bd admin reset` (full DB wipe) stay out of policy reach.
  "admin",
] as const;

// bd's hard-blocked subcommands (close/delete/archive/import/export) are owned
// by the policy engine's `BLOCKED.bd` set and enforced via `isBlocked("bd", …)`
// below — there is no separate bd-local list. A `blockedSubcommands("bd")`
// parity test (src/__tests__/runners.test.ts) pins the set so a future divergence
// trips a test rather than silently relying on a dead second runtime check.

// GH-1473: bd short-id structural guard ---------------------------------------
//
// A bare `<prefix>-<n>` positional (e.g. `ai-home-1463`) is a bd *short* id.
// bd's prefix-ID resolver substring-matches it against the timestamp segment of
// an unrelated long id (`ai-home-1463` ⊂ `ai-home-1777491131463-…`) and
// silently writes against the wrong record. prx resolves every ref to its
// canonical long id via the (domain, external_id) map *before* calling bd (see
// src/triage/promote-children.ts, invariant I-BF1); this is the structural
// backstop that refuses a short id if any future caller forgets. Upstream Go
// resolver fix is tracked at GH-1479.
//
// Canonical long-id shape (workspace-prefixed ts-seq-hex8). Mirror of
// `BD_LONG_ID_RE` in src/adapters/beads.ts; an exact long id is safe to admit.
const BD_LONG_ID_RE = /^[a-z][a-z0-9-]*-\d{13,}-\d+-[0-9a-f]{8}$/i;
// Bare bd short-id shape: lowercase workspace prefix + `-` + digits, nothing
// trailing. This is the fuzzy-matchable form prx must never hand to bd.
const BD_SHORT_ID_RE = /^[a-z][a-z0-9-]*-\d+$/;

/**
 * Scan a bd argv for a bare short-id positional, returning the offending arg
 * (or null). Scoped to id-position only: `--flag` tokens and the value token
 * after a space-form `--flag value` are skipped, so free-text flag values
 * (e.g. `--notes "...ai-home-1463..."`) are exempt. A canonical long id is
 * admitted via {@link BD_LONG_ID_RE}. Pure structural gate — no lookup.
 */
function findShortIdPositional(args: string[]): string | null {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === undefined) continue;
    if (arg.startsWith("-")) {
      // `--flag value` (space form): the next token is the flag's value, not an
      // id position. `--flag=value` carries its value inline — nothing to skip.
      if (arg.startsWith("--") && !arg.includes("=")) {
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith("-")) i += 1;
      }
      continue;
    }
    if (BD_LONG_ID_RE.test(arg)) continue;
    if (BD_SHORT_ID_RE.test(arg)) return arg;
  }
  return null;
}

// `bd` invocation seam (GH-1554 / GH-1609) -----------------------------------
//
// The generic spawn-capture helper lives in `@bounded-systems/proc` (the spawn capability). It
// streams the child's stdout to a per-call temp file so `bd list --all --json`
// (and any other large payload) can't hit the default 1 MiB cap and have its
// partial bytes silently surface as the result. `BdSpawnFn` / `BdSpawnResult`
// stay aliased here so callers / tests that already import them keep working.

/**
 * Type alias for the spawn-capture result. Exported for backwards compatibility
 * with callers that import this type.
 */
export type BdSpawnResult = SpawnCaptureResult;

/**
 * Type alias for the spawn-capture function. Exported for backwards compatibility
 * with callers that import this type.
 */
export type BdSpawnFn = SpawnCaptureFn;

/**
 * Default spawn implementation using spawnCapture from @bounded-systems/proc.
 * Injected into execBd for testing; production never passes this explicitly.
 */
export const defaultBdSpawn: BdSpawnFn = spawnCapture;

// beadsd door seam (prx-asr / prx-634) ---------------------------------------
//
// Inside the box profile there is no local `bd` binary (prx-82b): bd-backed
// work must reach the canonical store through the beadsd DOOR — the same path
// `prx beads <verb>` already uses. The box profile signals this by exporting
// `PRX_BEADS_DOOR=<door-name>`. In door mode {@link execBd} MUST NOT spawn
// `bd`; instead it asks the registered dialer to express the op over the door,
// and fails CLOSED (naming the door + provisioning path) when it can't —
// never bubbling bd's opaque "no beads database found".
//
// `@bounded-systems/bd` stays daemon-agnostic: it knows only this function
// type and never imports the beadsd client. prx owns the door knowledge and
// registers the production dialer at CLI startup ({@link registerBdDoorDialer}).
// A dialer returns a {@link BdExecResult} when it served the request over the
// door, or `null` when the op is not expressible there (caller fails closed).
/**
 * Function type for routing bd operations through the beadsd door in box mode.
 * Returns a result when the door handled the request, or null to fall back to
 * the host profile spawn path.
 */
export type BdDoorDialer = (opts: BdExecOptions, env: BdExecEnv) => BdExecResult | null;

let registeredDoorDialer: BdDoorDialer | undefined;

/**
 * Register (or, with `undefined`, clear) the process-wide beadsd door dialer.
 * prx calls this once at CLI startup; tests inject directly via execBd's 4th
 * positional and need not touch the registry.
 */
export function registerBdDoorDialer(dialer: BdDoorDialer | undefined): void {
  registeredDoorDialer = dialer;
}

/**
 * True iff the box profile has declared a beadsd door — i.e. there is no local
 * `bd` binary and bd-backed work must route through the door.
 */
export function isBdDoorMode(env: BdExecEnv): boolean {
  const door = env.PRX_BEADS_DOOR;
  return typeof door === "string" && door.trim().length > 0;
}

/** The fail-closed stderr for a bd op the door can't express (no local bd). */
function doorNotWiredStderr(subcommand: string, env: BdExecEnv): string {
  const door = (env.PRX_BEADS_DOOR ?? "").trim();
  return (
    `bd-safe: beadsd door '${door}' is not wired for 'bd ${subcommand}' — ` +
    `bd-backed work in the box profile must route through the beadsd door, ` +
    `and this op is not available over it. Provision the box pod doors ` +
    `(prx-asr / prx-634); there is no local bd to fall back to.`
  );
}

/**
 * Door-mode resolution for a bd op that has already cleared every gate: dial
 * the door, or fail closed. Shared by both bd-spawn seams ({@link execBd} and
 * {@link defaultBdGithubRunner}) so the box profile behaves identically across
 * them — neither ever reaches a local `bd` binary.
 */
function resolveBdViaDoor(
  opts: BdExecOptions,
  env: BdExecEnv,
  dialer: BdDoorDialer | undefined,
  decision: PolicyDecision | null,
): BdExecResult {
  const viaDoor = dialer?.(opts, env) ?? null;
  if (viaDoor) return viaDoor;
  return {
    exitCode: 1,
    stdout: "",
    stderr: doorNotWiredStderr(opts.subcommand, env),
    policy: decision,
  };
}

/**
 * Door-gate a raw `bd` command array — the reusable primitive every bd-spawn
 * seam shares. Returns a {@link BdExecResult} when door mode handled the call
 * (dialed the door, or failed closed because the op isn't expressible there),
 * or `null` when the caller should run its own spawn — i.e. the command is not
 * `bd`, or we're off-profile (no `PRX_BEADS_DOOR`). This is how the scattered
 * direct `bd` spawn sites (and {@link defaultBdGithubRunner}) keep "no local bd
 * in the box profile" without each re-implementing the gate.
 */
export function bdDoorGate(
  cmd: string[],
  env: BdExecEnv = processEnv(),
  dialer: BdDoorDialer | undefined = registeredDoorDialer,
): BdExecResult | null {
  if (cmd[0] !== "bd" || !isBdDoorMode(env)) return null;
  return resolveBdViaDoor({ subcommand: cmd[1] ?? "", args: cmd.slice(2) }, env, dialer, null);
}

/**
 * Execute a bd subcommand with optional policy enforcement.
 *
 * `spawn` is injectable (last positional, mirrors `BdGithubRunner`) so tests
 * can drive the spawn-capture boundary without a real `bd` binary; production
 * callers never pass it.
 */
export function execBd(
  opts: BdExecOptions,
  env: BdExecEnv = processEnv(),
  spawn: BdSpawnFn = defaultBdSpawn,
  doorDialer: BdDoorDialer | undefined = registeredDoorDialer,
): BdExecResult {
  // Hard-block check
  if (isBlocked("bd", opts.subcommand)) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `bd-safe: blocked subcommand '${opts.subcommand}'`,
      policy: null,
    };
  }

  // Allowlist check
  if (!(ALLOWED_SUBCOMMANDS as readonly string[]).includes(opts.subcommand)) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `bd-safe: unknown or disallowed subcommand '${opts.subcommand}'`,
      policy: null,
    };
  }

  // GH-1513: per-arg gate for `bd admin`. Only `compact` is admitted —
  // `admin cleanup` (deletes closed records) and `admin reset` (full DB wipe)
  // are blocked at this layer regardless of policy state/role. Defense in
  // depth: the policy table also gates `admin` to planner-only, and the
  // `runBdAdminCompact` wrapper is the only in-tree caller that constructs
  // the admin shape.
  if (opts.subcommand === "admin") {
    const first = opts.args[0];
    if (first !== "compact") {
      return {
        exitCode: 1,
        stdout: "",
        stderr: `bd-safe: 'bd admin' admits only 'compact', got '${first ?? "<missing>"}'`,
        policy: null,
      };
    }
  }

  // GH-1473: refuse a bare bd short id in an id position (defense in depth for
  // I-BF1). Callers must resolve refs to the canonical long id before reaching
  // this chokepoint — a short id fuzzy-matches an unrelated long id and
  // silently miswires the write.
  const shortId = findShortIdPositional(opts.args);
  if (shortId) {
    return {
      exitCode: 1,
      stdout: "",
      stderr:
        `bd-safe: refusing bd short id '${shortId}' in id position — ` +
        `resolve it to the canonical long id via the (domain, external_id) ` +
        `map before calling bd (GH-1473; I-BF1). Upstream resolver fix: GH-1479.`,
      policy: null,
    };
  }

  // Policy enforcement
  const state = opts.state ?? (env.PRX_CAPABILITY_STATE as PolicyState | undefined) ?? "validating";
  const role = opts.role ?? (env.PRX_AGENT_ROLE as PolicyRole | undefined) ?? "executor";
  const decision = checkPolicy("bd", opts.subcommand, state, role);

  if (!decision.allowed) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: `bd-safe: blocked subcommand '${opts.subcommand}' for state '${state}' role '${role}'`,
      policy: decision,
    };
  }

  // Build env — clear BEADS_DIR to isolate from ~/.config/worktrunk (matches commandEnv behavior)
  const childEnv = { ...env } as Record<string, string>;
  delete childEnv.BEADS_DIR;

  // GH-1573: `bd sql` accepts arbitrary SQL. The wrapper is the single
  // chokepoint for bd policy, so it owns the `--readonly` inject — callers
  // never have to remember. `--readonly` is a bd global flag ("block write
  // operations"), accepted either before or after the subcommand by cobra;
  // placing it before caller args keeps the injected flag adjacent to the
  // subcommand for readability and avoids interleaving with a positional
  // SQL string.
  const spawnArgs =
    opts.subcommand === "sql" && !opts.args.includes("--readonly")
      ? ["--readonly", ...opts.args]
      : opts.args;

  // Door mode (box profile): never spawn a local `bd`. The op has already
  // cleared the block/allowlist/short-id/policy gates above, so behavior is
  // identical to the host profile up to this point. Now either the dialer
  // serves it over the beadsd door, or we fail closed — naming the door and
  // the provisioning path rather than letting bd's "no beads database found"
  // surface (prx-asr / prx-634; AC: no local bd in the box profile).
  if (isBdDoorMode(env)) {
    return resolveBdViaDoor(opts, env, doorDialer, decision);
  }

  // Execute (host profile: spawn the local bd binary).
  const result = spawn(["bd", opts.subcommand, ...spawnArgs], { cwd: opts.cwd, env: childEnv });

  // GH-1554: a spawn error, killing signal, or non-zero exit means the stdout
  // we hold is partial or absent — never return it as the payload.
  if (isCaptureFailure(result)) {
    return {
      exitCode: result.status ?? 1,
      stdout: "",
      stderr: `bd-safe: ${captureFailureDetail(result) || "bd failed"}`,
      policy: decision,
    };
  }

  return {
    exitCode: 0,
    stdout: result.stdout,
    stderr: result.stderr,
    policy: decision,
  };
}

/**
 * Format a BdExecResult for output as either plain text or JSON.
 * In plain text mode, returns stdout or stderr (on failure); in JSON mode, returns the full result.
 */
export function formatBdExecResult(result: BdExecResult, format: "plain" | "json"): string {
  if (format === "json") {
    return JSON.stringify(result, null, 2);
  }
  let output = result.stdout;
  if (result.stderr && result.exitCode !== 0) {
    output = result.stderr;
  }
  return output.trimEnd();
}

// `bd github sync` integration ----------------------------------------------
//
// GitHub is authoritative for *open/closed status* in ai-home (see memory
// `feedback_beads_github_authority`), but priority is bd-authoritative and
// projected bd→external only (authority ADR §2, invariant I-DS-PRIO). The
// destructive `bd github sync --pull-only --prefer-github` shell-out below
// is **no longer on any reconcile-after-write path**: GH-2011 moved
// `prx triage apply` / `type-pass` / `prx repo protect-main` onto the
// status-only canonical reconcile `runBeadsSync` (src/sync/run.ts), and
// GH-2316 moved the remaining triage write verbs (prioritize,
// prioritize-bulk, drift-fix, migrate-axis-value, prune-merged) the same
// way — closing the channel through which a GH `priority::*` label could
// round-trip back into bd-canonical priority.
//
// The helper is retained as a thin, unit-tested low-level shim (see
// test/tools/bd.test.ts). The only surviving `bd github sync --pull-only`
// invocation is the one-shot seed in `runBeadsInit --import-gh`
// (src/pr-state/cli.ts), which spawns it inline (not via this helper) and
// is intentionally exempt: bd has no data to lose at seed time.

/**
 * Result from running a command via BdGithubRunner (bd or auxiliary commands like gh auth token).
 */
export type BdGithubRunResult = { stdout: string; stderr: string; status: number };

/**
 * Function type for running bd and auxiliary commands (e.g., gh auth token).
 * Injects door mode gates to avoid spawning local bd in box profiles.
 */
export type BdGithubRunner = (
  cmd: string[],
  options?: { cwd?: string; env?: NodeJS.ProcessEnv; check?: boolean },
) => BdGithubRunResult;

/**
 * Default implementation of BdGithubRunner using spawnCapture.
 * Respects door mode (prx-asr / prx-634) when PRX_BEADS_DOOR is set.
 */
export const defaultBdGithubRunner: BdGithubRunner = (
  cmd: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; check?: boolean } = {},
): BdGithubRunResult => {
  // Door mode (box profile): this runner is one bd-spawn seam (the `runBd*`
  // helpers — show/update/sync/doctor/merge/compact). The shared gate dials the
  // door or fails closed for `bd` invocations, never spawning a local `bd`;
  // non-`bd` commands (e.g. the `gh auth token` probe) pass through untouched
  // (prx-asr / prx-634; AC: no local bd in the box profile).
  const gated = bdDoorGate(cmd, (options.env ?? processEnv()) as BdExecEnv);
  if (gated) {
    return { stdout: gated.stdout, stderr: gated.stderr, status: gated.exitCode };
  }

  // GH-1609: route through spawnCapture so `bd github sync` and the `gh auth
  // token` probe both stream stdout through a temp file (no in-memory 1 MiB
  // cap). Apply the partial-read guard so a SIGTERM'd / errored child can
  // never return its half-baked stdout as the payload.
  const result = spawnCapture(cmd, {
    cwd: options.cwd,
    env: options.env ?? processEnv(),
  });
  if (isCaptureFailure(result)) {
    return {
      stdout: "",
      stderr: captureFailureDetail(result) || (result.stderr ?? ""),
      status: result.status ?? 1,
    };
  }
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status ?? 0,
  };
};

/**
 * Resolve a GITHUB_TOKEN for `bd github sync` calls.
 * Returns undefined if GITHUB_TOKEN is already set in the environment.
 * Falls back to `gh auth token` when missing, returning a merged env dict.
 * Used by {@link runBdGithubSyncPullOnly} to support headless execution.
 */
export function resolveBeadsGitHubSyncEnv(
  cwd: string,
  runner: BdGithubRunner = defaultBdGithubRunner,
): NodeJS.ProcessEnv | undefined {
  const existing = getEnv("GITHUB_TOKEN");
  if (typeof existing === "string" && existing.trim().length > 0) {
    return undefined;
  }

  const tokenResult = runner(["gh", "auth", "token"], { cwd, check: false });
  if (tokenResult.status !== 0) {
    return undefined;
  }

  const token = tokenResult.stdout.trim();
  if (token.length === 0) {
    return undefined;
  }

  return { ...processEnv(), GITHUB_TOKEN: token };
}

/**
 * Result from running `bd github sync --pull-only` via {@link runBdGithubSyncPullOnly}.
 */
export type BdGithubSyncResult = {
  /** Exit code from the bd process. */
  exitCode: number;
  /** Standard output from bd. */
  stdout: string;
  /** Standard error from bd. */
  stderr: string;
};

/**
 * Run `bd github sync --pull-only --prefer-github` from `cwd`.
 * Resolves GITHUB_TOKEN via `resolveBeadsGitHubSyncEnv` for headless execution.
 * Set `options.dryRun = true` to append `--dry-run` (used by `prx repo protect-main`).
 */
export function runBdGithubSyncPullOnly(
  cwd: string,
  options: { dryRun?: boolean } = {},
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdGithubSyncResult {
  const env = resolveBeadsGitHubSyncEnv(cwd, runner);
  const args = ["bd", "github", "sync", "--pull-only", "--prefer-github"];
  if (options.dryRun) {
    args.push("--dry-run");
  }
  const result = runner(args, { cwd, ...(env ? { env } : {}), check: false });
  return {
    exitCode: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

// `bd admin compact` integration (GH-1513) -----------------------------------
//
// Memory-decay policy chokepoint (GH-1500 ADR §7 split 4 of GH-298). The verb
// `prx memory compact` selects eligible closed bd records (opt-out classifier
// in src/memory/compact.ts), then asks bd to compact them via this wrapper.
//
// bd v1's `bd admin compact` CLI accepts one id per invocation. The wrapper
// loops the caller-supplied id list and aggregates per-id results so callers
// can treat the compaction as a single conceptual call (mirrors the
// `runBdGithubSyncPullOnly` shape).
//
// `--auto` is the only no-pre-summary id-based mode the bd CLI offers; it
// requires `ANTHROPIC_API_KEY` (or `ai.api_key` in bd config) at runtime.
// `--dry-run` short-circuits before the LLM call so the safety default
// (`prx memory compact` defaults to dry-run) does not require a key.

/**
 * Result from compacting a single record via {@link runBdAdminCompact}.
 */
export type BdAdminCompactPerIdResult = {
  /** The record ID that was compacted. */
  id: string;
  /** Exit code from bd admin compact. */
  exitCode: number;
  /** Standard output from bd. */
  stdout: string;
  /** Standard error from bd. */
  stderr: string;
};

/**
 * Aggregated result from {@link runBdAdminCompact} across multiple records.
 */
export type BdAdminCompactResult = {
  /** Worst per-id exit code (0 when every id succeeded). */
  exitCode: number;
  /** Per-id results in input order. */
  results: BdAdminCompactPerIdResult[];
};;

// `bd show --json` (GH-1766) ------------------------------------------------
//
// Used by the canonical=bd plan/implement session entry path to hydrate the
// covering bd record without falling through to `gh issue view`. The shape
// here is the subset of `BeadsRecord` (src/triage/triage.ts) that the
// session-entry hydrate banner and `BeadsResolver.fetch` actually read; a
// follow-up cleanup will promote `BeadsRecord` to use this schema directly.

/**
 * Result from `bd show <id> --json` — either the parsed record or an error.
 */
export type BdShowResult =
  | { ok: true; record: BdShowOutput; stdout: string; stderr: string }
  | { ok: false; exitCode: number; stdout: string; stderr: string };

/**
 * Fetch a single bd record by ID and parse the JSON output.
 * Returns either the parsed record or an error result with diagnostics.
 */
export function runBdShow(
  id: string,
  cwd: string,
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdShowResult {
  const result = runner(["bd", "show", id, "--json"], { cwd, check: false });
  if (result.status !== 0) {
    return {
      ok: false,
      exitCode: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(result.stdout);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      exitCode: 1,
      stdout: result.stdout,
      stderr: `bd show: failed to parse JSON: ${detail}`,
    };
  }
  // `bd show <id> --json` returns a length-1 array (single-id query); accept
  // the legacy object shape too for back-compat with older bd builds.
  const record = Array.isArray(raw) ? raw[0] : raw;
  if (record === undefined) {
    return {
      ok: false,
      exitCode: 1,
      stdout: result.stdout,
      stderr: `bd show: no record returned for ${id}`,
    };
  }
  const parsed = bdShowOutputSchema.safeParse(record);
  if (!parsed.success) {
    return {
      ok: false,
      exitCode: 1,
      stdout: result.stdout,
      stderr: `bd show: schema mismatch: ${parsed.error.message}`,
    };
  }
  return { ok: true, record: parsed.data as BdShowOutput, stdout: result.stdout, stderr: result.stderr };
}

// `bd update --claim` (GH-1766) ---------------------------------------------
//
// On canonical=bd plan-session entry the operator owns the record before the
// worktree materializes — mirroring the way canonical=gh sessions implicitly
// claim via the GH issue. `bd update --claim` is admitted by the policy table
// (planner role, all states; see src/tools/policy.ts) and is not in the
// BLOCKED list.

/**
 * Result from running `bd update <id> --claim`.
 */
export type BdUpdateClaimResult = {
  /** Exit code from bd update. */
  exitCode: number;
  /** Standard output from bd. */
  stdout: string;
  /** Standard error from bd. */
  stderr: string;
};

/**
 * Claim ownership of a bd record (planner role required).
 */
export function runBdUpdateClaim(
  id: string,
  cwd: string,
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdUpdateClaimResult {
  const result = runner(["bd", "update", id, "--claim"], { cwd, check: false });
  return {
    exitCode: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

/**
 * Compact closed records for memory decay (GH-1513).
 * Loops over ids and aggregates results. Requires ANTHROPIC_API_KEY unless dryRun is true.
 */
export function runBdAdminCompact(
  cwd: string,
  options: { dryRun: boolean; ids: string[] },
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdAdminCompactResult {
  const results: BdAdminCompactPerIdResult[] = [];
  let worstExit = 0;
  for (const id of options.ids) {
    const args = ["bd", "admin", "compact", "--auto", "--id", id];
    if (options.dryRun) {
      args.push("--dry-run");
    }
    const result = runner(args, { cwd, check: false });
    if (result.status !== 0 && worstExit === 0) {
      worstExit = result.status;
    }
    results.push({
      id,
      exitCode: result.status,
      stdout: result.stdout,
      stderr: result.stderr,
    });
  }
  return { exitCode: worstExit, results };
}

// `bd duplicates` / `bd doctor` / `bd merge` (GH-1255) ----------------------
//
// Wrappers used by `prx triage drift-fix` to surface bd's own content-hash
// dedupe heuristic and substrate-health report inline with the type/priority/
// status axis reconcile. None route through `execBd`: the wrapper builds argv
// + spawns via `defaultBdGithubRunner` so per-arg policy is owned at the call
// site (mirrors `runBdGithubSyncPullOnly`). Read-only and `--fix` paths are
// split into dedicated functions so the mutating call site differs from the
// read-only one in grep + audit logs.

const bdDuplicatesPayloadSchema = z
  .object({
    clusters: z.array(bdDuplicatesClusterSchema).default([]),
  })
  .passthrough();

/**
 * Result from `bd duplicates --dry-run --json` — deduplication clusters and diagnostics.
 */
export type BdDuplicatesDryRunResult = {
  /** Exit code from bd duplicates. */
  exitCode: number;
  /** Detected duplicate clusters. */
  clusters: BdDuplicatesCluster[];
  /** Standard output from bd. */
  stdout: string;
  /** Standard error from bd. */
  stderr: string;
};

/**
 * Detect duplicate records via bd's content-hash heuristic (dry-run, read-only).
 */
export function runBdDuplicatesDryRun(
  cwd: string,
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdDuplicatesDryRunResult {
  const result = runner(["bd", "duplicates", "--dry-run", "--json"], {
    cwd,
    check: false,
  });
  if (result.status !== 0) {
    return {
      exitCode: result.status,
      clusters: [],
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(result.stdout);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      exitCode: 1,
      clusters: [],
      stdout: result.stdout,
      stderr: `bd duplicates: failed to parse JSON: ${detail}`,
    };
  }
  // bd may emit `{ clusters: [...] }` or a bare array — accept both.
  const normalized = Array.isArray(raw) ? { clusters: raw } : raw;
  const parsed = bdDuplicatesPayloadSchema.safeParse(normalized);
  if (!parsed.success) {
    return {
      exitCode: 1,
      clusters: [],
      stdout: result.stdout,
      stderr: `bd duplicates: schema mismatch: ${parsed.error.message}`,
    };
  }
  return {
    exitCode: 0,
    clusters: parsed.data.clusters as BdDuplicatesCluster[],
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

/**
 * Default empty doctor report (all zeros, no issues).
 */
export const emptyBdDoctorReport: BdDoctorReport = bdDoctorReportSchema.parse({});

/**
 * Result from `bd doctor --json` or `bd doctor --fix --json` — health report and diagnostics.
 */
export type BdDoctorResult = {
  /** Exit code from bd doctor. */
  exitCode: number;
  /** Health report with issue counts and fixability. */
  report: BdDoctorReport;
  /** Standard output from bd. */
  stdout: string;
  /** Standard error from bd. */
  stderr: string;
};

/**
 * Parse bd doctor output from a BdGithubRunResult into a typed BdDoctorResult.
 * Handles JSON parsing and schema validation.
 */
function parseBdDoctorReport(result: BdGithubRunResult, verb: string): BdDoctorResult {
  if (result.status !== 0) {
    return {
      exitCode: result.status,
      report: emptyBdDoctorReport,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(result.stdout);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      exitCode: 1,
      report: emptyBdDoctorReport,
      stdout: result.stdout,
      stderr: `${verb}: failed to parse JSON: ${detail}`,
    };
  }
  const parsed = bdDoctorReportSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      exitCode: 1,
      report: emptyBdDoctorReport,
      stdout: result.stdout,
      stderr: `${verb}: schema mismatch: ${parsed.error.message}`,
    };
  }
  return {
    exitCode: 0,
    report: parsed.data,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

/**
 * Run `bd doctor --json` to report health issues (read-only).
 */
export function runBdDoctorJson(
  cwd: string,
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdDoctorResult {
  const result = runner(["bd", "doctor", "--json"], { cwd, check: false });
  return parseBdDoctorReport(result, "bd doctor");
}

/**
 * Run `bd doctor --fix --json` to detect and fix health issues.
 */
export function runBdDoctorFix(
  cwd: string,
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdDoctorResult {
  const result = runner(["bd", "doctor", "--fix", "--json"], { cwd, check: false });
  return parseBdDoctorReport(result, "bd doctor --fix");
}

/**
 * Options for running `bd merge`.
 */
export type BdMergeOptions = {
  /** Target record ID to merge other records into. */
  target: string;
  /** Source record IDs to merge from. */
  sources: string[];
  /** If true, append --dry-run to preview the merge. */
  dryRun?: boolean;
};

/**
 * Result from `bd merge` — merge operation outcome and diagnostics.
 */
export type BdMergeResult = {
  /** Exit code from bd merge. */
  exitCode: number;
  /** Merge result with target, sources, and applied flag. */
  result: BdMergeResultPayload;
  /** Standard output from bd. */
  stdout: string;
  /** Standard error from bd. */
  stderr: string;
};

/**
 * Merge source records into a target record.
 * Empty sources list is rejected with exitCode 1.
 */
export function runBdMerge(
  cwd: string,
  options: BdMergeOptions,
  runner: BdGithubRunner = defaultBdGithubRunner,
): BdMergeResult {
  if (options.sources.length === 0) {
    return {
      exitCode: 1,
      result: { target: options.target, sources: [], applied: false },
      stdout: "",
      stderr: "bd merge: refusing to run with empty sources list",
    };
  }
  const argv = ["bd", "merge", ...options.sources, "--into", options.target];
  if (options.dryRun) argv.push("--dry-run");
  argv.push("--json");
  const result = runner(argv, { cwd, check: false });

  const fallback: BdMergeResultPayload = {
    target: options.target,
    sources: options.sources,
    applied: false,
  };

  if (result.status !== 0) {
    return {
      exitCode: result.status,
      result: fallback,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }
  // bd merge may or may not emit JSON on success — fall back to the caller's
  // intent if parsing fails. Either way exitCode 0 means the merge applied
  // (dry-run reports `applied: false` from bd's own output).
  let parsed: BdMergeResultPayload = {
    target: options.target,
    sources: options.sources,
    applied: !options.dryRun,
  };
  const trimmed = result.stdout.trim();
  if (trimmed.length > 0) {
    try {
      const raw = JSON.parse(trimmed);
      const safe = bdMergeResultSchema.safeParse(raw);
      if (safe.success) {
        parsed = safe.data;
      }
    } catch {
      // bd merge can succeed without emitting parsable JSON; keep fallback.
    }
  }
  return {
    exitCode: 0,
    result: parsed,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}
