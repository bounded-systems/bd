import { test } from "bun:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assertSeam } from "@bounded-systems/seam-check";

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// @bounded-systems/bd: the policy-gated beads wrapper. Prod files touch zod and
// the env / proc / policy capability seams only — bd reaches subprocesses and
// ambient config through those seams, never directly. The harness proves that
// edge set and the no-ambient thesis.
test("@bounded-systems/bd upholds its seam claim", () => {
  assertSeam({
    root: SRC,
    prod: ["zod", "@bounded-systems/env", "@bounded-systems/proc", "@bounded-systems/policy"],
    test: ["@bounded-systems/bd", "@bounded-systems/seam-check", "node:fs"],
  });
});
