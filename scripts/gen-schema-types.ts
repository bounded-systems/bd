#!/usr/bin/env bun
/**
 * Generate src/types.generated.ts from the internal zod schemas via the shared
 * @bounded-systems/schema-gen. Author schemas in src/schemas.ts (with
 * .describe()); this projects them to explicit, fast-types-clean public types.
 *
 *   bun run schema:gen     # write src/types.generated.ts
 *   bun run schema:check   # exit 1 if the committed file is stale (CI drift gate)
 */
import { genSchemaTypes } from "@bounded-systems/schema-gen";

import {
  bdShowOutputSchema,
  bdDuplicatesClusterMemberSchema,
  bdDuplicatesClusterSchema,
  bdDoctorIssueSchema,
  bdDoctorReportSchema,
  bdMergeResultSchema,
} from "../src/schemas.ts";

const out = new URL("../src/types.generated.ts", import.meta.url).pathname;
const check = process.argv.includes("--check");

const { drift } = await genSchemaTypes(
  [
    [bdShowOutputSchema, "BdShowOutput"],
    [bdDuplicatesClusterMemberSchema, "BdDuplicatesClusterMember"],
    [bdDuplicatesClusterSchema, "BdDuplicatesCluster"],
    [bdDoctorIssueSchema, "BdDoctorIssue"],
    [bdDoctorReportSchema, "BdDoctorReport"],
    [bdMergeResultSchema, "BdMergeResultPayload"],
  ],
  out,
  { check },
);

if (check) {
  if (drift) {
    console.error("::error::src/types.generated.ts is stale — run `bun run schema:gen` and commit.");
    process.exit(1);
  }
  console.log("types.generated.ts up to date.");
} else {
  console.log("wrote src/types.generated.ts");
}
