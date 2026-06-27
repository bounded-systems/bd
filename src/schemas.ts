/**
 * Internal zod schemas for bd package. These are compiled to fast-type
 * definitions via @bounded-systems/schema-gen → types.generated.ts, with JSDoc
 * extracted from .describe() fields.
 *
 * DO NOT export these schemas from the public API. They are internal
 * implementation details. Use the generated types instead (src/types.generated.ts).
 */

import { z } from "zod";

export const bdShowOutputSchema = z
  .object({
    id: z.string().describe("Beads record ID"),
    title: z.string().default("").describe("Record title"),
    description: z.string().optional().nullable().describe("Record description"),
    status: z.string().default("").describe("Record status"),
    priority: z.number().int().optional().nullable().describe("Record priority level"),
    issueType: z.string().optional().nullable().describe("Issue type classification"),
    labels: z.array(z.string()).optional().nullable().describe("Associated labels"),
    blockedBy: z.array(z.string()).optional().nullable().describe("IDs of blocking records"),
    externalRef: z.string().optional().nullable().describe("Primary external reference"),
    externalRefs: z.record(z.string(), z.string()).optional().nullable().describe("Map of external system references"),
    metadata: z.record(z.string(), z.unknown()).optional().nullable().describe("Arbitrary metadata map"),
    sourceSystem: z.string().optional().nullable().describe("Source system identifier"),
    updatedAt: z.string().optional().nullable().describe("Last update timestamp"),
  })
  .describe("Output from `bd show <id> --json`");

export const bdDuplicatesClusterMemberSchema = z
  .object({
    beadsId: z.string().describe("Beads record ID"),
    title: z.string().default("").describe("Record title"),
    status: z.string().default("").describe("Record status"),
    priority: z.number().int().nullable().default(null).describe("Priority level or null"),
  })
  .describe("Member of a deduplication cluster");

export const bdDuplicatesClusterSchema = z
  .object({
    target: bdDuplicatesClusterMemberSchema.describe("Target record to merge into"),
    sources: z.array(bdDuplicatesClusterMemberSchema).nonempty().describe("Records to merge from (minimum 1)"),
  })
  .describe("Cluster of duplicate records");

export const bdDoctorIssueSchema = z
  .object({
    category: z.string().describe("Issue category name"),
    count: z.number().int().nonnegative().default(0).describe("Number of issues"),
    fixable: z.boolean().default(false).describe("Whether the issue is automatically fixable"),
  })
  .describe("Health check issue from `bd doctor`");

export const bdDoctorReportSchema = z
  .object({
    total: z.number().int().nonnegative().default(0).describe("Total issues found"),
    fixable: z.number().int().nonnegative().default(0).describe("Number of fixable issues"),
    issues: z.array(bdDoctorIssueSchema).default([]).describe("List of detected issues"),
  })
  .describe("Health report from `bd doctor --json`");

export const bdMergeResultSchema = z
  .object({
    target: z.string().describe("Target record ID"),
    sources: z.array(z.string()).default([]).describe("Source record IDs merged"),
    applied: z.boolean().default(false).describe("Whether the merge was applied"),
  })
  .describe("Result from `bd merge`");
