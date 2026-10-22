// Git branch tools: create and inspect safe, isolated infrastructure changes.

export type CostDelta = {
  value: number | null;
  status: "estimated" | "unknown" | "n/a";
  reason: string;
  unknown_count: number;
  known_provisioned_delta: number | null;
  currency: "USD";
};

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

// Every handler in this file funnels its response through `redactDeep` and any
// caller-supplied resource identifier through `expandTokens`, matching the
// contract the scan/simulate/verify-fix tools already follow. Skipping either
// one silently breaks a privacy mode or rejects the tokenized ids that
// emfirge_scan hands back, so keep both wired when adding a tool here.
function ok(result: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) },
    ],
  };
}

export const createBranchSchema = {
  base_analysis_id: z
    .string()
    .min(1)
    .describe("Analysis ID returned by emfirge_scan to use as the branch base"),
  name: z.string().min(1).describe("Human-readable name for the branch"),
};

export const createBranchZodObject = z.object(createBranchSchema);
export type CreateBranchArgs = z.infer<typeof createBranchZodObject>;

export async function createBranchHandler(args: CreateBranchArgs) {
  const result = await backendCall("POST", "/branches", args);
  return ok(result);
}

export const applyChangeSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
  op: z.enum(["add", "modify", "delete"]).describe("Change operation to apply; iam_role_policy supports modify only; route_table supports add and modify"),
  resource_type: z.string().min(1).describe("Infrastructure type; iam_role_policy modify replaces the complete statement list; route_table add needs vpc_id (optional routes, associated_subnet_ids, tags) and route_table modify replaces the complete routes list"),
  resource_id: z.string().min(1).describe("Resource ID; use the collected role ARN for iam_role_policy and collected route table ID for route_table"),
  expected_change_count: z.number().int().nonnegative().optional().describe("Optional branch change count observed by the agent; stale appends fail with HTTP 409"),
  branch_revision: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Optional branch_revision from emfirge_get_branch; stale state fails with HTTP 409"),
  fields: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Fields to add or modify; security-group rules use only from_port, to_port, protocol, ip_ranges, source_sg_ids, and dest_sg_ids; for iam_role_policy, provide only access_statements as the complete replacement statement list; for route_table modify, provide only routes as the complete normalized route list; for route_table add, provide vpc_id and optionally routes, associated_subnet_ids and tags; new internet_gateway routes require complete collected same-VPC attachment evidence in the available state"),
};

export const applyChangeZodObject = z.object(applyChangeSchema);
export type ApplyChangeArgs = z.infer<typeof applyChangeZodObject>;

export async function applyChangeHandler(args: ApplyChangeArgs) {
  // `emfirge_scan` returns tokenized ids (SG_001), so the id and any ids
  // embedded in `fields` must be expanded back to real AWS ids before the
  // backend looks the target up.
  const agentResourceId = args.resource_id;
  const { branch_id, ...change } = expandTokens(args) as ApplyChangeArgs;
  try {
    const result = await backendCall(
      "POST",
      `/branches/${encodeURIComponent(branch_id)}/changes`,
      { ...change, fields: change.fields ?? {} },
    );
    return ok(result);
  } catch (error) {
    if (error instanceof Error && /target not found/i.test(error.message)) {
      throw new Error(`${error.message} (target: ${agentResourceId})`);
    }
    throw error;
  }
}

export const branchIdSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
};

export const getBranchZodObject = z.object(branchIdSchema);
export type GetBranchArgs = z.infer<typeof getBranchZodObject>;

export async function getBranchHandler(args: GetBranchArgs) {
  const result = await backendCall(
    "GET",
    `/branches/${encodeURIComponent(args.branch_id)}`,
  );
  return ok(result);
}

export const forkBranchZodObject = z.object({
  ...branchIdSchema,
  name: z.string().min(1).describe("Name for the new branch"),
  branch_revision: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Optional observed branch_revision; stale state fails with HTTP 409"),
});
export type ForkBranchArgs = z.infer<typeof forkBranchZodObject>;

export async function forkBranchHandler(args: ForkBranchArgs) {
  const result = await backendCall(
    "POST",
    `/branches/${encodeURIComponent(args.branch_id)}/fork`,
    {
      name: args.name,
      ...(args.branch_revision === undefined ? {} : { branch_revision: args.branch_revision }),
    },
  );
  return ok(result);
}

export const branchDiffZodObject = z.object(branchIdSchema);
export type BranchDiffArgs = z.infer<typeof branchDiffZodObject>;

export async function branchDiffHandler(args: BranchDiffArgs) {
  const result = await backendCall(
    "GET",
    `/branches/${encodeURIComponent(args.branch_id)}/diff`,
  );
  return ok(result);
}

export const branchVerdictZodObject = z.object(branchIdSchema);
export type BranchVerdictArgs = z.infer<typeof branchVerdictZodObject>;

export async function branchVerdictHandler(args: BranchVerdictArgs) {
  const result = await backendCall(
    "GET",
    `/branches/${encodeURIComponent(args.branch_id)}/verdict`,
  );
  return ok(result);
}

export const rollbackBranchZodObject = z.object({
  ...branchIdSchema,
  expected_change_count: z.number().int().nonnegative().optional().describe("Optional observed change count; stale rollback fails with HTTP 409"),
  branch_revision: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Optional observed branch_revision; stale rollback fails with HTTP 409"),
});
export type RollbackBranchArgs = z.infer<typeof rollbackBranchZodObject>;

export async function rollbackBranchHandler(args: RollbackBranchArgs) {
  const result = await backendCall(
    "POST",
    `/branches/${encodeURIComponent(args.branch_id)}/rollback`,
    {
      ...(args.expected_change_count === undefined ? {} : { expected_change_count: args.expected_change_count }),
      ...(args.branch_revision === undefined ? {} : { branch_revision: args.branch_revision }),
    },
  );
  return ok(result);
}

export const rollbackBranchToCountZodObject = z.object({
  ...branchIdSchema,
  target_change_count: z.number().int().nonnegative().describe("Number of leading changes to retain; must not exceed the current branch change count"),
  branch_revision: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Optional observed branch_revision; stale state fails with HTTP 409"),
});
export type RollbackBranchToCountArgs = z.infer<typeof rollbackBranchToCountZodObject>;

export async function rollbackBranchToCountHandler(args: RollbackBranchToCountArgs) {
  const result = await backendCall(
    "POST",
    `/branches/${encodeURIComponent(args.branch_id)}/rollback-to-count`,
    {
      target_change_count: args.target_change_count,
      ...(args.branch_revision === undefined ? {} : { branch_revision: args.branch_revision }),
    },
  );
  return ok(result);
}

export const discardBranchZodObject = z.object({
  ...branchIdSchema,
  expected_change_count: z.number().int().nonnegative().optional().describe("Optional observed change count; stale discard fails with HTTP 409"),
  branch_revision: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Optional observed branch_revision; stale discard fails with HTTP 409"),
});
export type DiscardBranchArgs = z.infer<typeof discardBranchZodObject>;

export async function discardBranchHandler(args: DiscardBranchArgs) {
  const result = await backendCall(
    "POST",
    `/branches/${encodeURIComponent(args.branch_id)}/discard`,
    {
      ...(args.expected_change_count === undefined ? {} : { expected_change_count: args.expected_change_count }),
      ...(args.branch_revision === undefined ? {} : { branch_revision: args.branch_revision }),
    },
  );
  return ok(result);
}

export const listBranchesSchema = {
  base_analysis_id: z
    .string()
    .min(1)
    .optional()
    .describe("Optionally filter branches by the analysis ID they are based on"),
};

export const listBranchesZodObject = z.object(listBranchesSchema);
export type ListBranchesArgs = z.infer<typeof listBranchesZodObject>;

export async function listBranchesHandler(args: ListBranchesArgs) {
  const query = new URLSearchParams();
  if (args.base_analysis_id !== undefined) {
    query.set("base_analysis_id", args.base_analysis_id);
  }
  const queryString = query.toString();
  const result = await backendCall("GET", `/branches${queryString ? `?${queryString}` : ""}`);
  return ok(Array.isArray(result) ? { branches: result, count: result.length } : result);
}

export const compareBranchesSchema = {
  branch_ids: z
    .array(z.string().min(1))
    .min(1)
    .describe("Branch IDs to compare"),
};

export const compareBranchesZodObject = z.object(compareBranchesSchema);
export type CompareBranchesArgs = z.infer<typeof compareBranchesZodObject>;

export async function compareBranchesHandler(args: CompareBranchesArgs) {
  const result = await backendCall("POST", "/branches/compare", {
    branch_ids: args.branch_ids,
  });
  return ok(result);
}
