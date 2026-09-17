// Git branch tools: create and inspect safe, isolated infrastructure changes.

import { z } from "zod";
import { backendCall } from "../client.js";

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
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}

export const applyChangeSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
  op: z.enum(["add", "modify", "delete"]).describe("Change operation to apply"),
  resource_type: z.string().min(1).describe("Type of infrastructure resource"),
  resource_id: z.string().min(1).describe("ID of the resource to change"),
  fields: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Fields to add or modify; omit for delete or when no fields are needed"),
};

export const applyChangeZodObject = z.object(applyChangeSchema);
export type ApplyChangeArgs = z.infer<typeof applyChangeZodObject>;

export async function applyChangeHandler(args: ApplyChangeArgs) {
  const { branch_id, ...change } = args;
  const result = await backendCall(
    "POST",
    `/branches/${encodeURIComponent(branch_id)}/changes`,
    { ...change, fields: change.fields ?? {} },
  );
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}

export const branchIdSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
};

export const branchDiffZodObject = z.object(branchIdSchema);
export type BranchDiffArgs = z.infer<typeof branchDiffZodObject>;

export async function branchDiffHandler(args: BranchDiffArgs) {
  const result = await backendCall(
    "GET",
    `/branches/${encodeURIComponent(args.branch_id)}/diff`,
  );
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}

export const branchVerdictZodObject = z.object(branchIdSchema);
export type BranchVerdictArgs = z.infer<typeof branchVerdictZodObject>;

export async function branchVerdictHandler(args: BranchVerdictArgs) {
  const result = await backendCall(
    "GET",
    `/branches/${encodeURIComponent(args.branch_id)}/verdict`,
  );
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}

export const rollbackBranchZodObject = z.object(branchIdSchema);
export type RollbackBranchArgs = z.infer<typeof rollbackBranchZodObject>;

export async function rollbackBranchHandler(args: RollbackBranchArgs) {
  const result = await backendCall(
    "POST",
    `/branches/${encodeURIComponent(args.branch_id)}/rollback`,
    {},
  );
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}

export const discardBranchZodObject = z.object(branchIdSchema);
export type DiscardBranchArgs = z.infer<typeof discardBranchZodObject>;

export async function discardBranchHandler(args: DiscardBranchArgs) {
  const result = await backendCall(
    "POST",
    `/branches/${encodeURIComponent(args.branch_id)}/discard`,
    {},
  );
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
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
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
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
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
  };
}
