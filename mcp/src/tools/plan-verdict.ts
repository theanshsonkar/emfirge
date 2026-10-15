import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

export const planVerdictSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
  format: z.enum(["terraform", "aws-api", "aws-cli", "cloudformation"]),
  plan: z.union([
    z.record(z.string(), z.unknown()),
    z.array(z.string()),
  ]).describe("Terraform plan, AWS API calls, AWS CLI commands, or CloudFormation change set document"),
};

export const planVerdictZodObject = z.object(planVerdictSchema);
export type PlanVerdictArgs = z.infer<typeof planVerdictZodObject>;

type PlanIngest = {
  plan_id: string;
  input_sha256: string;
  applied: unknown[];
  rejected: unknown[];
  unmodeled: unknown[];
  unknown_fields: unknown[];
  branch_revision?: string;
};

type BranchVerdict = {
  verdict: string;
  reasons: unknown[];
};

type PlanHandback = {
  plan_id: string;
  input_sha256: string;
  verdict_id: string;
  branch_revision: string;
  [key: string]: unknown;
};

function ok(result: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) },
    ],
  };
}

export async function planVerdictHandler(args: PlanVerdictArgs) {
  const expanded = expandTokens(args) as PlanVerdictArgs;
  const branchId = encodeURIComponent(expanded.branch_id);
  const pathFormat = expanded.format;
  let body: Record<string, unknown>;
  if (pathFormat === "aws-cli" && Array.isArray(expanded.plan)) {
    body = { format: "aws-cli/1", commands: expanded.plan };
  } else {
    body = expanded.plan as Record<string, unknown>;
  }

  const ingest = await backendCall<PlanIngest>(
    "POST",
    `/branches/${branchId}/plans/${pathFormat}`,
    body,
  );
  const branchVerdict = await backendCall<BranchVerdict>(
    "GET",
    `/branches/${branchId}/verdict`,
  );
  const handback = await backendCall<PlanHandback>(
    "GET",
    `/branches/${branchId}/plans/${encodeURIComponent(ingest.plan_id)}/handback`,
  );

  return ok({
    plan_id: ingest.plan_id,
    input_sha256: ingest.input_sha256,
    applied: ingest.applied,
    rejected: ingest.rejected,
    unmodeled: ingest.unmodeled,
    unknown_fields: ingest.unknown_fields,
    verdict: {
      decision: branchVerdict.verdict,
      reasons: branchVerdict.reasons,
    },
    verdict_id: handback.verdict_id,
    branch_revision: handback.branch_revision,
    handback,
  });
}
