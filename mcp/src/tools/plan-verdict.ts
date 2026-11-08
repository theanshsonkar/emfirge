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

// Emfirge keeps only a sha256 of the plan, never its text, so the caller applies its own copy.
export const PLAN_BINDING_NOTE =
  "Emfirge does not store plan text. Apply your own original plan, not anything returned here; " +
  "input_sha256 is the sha256 of the exact JSON this tool sent (JSON.stringify of `plan`; for an aws-cli " +
  "list, {\"format\":\"aws-cli/1\",\"commands\":[...]}). A plan whose sha256 differs is not the one this " +
  "verdict covers; re-run emfirge_plan_verdict on it.";

/** A short, single-line reason: status and message, never an HTML error page. */
function shortError(err: unknown): string {
  const status = (err as { status?: number })?.status;
  let message = err instanceof Error ? err.message : String(err);
  message = message.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  if (message.length > 160) message = message.slice(0, 160) + "…";
  return status ? `HTTP ${status}: ${message}` : message;
}

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
  // The change is on the branch once the ingest answers. A verdict or hand-back failure after that
  // must not read as "try failed": an agent would try the same change again and add it twice.
  let branchVerdict: BranchVerdict | null = null;
  let handback: PlanHandback | null = null;
  let verdictError: string | null = null;
  try {
    branchVerdict = await backendCall<BranchVerdict>("GET", `/branches/${branchId}/verdict`);
    handback = await backendCall<PlanHandback>(
      "GET",
      `/branches/${branchId}/plans/${encodeURIComponent(ingest.plan_id)}/handback`,
    );
  } catch (err) {
    verdictError = shortError(err);
  }
  if (!branchVerdict || !handback) {
    return ok({
      saved: true,
      plan_id: ingest.plan_id,
      input_sha256: ingest.input_sha256,
      applied: ingest.applied,
      rejected: ingest.rejected,
      unmodeled: ingest.unmodeled,
      unknown_fields: ingest.unknown_fields,
      branch_revision: ingest.branch_revision ?? null,
      verdict: null,
      verdict_error: verdictError ?? "verdict not available",
      next_step: `The change is saved on the branch. Do not try it again. Run \`emfirge check ${expanded.branch_id}\` ` +
        "for the answers once the server responds; `emfirge report` gives the hand-back.",
    });
  }

  return ok({
    saved: true,
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
    next_step: PLAN_BINDING_NOTE,
  });
}
