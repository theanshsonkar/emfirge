import { z } from "zod";
import { backendCall, BackendHttpError } from "../client.js";
import { redactDeep } from "../tokenize.js";
import { roleArnSchema } from "./scan.js";

const NEXT_STEP = "Show this estimate to the user. Call again with approve=true, accept_estimate_id and role_arn only after the user agrees.";

export const policyChecksSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
  approve: z.literal(true).optional().describe("Set to true only after the user agreed to the shown estimate"),
  accept_estimate_id: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Estimate ID the user agreed to; required with approve"),
  role_arn: roleArnSchema.optional().describe("Same AWS IAM role ARN used by emfirge_scan; required only with approve"),
};

export const policyChecksZodObject = z.object(policyChecksSchema).strict();
export type PolicyChecksArgs = z.infer<typeof policyChecksZodObject>;

function ok(result: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) }] };
}

export async function policyChecksHandler(args: PolicyChecksArgs) {
  const path = `/branches/${encodeURIComponent(args.branch_id)}/policy-checks`;
  if (args.approve !== true) {
    const estimate = await backendCall("GET", `${path}/estimate`);
    return ok({ ...(estimate as Record<string, unknown>), next_step: NEXT_STEP });
  }
  if (!args.role_arn || !args.accept_estimate_id) {
    throw new Error("role_arn and accept_estimate_id are required with approve (use the same role ARN as emfirge_scan and the estimate_id shown to the user)");
  }
  try {
    const result = await backendCall("POST", path, { role_arn: args.role_arn, approve: true, accept_estimate_id: args.accept_estimate_id });
    return ok(result);
  } catch (error) {
    if (error instanceof BackendHttpError && error.status === 409) {
      const body = error.body as { detail?: unknown; estimate?: unknown };
      return ok({ detail: body.detail, estimate: body.estimate, next_step: NEXT_STEP });
    }
    throw error;
  }
}
