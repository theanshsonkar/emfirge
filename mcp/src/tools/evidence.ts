import { z } from "zod";
import { backendCall, BackendHttpError } from "../client.js";
import { redactDeep } from "../tokenize.js";
import { roleArnSchema } from "./scan.js";

const SOURCES = ["cloudtrail_events", "cloudwatch_metrics"] as const;
const NEXT_STEP = "Show this estimate to the user. Call again with accept_estimate_id only after the user agrees.";

export const inUseEvidenceSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
  sources: z.array(z.enum(SOURCES)).min(1).refine((values) => new Set(values).size === values.length, "sources must be unique").default([...SOURCES]).describe("Evidence sources to estimate or read"),
  accept_estimate_id: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Estimate ID explicitly agreed to by the user"),
  role_arn: roleArnSchema.optional().describe("Same AWS IAM role ARN used by emfirge_scan; required only when accepting an estimate"),
};

export const inUseEvidenceZodObject = z.object(inUseEvidenceSchema).strict();
export type InUseEvidenceArgs = z.infer<typeof inUseEvidenceZodObject>;

function ok(result: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) }] };
}

export async function inUseEvidenceHandler(args: InUseEvidenceArgs) {
  const sources = (args.sources ?? [...SOURCES]) as readonly string[];
  const path = `/branches/${encodeURIComponent(args.branch_id)}/in-use-evidence`;
  if (args.accept_estimate_id === undefined) {
    const estimate = await backendCall("GET", `${path}/estimate?sources=${encodeURIComponent(sources.join(","))}`);
    return ok({ ...(estimate as Record<string, unknown>), next_step: NEXT_STEP });
  }

  if (!args.role_arn) {
    throw new Error("role_arn is required with accept_estimate_id (use the same role ARN as emfirge_scan)");
  }

  try {
    const result = await backendCall("POST", path, {
      role_arn: args.role_arn,
      sources,
      accept_estimate_id: args.accept_estimate_id,
    });
    return ok(result);
  } catch (error) {
    if (error instanceof BackendHttpError && error.status === 409) {
      const body = error.body as { detail?: unknown; estimate?: unknown };
      return ok({ detail: body.detail, estimate: body.estimate, next_step: NEXT_STEP });
    }
    throw error;
  }
}
