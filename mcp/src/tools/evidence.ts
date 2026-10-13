import { z } from "zod";
import { backendCall, BackendHttpError } from "../client.js";
import { redactDeep } from "../tokenize.js";

const SOURCES = ["cloudtrail_events", "cloudwatch_metrics"] as const;
const NEXT_STEP = "Show this estimate to the user. Call again with accept_estimate_id only after the user agrees.";

export const inUseEvidenceSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
  sources: z.array(z.enum(SOURCES)).min(1).refine((values) => new Set(values).size === values.length, "sources must be unique").default([...SOURCES]).describe("Evidence sources to estimate or read"),
  accept_estimate_id: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Estimate ID explicitly agreed to by the user"),
};

export const inUseEvidenceZodObject = z.object(inUseEvidenceSchema).strict();
export type InUseEvidenceArgs = z.infer<typeof inUseEvidenceZodObject>;

function ok(result: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) }] };
}

function roleArn(): string {
  const value = process.env.EMFIRGE_ROLE_ARN;
  if (!value) {
    throw new Error(
      "No role ARN is configured. Call emfirge_setup_help, then configure EMFIRGE_ROLE_ARN with the RoleArn used by emfirge_scan.",
    );
  }
  return value;
}

export async function inUseEvidenceHandler(args: InUseEvidenceArgs) {
  const sources = (args.sources ?? [...SOURCES]) as readonly string[];
  const path = `/branches/${encodeURIComponent(args.branch_id)}/in-use-evidence`;
  if (args.accept_estimate_id === undefined) {
    const estimate = await backendCall("GET", `${path}/estimate?sources=${encodeURIComponent(sources.join(","))}`);
    return ok({ ...(estimate as Record<string, unknown>), next_step: NEXT_STEP });
  }

  try {
    const result = await backendCall("POST", path, {
      role_arn: roleArn(),
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
