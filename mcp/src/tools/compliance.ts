// emfirge_check_compliance: GET /compliance/{id}.

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep } from "../tokenize.js";

export const complianceSchema = {
  analysis_id: z.string().min(1).describe("Analysis ID returned by emfirge_scan"),
  framework: z
    .enum(["cis-aws-1.5", "soc2"])
    .optional()
    .describe("Framework to filter by. Omit to get all."),
};

export const complianceZodObject = z.object(complianceSchema);
export type ComplianceArgs = z.infer<typeof complianceZodObject>;

interface ComplianceResponse {
  frameworks?: Array<{ id: string; [k: string]: unknown }>;
  [k: string]: unknown;
}

export async function complianceHandler(args: ComplianceArgs) {
  const result = await backendCall<ComplianceResponse>(
    "GET",
    `/compliance/${encodeURIComponent(args.analysis_id)}`,
  );

  const filtered = args.framework
    ? (result.frameworks?.find((f) => f.id === args.framework) ?? {
        error: `Framework '${args.framework}' not found in this scan`,
      })
    : result;

  const redacted = redactDeep(filtered);

  return {
    content: [{ type: "text" as const, text: JSON.stringify(redacted, null, 2) }],
  };
}
