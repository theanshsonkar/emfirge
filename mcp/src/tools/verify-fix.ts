// emfirge_verify_fix: POST /remediation/verify-fix.
// Pure computation - clones infra, applies the rule's mutation, rebuilds graph, diffs findings.
// Supported rule_ids: EC2-002/003/009, S3-001/002/003, RDS-002/003/004/006, WAF-001, GUARD-001, CW-001.

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

export const verifyFixSchema = {
  rule_id: z
    .string()
    .min(1)
    .describe("Rule ID like EMFIRGE-EC2-002 (or short form EC2-002)"),
  resource_id: z
    .string()
    .min(1)
    .describe(
      "AWS resource ID (sg-..., i-..., arn:...) OR a token from a previous response (SG_001). " +
        "Tokens are auto-expanded.",
    ),
  analysis_id: z.string().min(1).describe("Analysis ID returned by emfirge_scan"),
};

export const verifyFixZodObject = z.object(verifyFixSchema);
export type VerifyFixArgs = z.infer<typeof verifyFixZodObject>;

export async function verifyFixHandler(args: VerifyFixArgs) {
  const realArgs = expandTokens(args) as VerifyFixArgs;

  const result = await backendCall("POST", "/remediation/verify-fix", realArgs, {
    timeout: 30_000,
  });

  const redacted = redactDeep(result);

  return {
    content: [{ type: "text" as const, text: JSON.stringify(redacted, null, 2) }],
  };
}
