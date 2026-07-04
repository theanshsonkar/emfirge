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

// The backend's verify-fix mutation map keys on the FULL rule id
// (e.g. "EMFIRGE-EC2-002"). The tool also accepts the short form
// ("EC2-002") for convenience, so normalize before the backend call —
// otherwise the short form silently returns can_simulate: false.
export function normalizeRuleId(ruleId: string): string {
  const trimmed = ruleId.trim().toUpperCase();
  return trimmed.startsWith("EMFIRGE-") ? trimmed : `EMFIRGE-${trimmed}`;
}

export async function verifyFixHandler(args: VerifyFixArgs) {
  const realArgs = expandTokens(args) as VerifyFixArgs;
  const normalizedArgs = {
    ...realArgs,
    rule_id: normalizeRuleId(realArgs.rule_id),
  };

  const result = await backendCall("POST", "/remediation/verify-fix", normalizedArgs, {
    timeout: 30_000,
  });

  const redacted = redactDeep(result);

  return {
    content: [{ type: "text" as const, text: JSON.stringify(redacted, null, 2) }],
  };
}
