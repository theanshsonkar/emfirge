// emfirge_verify_fix: POST /remediation/verify-fix.
// Pure computation - clones infra, applies the rule's mutation, rebuilds graph, diffs findings.
// Supported rule_ids: EC2-002/003/009, S3-001/002/003, RDS-002/003/004/006, WAF-001, GUARD-001, CW-001.

import { z } from "zod";
import { backendCall, getBaseUrl } from "../client.js";
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

// Rules the backend can deterministically simulate (fix_mutations.py). Keep in
// sync with FIX_MUTATIONS — anything else comes back can_simulate:false.
const SIMULATABLE_RULES =
  "EC2-002, EC2-003, EC2-009, S3-001, S3-002, S3-003, " +
  "RDS-002, RDS-003, RDS-004, RDS-006, WAF-001, GUARD-001, CW-001";

// Derive the human web app URL from the API base (https://emfirge.cloud/api ->
// https://emfirge.cloud), so self-hosters get their own domain too.
function webAppUrl(): string {
  return getBaseUrl().replace(/\/api\/?$/, "");
}

export async function verifyFixHandler(args: VerifyFixArgs) {
  const realArgs = expandTokens(args) as VerifyFixArgs;
  const normalizedArgs = {
    ...realArgs,
    rule_id: normalizeRuleId(realArgs.rule_id),
  };

  const result = (await backendCall("POST", "/remediation/verify-fix", normalizedArgs, {
    timeout: 30_000,
  })) as { can_simulate?: boolean; [k: string]: unknown };

  const web = webAppUrl();

  // Not every rule has a fix-simulation mutation. Instead of returning a bare
  // {can_simulate:false} the user can't act on, explain what verify_fix covers
  // and how to fix this finding anyway.
  if (result && result.can_simulate === false) {
    return {
      content: [
        {
          type: "text" as const,
          text:
            `This finding can't be fix-simulated yet. verify_fix currently proves fixes for: ${SIMULATABLE_RULES}.\n\n` +
            `You can still remediate it: ask me to generate the Terraform for this finding and apply it yourself, ` +
            `or open this scan at ${web} to generate the fix and open a pull request automatically.`,
        },
      ],
    };
  }

  const redacted = redactDeep(result);

  return {
    content: [
      {
        type: "text" as const,
        text:
          JSON.stringify(redacted, null, 2) +
          `\n\nTo apply this fix: ask me to generate the Terraform, or open this scan at ${web} to open a pull request automatically.`,
      },
    ],
  };
}
