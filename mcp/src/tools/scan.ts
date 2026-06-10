// emfirge_scan: POST /analyze. Scans take 30-60s on real accounts.

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep } from "../tokenize.js";

export const scanSchema = {
  role_arn: z
    .string()
    .regex(/^arn:aws:iam::\d{12}:role\/.+$/, "Must be a valid IAM role ARN")
    .describe(
      "AWS IAM role ARN to assume. Must trust Emfirge's account with ExternalId 'aws-risk-agent'. " +
        "If the user doesn't have one, call emfirge_setup_help first.",
    ),
  region: z
    .string()
    .default("us-east-1")
    .describe(
      "AWS region (e.g., us-east-1, ap-south-1, eu-west-1, eu-central-1, ap-southeast-2). " +
        "Most AWS resources are region-specific — scanning the wrong region returns 0 findings " +
        "even on busy accounts, which makes the user think their account is clean when it isn't. " +
        "ALWAYS ask the user which region they want to scan if they haven't specified one. " +
        "Only fall back to the us-east-1 default if the user explicitly says 'use the default' or 'I don't know'.",
    ),
};

export const scanZodObject = z.object(scanSchema);
export type ScanArgs = z.infer<typeof scanZodObject>;

export async function scanHandler(args: ScanArgs) {
  const result = await backendCall("POST", "/analyze", args, { timeout: 180_000 });
  const redacted = redactDeep(result);

  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(redacted, null, 2),
      },
    ],
  };
}
