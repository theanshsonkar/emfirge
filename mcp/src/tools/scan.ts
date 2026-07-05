// emfirge_scan: POST /analyze/stream (SSE). Scans take 30-60s on real accounts,
// and large accounts can exceed a proxy's request timeout on the plain /analyze
// route. The streaming endpoint keeps the connection alive (up to ~5 min) and
// emits the full AnalysisResponse as its final `complete` event, so we consume
// it via backendCallSSE. Progress events are dropped — MCP tool calls can't
// surface mid-call progress to the chat.

import { z } from "zod";
import { backendCall, backendCallSSE } from "../client.js";
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
    .min(1)
    .describe(
      "AWS region to scan (e.g., us-east-1, ap-south-1, eu-west-1, eu-central-1, ap-southeast-2). " +
        "REQUIRED — there is no default. Most AWS resources are region-specific, so scanning the " +
        "wrong region returns 0 findings even on a busy account and makes the user think they're " +
        "clean when they aren't. If the user gave a role ARN but no region, ASK them which region " +
        "to scan before calling this tool. Do not guess.",
    ),
};

export const scanZodObject = z.object(scanSchema);
export type ScanArgs = z.infer<typeof scanZodObject>;

export async function scanHandler(args: ScanArgs) {
  const result = await backendCallSSE("POST", "/analyze/stream", args, {
    timeout: 240_000,
  });
  const redacted = redactDeep(result);

  let text = JSON.stringify(redacted, null, 2);

  // Best-effort quota footer so the user knows where they stand BEFORE they
  // hit a 429. account_id is the 5th ':'-delimited field of the role ARN
  // (arn:aws:iam::ACCOUNT_ID:role/Name) — no extra AWS call needed. Never let
  // a usage-lookup failure break the scan result.
  const accountId = args.role_arn.split(":")[4];
  if (accountId) {
    try {
      const usage = await backendCall<{ scans?: { used: number; limit: number } }>(
        "GET",
        `/usage/remaining?account_id=${encodeURIComponent(accountId)}`,
        undefined,
        { timeout: 10_000 },
      );
      if (usage?.scans) {
        const remaining = Math.max(0, usage.scans.limit - usage.scans.used);
        text += `\n\nScans remaining today: ${remaining}/${usage.scans.limit} (resets midnight UTC).`;
      }
    } catch {
      /* usage endpoint unavailable — omit the footer, scan result stands */
    }
  }

  return {
    content: [
      {
        type: "text" as const,
        text,
      },
    ],
  };
}
