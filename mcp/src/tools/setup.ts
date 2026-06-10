// emfirge_setup_help: returns a clickable CloudFormation deploy URL for the IAM role.
// First-time users don't have a role ARN yet, and chat doesn't have buttons.

import { z } from "zod";

export const setupSchema = {} as const;

const TEMPLATE_URL =
  process.env.EMFIRGE_TEMPLATE_URL ??
  "https://emfirge-reports.s3.ap-south-1.amazonaws.com/cloudformation/iam-role.yaml";

const TRUSTED_ACCOUNT = process.env.EMFIRGE_TRUSTED_ACCOUNT_ID ?? "282027772803";
const EXTERNAL_ID = process.env.EMFIRGE_EXTERNAL_ID ?? "aws-risk-agent";

export async function setupHandler(_args: Record<string, never>) {
  const cfUrl =
    `https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?` +
    `templateURL=${encodeURIComponent(TEMPLATE_URL)}` +
    `&stackName=EmfirgeReadOnlyStack` +
    `&param_ExternalId=${EXTERNAL_ID}`;

  // IMPORTANT: This text is engineered for cross-client rendering.
  // - URL on the first line so the LLM can't summarize past it.
  // - Bare URL (no markdown link) so terminal clients (Claude Code, Codex CLI,
  //   Kiro CLI) display it raw and the user can copy/click in modern terminals.
  // - Explicit assistant note because TUI clients hide tool output by default;
  //   the LLM has to relay it verbatim or the user sees nothing actionable.
  const text = [
    `Deploy URL: ${cfUrl}`,
    "",
    "(Note to assistant: paste the URL above verbatim in your reply. " +
      "Users on CLI clients — Claude Code, Codex, Kiro CLI — do not see tool output by default.)",
    "",
    "Tell the user these next steps:",
    "1. Open the URL above in your browser. The AWS console loads with the CloudFormation form pre-filled.",
    "2. Tick the 'I acknowledge that AWS CloudFormation might create IAM resources' checkbox and click 'Create stack'. Takes ~30 seconds.",
    "3. When the stack reaches CREATE_COMPLETE, open the Outputs tab and copy the RoleArn (starts with arn:aws:iam::).",
    "4. Paste the RoleArn back here and the scan will run.",
    "",
    "Background (relay only if asked):",
    `- Trusts AWS account ${TRUSTED_ACCOUNT}, ExternalId "${EXTERNAL_ID}".`,
    "- Read-only: AWS-managed SecurityAudit policy + a handful of extra read perms. No write access of any kind.",
    "- Instantly revocable — deleting the CloudFormation stack removes the role.",
    "- Details: https://emfirge.cloud/security.html",
  ].join("\n");

  return {
    content: [{ type: "text" as const, text }],
  };
}

export const setupZodObject = z.object(setupSchema);
