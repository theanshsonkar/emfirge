import { z } from "zod";
import { formatToolError } from "./tool-error.js";

import { setupSchema, setupZodObject, setupHandler } from "./tools/setup.js";
import { loginSchema, loginZodObject, loginHandler, logoutSchema, logoutZodObject, logoutHandler } from "./tools/login.js";
import { scanSchema, scanZodObject, scanHandler } from "./tools/scan.js";
import { findingsSchema, findingsZodObject, findingsHandler } from "./tools/findings.js";
import {
  attackPathsSchema,
  attackPathsZodObject,
  attackPathsHandler,
} from "./tools/attack-paths.js";
import { linkProjectSchema, linkProjectZodObject, linkProjectHandler } from "./tools/link.js";
import {
  verifyFixSchema,
  verifyFixZodObject,
  verifyFixHandler,
} from "./tools/verify-fix.js";
import {
  complianceSchema,
  complianceZodObject,
  complianceHandler,
} from "./tools/compliance.js";
import { simulateSchema, simulateZodObject, simulateHandler } from "./tools/simulate.js";
import { inUseEvidenceSchema, inUseEvidenceZodObject, inUseEvidenceHandler } from "./tools/evidence.js";
import { planVerdictSchema, planVerdictZodObject, planVerdictHandler } from "./tools/plan-verdict.js";
import { branchHandbackSchema, branchHandbackZodObject, branchHandbackHandler } from "./tools/branch-handback.js";
import {
  applyChangeSchema,
  applyChangeZodObject,
  applyChangeHandler,
  branchDiffZodObject,
  branchDiffHandler,
  branchIdSchema,
  branchVerdictZodObject,
  branchVerdictHandler,
  createBranchSchema,
  createBranchZodObject,
  createBranchHandler,
  getBranchZodObject,
  getBranchHandler,
  forkBranchZodObject,
  forkBranchHandler,
  discardBranchZodObject,
  discardBranchHandler,
  listBranchesSchema,
  listBranchesZodObject,
  listBranchesHandler,
  compareBranchesSchema,
  compareBranchesZodObject,
  compareBranchesHandler,
  rollbackBranchZodObject,
  rollbackBranchHandler,
  rollbackBranchToCountZodObject,
  rollbackBranchToCountHandler,
} from "./tools/branches.js";

interface ToolRegistration {
  name: string;
  description: string;
  schema: Record<string, z.ZodTypeAny>;
  zodObject: z.ZodObject<z.ZodRawShape>;
  handler: (args: any) => Promise<{ content: Array<{ type: "text"; text: string }> }>;
}

export const tools: ToolRegistration[] = [
  {
    name: "emfirge_login",
    description: "Sign in to Emfirge with GitHub or Google in your browser.",
    schema: loginSchema as Record<string, z.ZodTypeAny>, zodObject: loginZodObject as z.ZodObject<z.ZodRawShape>, handler: loginHandler,
  },
  {
    name: "emfirge_link_project",
    description: "Link your saved Supabase sign-in to an existing API-key project.",
    schema: linkProjectSchema as Record<string, z.ZodTypeAny>,
    zodObject: linkProjectZodObject as z.ZodObject<z.ZodRawShape>,
    handler: linkProjectHandler,
  },
  {
    name: "emfirge_logout",
    description: "Sign out of Emfirge on this device.",
    schema: logoutSchema as Record<string, z.ZodTypeAny>, zodObject: logoutZodObject as z.ZodObject<z.ZodRawShape>, handler: logoutHandler,
  },
  {
    name: "emfirge_setup_help",
    description:
      "Returns the AWS CloudFormation deploy URL for setting up the read-only IAM role. " +
      "Call this when the user does not have a role ARN yet, or if emfirge_scan returns 403. " +
      "CRITICAL: After calling this tool, paste the deploy URL verbatim in your reply to the user. " +
      "Many MCP clients (Claude Code, Codex CLI, Kiro CLI) hide tool output by default, so saying " +
      "'click the link above' will leave the user with nothing to click.",
    schema: setupSchema as Record<string, z.ZodTypeAny>,
    zodObject: setupZodObject as z.ZodObject<z.ZodRawShape>,
    handler: setupHandler,
  },
  {
    name: "emfirge_scan",
    description:
      "Scan an AWS account for security risks. Returns risk score (0-100), finding counts, " +
      "and an analysis_id for the other tools. Resource IDs are tokenized by default.",
    schema: scanSchema as Record<string, z.ZodTypeAny>,
    zodObject: scanZodObject as z.ZodObject<z.ZodRawShape>,
    handler: scanHandler,
  },
  {
    name: "emfirge_get_findings",
    description:
      "Get the full findings list for a previous scan, optionally filtered by severity " +
      "(Critical/Moderate/Low). Each finding has rule_id, issue, recommendation, attack_path, blast_radius, MITRE mapping.",
    schema: findingsSchema as Record<string, z.ZodTypeAny>,
    zodObject: findingsZodObject as z.ZodObject<z.ZodRawShape>,
    handler: findingsHandler,
  },
  {
    name: "emfirge_attack_paths",
    description:
      "Get attack paths from the internet to internal resources. Shows pivot routes from " +
      "public-facing resources to crown jewels. Also returns chokepoint and orphaned resources.",
    schema: attackPathsSchema as Record<string, z.ZodTypeAny>,
    zodObject: attackPathsZodObject as z.ZodObject<z.ZodRawShape>,
    handler: attackPathsHandler,
  },
  {
    name: "emfirge_verify_fix",
    description:
      "Simulate fixing a finding without applying changes. Clones the infra, applies the rule's " +
      "mutation, rebuilds the graph, re-runs all rules, returns score delta + which other findings get resolved.",
    schema: verifyFixSchema as Record<string, z.ZodTypeAny>,
    zodObject: verifyFixZodObject as z.ZodObject<z.ZodRawShape>,
    handler: verifyFixHandler,
  },
  {
    name: "emfirge_check_compliance",
    description:
      "Get CIS AWS Foundations 1.5 or SOC 2 compliance status. Returns per-requirement status (pass, fail, partial, not_applicable, not_evaluated) using Prowler's published requirement ids, with the rules that triggered each failure and coverage of how many requirements Emfirge evaluates.",
    schema: complianceSchema as Record<string, z.ZodTypeAny>,
    zodObject: complianceZodObject as z.ZodObject<z.ZodRawShape>,
    handler: complianceHandler,
  },
  {
    name: "emfirge_simulate_breach",
    description:
      "Walk a full kill chain end-to-end against the infrastructure graph. Given a " +
      "natural-language scenario or 'what if' query, returns verdict + severity + every " +
      "stage of the attack (entry → pivot → impact) + blast radius + follow-up moves. " +
      "Read-only — no AWS changes.",
    schema: simulateSchema as Record<string, z.ZodTypeAny>,
    zodObject: simulateZodObject as z.ZodObject<z.ZodRawShape>,
    handler: simulateHandler,
  },
  {
    name: "emfirge_create_branch",
    description:
      "Create an isolated infrastructure branch from a completed analysis. Use it to model changes safely before applying anything to AWS.",
    schema: createBranchSchema as Record<string, z.ZodTypeAny>,
    zodObject: createBranchZodObject as z.ZodObject<z.ZodRawShape>,
    handler: createBranchHandler,
  },
  {
    name: "emfirge_compare_branches",
    description: "Compare the verdicts of several branches of the same base analysis side by side. Input: branch_ids (ids from emfirge_list_branches).",
    schema: compareBranchesSchema as Record<string, z.ZodTypeAny>,
    zodObject: compareBranchesZodObject as z.ZodObject<z.ZodRawShape>,
    handler: compareBranchesHandler,
  },
  {
    name: "emfirge_apply_change",
    description:
      "Apply an add, modify, or delete change to a resource in an isolated branch. This changes the branch model, not AWS.",
    schema: applyChangeSchema as Record<string, z.ZodTypeAny>,
    zodObject: applyChangeZodObject as z.ZodObject<z.ZodRawShape>,
    handler: applyChangeHandler,
  },
  {
    name: "emfirge_get_branch",
    description:
      "Read branch metadata and its ordered normalized change log without returning the base infrastructure snapshot.",
    schema: branchIdSchema as Record<string, z.ZodTypeAny>,
    zodObject: getBranchZodObject as z.ZodObject<z.ZodRawShape>,
    handler: getBranchHandler,
  },
  {
    name: "emfirge_fork_branch",
    description:
      "Fork an open branch into a new independent branch with the same base and ordered modeled changes. Does not modify AWS or the parent branch.",
    schema: { ...branchIdSchema, name: z.string().min(1).describe("Name for the new branch") } as Record<string, z.ZodTypeAny>,
    zodObject: forkBranchZodObject as z.ZodObject<z.ZodRawShape>,
    handler: forkBranchHandler,
  },
  {
    name: "emfirge_branch_diff",
    description:
      "Show the infrastructure diff for an isolated branch compared with its base analysis.",
    schema: branchIdSchema as Record<string, z.ZodTypeAny>,
    zodObject: branchDiffZodObject as z.ZodObject<z.ZodRawShape>,
    handler: branchDiffHandler,
  },
  {
    name: "emfirge_branch_verdict",
    description:
      "Evaluate the security verdict for an isolated branch, including the effect of its modeled changes.",
    schema: branchIdSchema as Record<string, z.ZodTypeAny>,
    zodObject: branchVerdictZodObject as z.ZodObject<z.ZodRawShape>,
    handler: branchVerdictHandler,
  },
  {
    name: "emfirge_plan_verdict",
    description:
      "Check a proposed change on a branch before it is applied. Accepted shapes: aws-api {\"format\":\"aws-api-calls/1\",\"calls\":[{\"service\":\"ec2\",\"operation\":\"AuthorizeSecurityGroupIngress\",\"parameters\":{...},\"region\":\"optional\"}]}; aws-cli a list of command strings or {\"format\":\"aws-cli/1\",\"commands\":[...]}, e.g. \"aws ec2 authorize-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0\"; terraform JSON of `terraform show -json <plan>`; cloudformation describe-change-set JSON. Emfirge never runs the change. Returns the verdict and the hand-back bound to the exact input by hash.",
    schema: planVerdictSchema as Record<string, z.ZodTypeAny>,
    zodObject: planVerdictZodObject as z.ZodObject<z.ZodRawShape>,
    handler: planVerdictHandler,
  },
  {
    name: "emfirge_branch_handback",
    description:
      "Return the exact AWS API calls for an isolated branch and their hash binding; optionally verify the calls with the backend. Unmappable changes are returned as gaps and never as partial calls.",
    schema: branchHandbackSchema as Record<string, z.ZodTypeAny>,
    zodObject: branchHandbackZodObject as z.ZodObject<z.ZodRawShape>,
    handler: branchHandbackHandler,
  },
  {
    name: "emfirge_rollback_branch",
    description:
      "Rollback an isolated branch to its base state without changing AWS.",
    schema: branchIdSchema as Record<string, z.ZodTypeAny>,
    zodObject: rollbackBranchZodObject as z.ZodObject<z.ZodRawShape>,
    handler: rollbackBranchHandler,
  },
  {
    name: "emfirge_rollback_branch_to_count",
    description:
      "Truncate an open isolated branch's ordered change log to a specified existing count. " +
      "Use branch_revision from emfirge_get_branch to reject stale state; this changes no AWS resources.",
    schema: rollbackBranchToCountZodObject.shape as Record<string, z.ZodTypeAny>,
    zodObject: rollbackBranchToCountZodObject as z.ZodObject<z.ZodRawShape>,
    handler: rollbackBranchToCountHandler,
  },
  {
    name: "emfirge_discard_branch",
    description:
      "Discard an isolated branch when it is no longer needed. This does not change AWS.",
    schema: branchIdSchema as Record<string, z.ZodTypeAny>,
    zodObject: discardBranchZodObject as z.ZodObject<z.ZodRawShape>,
    handler: discardBranchHandler,
  },
  {
    name: "emfirge_list_branches",
    description:
      "List isolated infrastructure branches, optionally filtered by their base analysis ID. Returns an object with a branches array and count.",
    schema: listBranchesSchema as Record<string, z.ZodTypeAny>,
    zodObject: listBranchesZodObject as z.ZodObject<z.ZodRawShape>,
    handler: listBranchesHandler,
  },
  {
    name: "emfirge_in_use_evidence",
    description:
      "Read-only: reads CloudTrail event history (free) and CloudWatch metrics (billed API requests beyond the free tier) only for resources the branch deletes; can only make a verdict stricter, never looser. role_arn is required only when accepting an estimate and must be the same role used by emfirge_scan. Never call with accept_estimate_id unless the user agreed to the shown estimate.",
    schema: inUseEvidenceSchema as Record<string, z.ZodTypeAny>,

    zodObject: inUseEvidenceZodObject as z.ZodObject<z.ZodRawShape>,
    handler: inUseEvidenceHandler,
  },
];


function zodFieldToJsonSchema(field: z.ZodTypeAny): Record<string, unknown> {
  let inner = field;
  while (
    inner instanceof z.ZodOptional ||
    inner instanceof z.ZodDefault ||
    inner instanceof z.ZodNullable
  ) {
    inner = (inner as any)._def.innerType;
  }

  const base: Record<string, unknown> = {};
  if (field.description) base.description = field.description;

  if (inner instanceof z.ZodString) base.type = "string";
  else if (inner instanceof z.ZodNumber) base.type = "number";
  else if (inner instanceof z.ZodBoolean) base.type = "boolean";
  else if (inner instanceof z.ZodEnum) {
    base.type = "string";
    base.enum = (inner as any)._def.values;
  } else if (inner instanceof z.ZodArray) {
    base.type = "array";
    base.items = zodFieldToJsonSchema((inner as any)._def.type);
  } else if (inner instanceof z.ZodRecord) {
    base.type = "object";
    base.additionalProperties = zodFieldToJsonSchema((inner as any)._def.valueType);
  } else if (inner instanceof z.ZodUnknown) {
    return field.description ? { description: field.description } : {};
  } else base.type = "string";

  return base;
}
export function zodToJsonSchema(zodObject: z.ZodObject<z.ZodRawShape>): Record<string, unknown> {
  const shape = zodObject.shape;
  const properties: Record<string, unknown> = {};
  const required: string[] = [];

  for (const [key, field] of Object.entries(shape)) {
    properties[key] = zodFieldToJsonSchema(field as z.ZodTypeAny);
    if (!(field as z.ZodTypeAny).isOptional()) required.push(key);
  }

  const out: Record<string, unknown> = { type: "object", properties };
  if (required.length > 0) out.required = required;
  return out;
}

export async function dispatchTool(name: string, args: unknown) {
  try {
    const tool = tools.find((entry) => entry.name === name);
    if (!tool) throw new Error(`Unknown tool: ${name}`);
    return await tool.handler(tool.zodObject.parse(args ?? {}));
  } catch (error) {
    return {
      content: [{ type: "text" as const, text: formatToolError(error) }],
      isError: true,
    };
  }
}

