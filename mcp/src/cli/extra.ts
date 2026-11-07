// Two reads the CLI needs that have no MCP tool of their own: the branch check
// (GET /branches/{id}/check) and a plan's hand-back. Same contract as the tool
// handlers: caller ids are detokenized going out, answers are redacted coming back.

import { backendCall } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

export async function checkBranch(branchId: string): Promise<unknown> {
  const id = encodeURIComponent(expandTokens(branchId) as string);
  return redactDeep(await backendCall("GET", `/branches/${id}/check`));
}

export async function planHandback(branchId: string, planId: string): Promise<unknown> {
  const b = encodeURIComponent(expandTokens(branchId) as string);
  const p = encodeURIComponent(expandTokens(planId) as string);
  return redactDeep(await backendCall("GET", `/branches/${b}/plans/${p}/handback`));
}
