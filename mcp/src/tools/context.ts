// emfirge_context: read-only facts about the cloud, from POST /context.
// Facts only, never advice. Resource ids and names in the answer are tokenized
// by redactDeep (they sit under identifier keys); a tokenized resource_id the
// agent sends back is expanded to the real id first.

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

export const CONTEXT_QUESTIONS = [
  "inventory", "resource", "depends_on", "dependents", "reachable",
  "access", "data", "cost", "live", "marks", "baseline",
] as const;

export const contextSchema = {
  question: z.enum(CONTEXT_QUESTIONS).describe(
    "inventory: what exists. resource, depends_on, dependents: one resource and what it depends on or what depends on it (need resource_id). " +
      "reachable: what the internet can reach. access: who can access what. data: data stores and their backups. cost: monthly list price. " +
      "live: recent use. marks: owner tags. baseline: counts for the whole snapshot.",
  ),
  analysis_id: z.string().min(1).optional().describe("Analysis ID from emfirge_scan; omit to use your latest scan"),
  branch_id: z.string().min(1).optional().describe("Branch ID to ask about a branch instead of a scan; do not send together with analysis_id"),
  resource_id: z.string().min(1).optional().describe("Resource ID or token such as S3_001; required for resource, depends_on and dependents"),
};

export const contextZodObject = z.object(contextSchema);
export type ContextArgs = z.infer<typeof contextZodObject>;

export const CONTEXT_DESCRIPTION =
  "Read-only facts about the cloud: what exists, what depends on what, what is reachable, who can access what, " +
  "data and backups, cost, recent use, owner tags and a baseline. Each answer also lists what was checked and what is unknown, and why. " +
  "Facts only, never advice.";

export async function contextHandler(args: ContextArgs) {
  const resourceId = args.resource_id === undefined ? null : (expandTokens(args.resource_id) as string);
  const result = await backendCall("POST", "/context", {
    question: args.question,
    analysis_id: args.analysis_id ?? null,
    branch_id: args.branch_id ?? null,
    resource_id: resourceId,
  });
  return { content: [{ type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) }] };
}
