// emfirge_attack_paths: calls the graph endpoint at /cartography/{id}
// (legacy URL — see backend/app/egraph.py). Slices the response to attack
// paths + crown jewels + orphans. Full graph is too noisy for chat.

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep } from "../tokenize.js";

export const attackPathsSchema = {
  analysis_id: z
    .string()
    .min(1)
    .describe("Analysis ID returned by emfirge_scan"),
};

export const attackPathsZodObject = z.object(attackPathsSchema);
export type AttackPathsArgs = z.infer<typeof attackPathsZodObject>;

interface GraphResponse {
  attack_paths?: unknown;
  critical_resources?: unknown;
  orphaned_resources?: unknown;
  stats?: unknown;
  [k: string]: unknown;
}

export async function attackPathsHandler(args: AttackPathsArgs) {
  const result = await backendCall<GraphResponse>(
    "GET",
    `/cartography/${encodeURIComponent(args.analysis_id)}`,
  );

  const summary = {
    paths: result.attack_paths ?? [],
    critical_resources: result.critical_resources ?? [],
    orphaned_resources: result.orphaned_resources ?? [],
    stats: result.stats ?? {},
  };

  const redacted = redactDeep(summary);

  return {
    content: [{ type: "text" as const, text: JSON.stringify(redacted, null, 2) }],
  };
}
