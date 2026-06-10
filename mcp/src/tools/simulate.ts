// emfirge_simulate_breach: POST /simulate.
// /simulate is an SSE endpoint — we read the stream and return the payload
// of the final `complete` event. Backend skips Haiku in MCP mode (X-MCP),
// so the response is deterministic and arrives in 2-4s.

import { z } from "zod";
import { backendCallSSE } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

export const simulateSchema = {
  query: z
    .string()
    .min(3)
    .max(500)
    .describe(
      "Natural-language query about the infra. Examples: " +
        "'what gets exposed if SG_001 opens port 80', " +
        "'show the worst attack path'. " +
        "Tokens like SG_001 are auto-expanded.",
    ),
  analysis_id: z.string().min(1).describe("Analysis ID returned by emfirge_scan"),
};

export const simulateZodObject = z.object(simulateSchema);
export type SimulateArgs = z.infer<typeof simulateZodObject>;

export async function simulateHandler(args: SimulateArgs) {
  const realArgs = expandTokens(args) as SimulateArgs;

  const result = await backendCallSSE("POST", "/simulate", realArgs, {
    timeout: 60_000,
  });
  const redacted = redactDeep(result);

  return {
    content: [{ type: "text" as const, text: JSON.stringify(redacted, null, 2) }],
  };
}
