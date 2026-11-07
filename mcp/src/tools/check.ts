// emfirge_check: the branch check (GET /branches/{id}/check).
// Same contract as the other branch tools: the branch id is detokenized going out
// and the whole answer goes through redactDeep coming back.

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

export const CHECK_DESCRIPTION =
  "Runs the check on a branch and returns facts about consequences for six damages " +
  "(data, exposure, money, availability, control, outside world), with what was checked " +
  "and what is unknown. Unknown means not checked, never safe. Facts, not advice.";

export const checkSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
};

export const checkZodObject = z.object(checkSchema);
export type CheckArgs = z.infer<typeof checkZodObject>;

export async function checkHandler(args: CheckArgs) {
  const id = encodeURIComponent(expandTokens(args.branch_id) as string);
  const result = await backendCall("GET", `/branches/${id}/check`);
  return {
    content: [{ type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) }],
  };
}
