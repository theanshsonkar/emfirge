import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep, expandTokens } from "../tokenize.js";

export const branchHandbackSchema = {
  branch_id: z.string().min(1).describe("Branch ID returned by emfirge_create_branch"),
  verify: z.boolean().optional().describe("Verify the returned calls and binding with the backend"),
};

export const branchHandbackZodObject = z.object(branchHandbackSchema);
export type BranchHandbackArgs = z.infer<typeof branchHandbackZodObject>;

type Handback = {
  calls: unknown[];
  input_sha256: string;
  base_analysis_id: string;
  branch_revision: string;
  verdict_id: string;
  [key: string]: unknown;
};

function ok(result: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(redactDeep(result), null, 2) },
    ],
  };
}

export async function branchHandbackHandler(args: BranchHandbackArgs) {
  const expanded = expandTokens(args) as BranchHandbackArgs;
  const branchId = encodeURIComponent(expanded.branch_id);
  const handback = await backendCall<Handback>(
    "GET",
    `/branches/${branchId}/handback`,
  );

  if (!expanded.verify) return ok(handback);

  const verification = await backendCall(
    "POST",
    `/branches/${branchId}/handback/verify`,
    handback,
  );
  return ok({ ...handback, verification });
}
