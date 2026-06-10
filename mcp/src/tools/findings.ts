// emfirge_get_findings: GET /logs/by-uuid/{id}. Optional severity filter.

import { z } from "zod";
import { backendCall } from "../client.js";
import { redactDeep } from "../tokenize.js";

export const findingsSchema = {
  analysis_id: z
    .string()
    .min(1)
    .describe("Analysis ID returned by emfirge_scan"),
  severity: z
    .enum(["Critical", "Moderate", "Low"])
    .optional()
    .describe("Filter findings by severity. Omit to get all."),
};

export const findingsZodObject = z.object(findingsSchema);
export type FindingsArgs = z.infer<typeof findingsZodObject>;

interface BackendLog {
  findings_json?: unknown;
  critical_risks?: unknown;
  moderate_risks?: unknown;
  best_practices?: unknown;
  cost_findings?: unknown;
  [k: string]: unknown;
}

export async function findingsHandler(args: FindingsArgs) {
  const result = await backendCall<BackendLog>(
    "GET",
    `/logs/by-uuid/${encodeURIComponent(args.analysis_id)}`,
  );

  // legacy logs store findings_json as a JSON string
  let findings: Record<string, unknown> = {};
  if (typeof result.findings_json === "string") {
    try {
      findings = JSON.parse(result.findings_json);
    } catch {
      findings = result as Record<string, unknown>;
    }
  } else if (result.findings_json && typeof result.findings_json === "object") {
    findings = result.findings_json as Record<string, unknown>;
  } else {
    findings = result as Record<string, unknown>;
  }

  if (args.severity) {
    const key =
      args.severity === "Critical"
        ? "critical_risks"
        : args.severity === "Moderate"
          ? "moderate_risks"
          : "best_practices";
    findings = { [key]: findings[key] ?? [] };
  }

  const redacted = redactDeep(findings);

  return {
    content: [{ type: "text" as const, text: JSON.stringify(redacted, null, 2) }],
  };
}
