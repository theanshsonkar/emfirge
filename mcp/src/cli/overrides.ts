// Commands that need code built into the CLI. The manifest names them by key (`client`), and these are the keys this
// version has. Each needs more than one request, a local file or stdin, or post-processing of the answer, which a
// request description cannot express:
//   context.refresh / .simulate   server-sent events; refresh also adds the scans-remaining note
//   context.findings / .attack-paths / .compliance   the answer is filtered or reshaped here
//   try                           file / stdin / inline JSON inputs, AWS CLI shorthand refusal, a three-request flow
//   check.policy / check.evidence estimate first, then an approved run; a 409 turns into the estimate again
//   report.verify                 two requests, the second sends the first answer back
// They call the same MCP tool handlers as before, so requests, token expansion and redaction are unchanged.

import { UsageError, type Parsed } from "./args.js";
import { findShorthand } from "./extra.js";
import { tool, str, on, need, oneId, dropUndefined, jsonInput, type CliIo } from "./support.js";

export type Override = (p: Parsed, io: CliIo) => Promise<unknown>;

async function tryVerb(p: Parsed, io: CliIo): Promise<unknown> {
  if (on(p, "verify-fix")) {
    return tool("emfirge_verify_fix", { rule_id: need(p, "rule"), resource_id: need(p, "resource"), analysis_id: need(p, "analysis") });
  }
  const kinds = ["typed", "aws-cli", "aws-api", "terraform", "cloudformation"].filter((k) => p.flags[k] !== undefined);
  if (kinds.length !== 1) {
    throw new UsageError("Give exactly one of: --typed, --aws-cli, --aws-api, --terraform, --cloudformation", p.verb);
  }
  const branchId = oneId(p);
  const kind = kinds[0];

  if (kind === "typed") {
    const change = await jsonInput(io, p.flags.typed as string, p.verb);
    if (change === null || typeof change !== "object" || Array.isArray(change)) {
      throw new UsageError("--typed must be a JSON object", p.verb);
    }
    return tool("emfirge_apply_change", { ...(change as Record<string, unknown>), branch_id: branchId });
  }

  let plan: unknown;
  if (kind === "aws-cli") {
    const values = p.flags["aws-cli"] as string[];
    const first = values[0].trim();
    if (values.length === 1 && (first.startsWith("[") || first.startsWith("{"))) {
      const parsed = await jsonInput(io, values[0], p.verb);
      plan = Array.isArray(parsed) ? parsed : (parsed as { commands?: unknown })?.commands;
      if (!Array.isArray(plan)) throw new UsageError("--aws-cli JSON must be a list of commands or {commands:[...]}", p.verb);
    } else plan = values;
    (plan as unknown[]).forEach((command, index) => {
      const hit = typeof command === "string" ? findShorthand(command) : undefined;
      if (hit) {
        throw new UsageError(
          `Command ${index + 1}: ${hit.option} uses AWS shorthand syntax (${hit.value.slice(0, 40)}), which is not supported. ` +
          `Emfirge will not guess what it means; pass the value as JSON, for example ${hit.option} '{"Key":"value"}'.`,
          p.verb);
      }
    });
  } else {
    plan = await jsonInput(io, p.flags[kind] as string, p.verb);
    if (plan === null || typeof plan !== "object" || Array.isArray(plan)) {
      throw new UsageError(`--${kind} must be a JSON object`, p.verb);
    }
  }
  return tool("emfirge_plan_verdict", { branch_id: branchId, format: kind, plan });
}

/**
 * `context --refresh` answers with what happened, not the old scanner report (scores, CRITICAL labels,
 * recommendations): facts, not verdicts. The old report stays reachable with `context --findings`.
 */
export function scanSummary(raw: unknown): Record<string, unknown> {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const id = typeof r.analysis_id === "string" ? r.analysis_id : null;
  const out: Record<string, unknown> = {
    scan: "done",
    analysis_id: id,
    region: r.region_analyzed ?? null,
    resources: r.total_resources_scanned ?? null,
    seconds: r.scan_duration_seconds ?? null,
    warnings: Array.isArray(r.warnings) ? r.warnings : [],
    next: id
      ? [`emfirge context inventory --analysis ${id}`, `emfirge branch open --analysis ${id} --name NAME`]
      : ["emfirge context inventory"],
    note: "What was and was not read is listed under `unknown` in every context answer. " +
      "The old scanner report (scores, findings) is still there: emfirge context --findings --analysis ID.",
  };
  if (typeof r.note === "string") out.quota = r.note;
  if (r.message && !id) out.message = r.message;
  return out;
}

export const OVERRIDES: Record<string, Override> = {
  "context.refresh": async (p) =>
    scanSummary(await tool("emfirge_scan", { role_arn: need(p, "role-arn"), region: need(p, "region") })),
  "context.findings": async (p) =>
    tool("emfirge_get_findings", dropUndefined({ analysis_id: need(p, "analysis"), severity: str(p, "severity") })),
  "context.attack-paths": async (p) => tool("emfirge_attack_paths", { analysis_id: need(p, "analysis") }),
  "context.compliance": async (p) =>
    tool("emfirge_check_compliance", dropUndefined({ analysis_id: need(p, "analysis"), framework: str(p, "framework") })),
  "context.simulate": async (p) => tool("emfirge_simulate_breach", { query: str(p, "simulate")!, analysis_id: need(p, "analysis") }),
  try: tryVerb,
  "check.policy": async (p) =>
    tool("emfirge_policy_checks", dropUndefined({
      branch_id: oneId(p), approve: on(p, "approve") ? true : undefined, accept_estimate_id: str(p, "accept-estimate"),
    })),
  "check.evidence": async (p) =>
    tool("emfirge_in_use_evidence", dropUndefined({
      branch_id: oneId(p), sources: p.flags.source as string[] | undefined,
      accept_estimate_id: str(p, "accept-estimate"), role_arn: str(p, "role-arn"),
    })),
  "report.verify": async (p) => tool("emfirge_branch_handback", { branch_id: oneId(p), verify: true }),
};

export const CLIENT_KEYS: readonly string[] = Object.keys(OVERRIDES);

