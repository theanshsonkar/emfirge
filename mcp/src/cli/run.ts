// The emfirge CLI. Thin by design: sign in, tokenize, send the verb, print the answer.
// All logic lives on the hosted engine; request building, token expansion and
// redaction are the same code the MCP tools use (tools-registry handlers).
//
// Exit codes: 0 ok, 1 usage error, 2 not signed in / forbidden, 3 not found, 4 server or network.

import { readFileSync } from "node:fs";
import { ZodError } from "zod";
import { tools } from "../tools-registry.js";
import { setInteractiveLogin } from "../client.js";
import { redactDeep } from "../tokenize.js";
import { parseCommand, UsageError, type Parsed } from "./args.js";
import { VERB_NAMES, verbHelp, topUsage } from "./verbs.js";
import { formatOk, formatError, type ErrorInfo } from "./output.js";
import { checkBranch, planHandback } from "./extra.js";
import { loadGuide } from "./guide.js";

export interface CliIo {
  out: (s: string) => void;
  err: (s: string) => void;
  readFile: (path: string) => string;
  readStdin: () => Promise<string>;
}

const defaultIo: CliIo = {
  out: (s) => { process.stdout.write(s); },
  err: (s) => { process.stderr.write(s); },
  readFile: (p) => readFileSync(p, "utf-8"),
  readStdin: async () => {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString("utf-8");
  },
};

class CliError extends Error {
  constructor(public readonly info: ErrorInfo) {
    super(info.message);
  }
}

type ToolResult = { content: Array<{ type: "text"; text: string }> };

/** Run an MCP tool handler (same request code, tokenizing and redaction) and return its JSON. */
async function tool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const t = tools.find((x) => x.name === name);
  if (!t) throw new Error(`Unknown tool: ${name}`);
  const result = (await t.handler(t.zodObject.parse(args))) as ToolResult;
  return parseToolText(result.content.map((c) => c.text).join("\n"));
}

function parseToolText(text: string): unknown {
  try { return JSON.parse(text); } catch { /* fall through */ }
  const split = text.indexOf("\n\n");
  if (split > 0) {
    try {
      const head = JSON.parse(text.slice(0, split));
      if (head && typeof head === "object" && !Array.isArray(head)) {
        return { ...head, note: text.slice(split + 2).trim() };
      }
    } catch { /* plain text */ }
  }
  return { message: text };
}

const str = (p: Parsed, name: string): string | undefined => {
  const v = p.flags[name];
  return typeof v === "string" ? v : undefined;
};
const on = (p: Parsed, name: string): boolean => p.flags[name] === true;

function need(p: Parsed, name: string): string {
  const v = str(p, name);
  if (v === undefined) throw new UsageError(`--${name} is required here`, p.verb);
  return v;
}

function oneId(p: Parsed, what = "BRANCH"): string {
  if (p.positionals.length !== 1) throw new UsageError(`Give exactly one ${what} id`, p.verb);
  return p.positionals[0];
}

function count(p: Parsed, name: string): number | undefined {
  const v = str(p, name);
  if (v === undefined) return undefined;
  if (!/^\d+$/.test(v)) throw new UsageError(`--${name} must be a whole number`, p.verb);
  return Number(v);
}

function dropUndefined(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));
}

/** A JSON input: "-" is stdin, text starting with { or [ is inline, anything else is a file path. */
async function jsonInput(io: CliIo, value: string, verb: string): Promise<unknown> {
  let text: string;
  const t = value.trim();
  if (value === "-") text = await io.readStdin();
  else if (t.startsWith("{") || t.startsWith("[")) text = value;
  else {
    try { text = io.readFile(value); } catch { throw new UsageError(`Cannot read file: ${value}`, verb); }
  }
  try { return JSON.parse(text); } catch { throw new UsageError(`Input is not valid JSON: ${value === "-" ? "stdin" : t.slice(0, 40)}`, verb); }
}

// ---- verbs ----

async function context(p: Parsed): Promise<unknown> {
  if (on(p, "refresh")) {
    return tool("emfirge_scan", { role_arn: need(p, "role-arn"), region: need(p, "region") });
  }
  if (on(p, "findings")) {
    return tool("emfirge_get_findings", dropUndefined({ analysis_id: need(p, "analysis"), severity: str(p, "severity") }));
  }
  if (on(p, "attack-paths")) return tool("emfirge_attack_paths", { analysis_id: need(p, "analysis") });
  if (on(p, "compliance")) {
    return tool("emfirge_check_compliance", dropUndefined({ analysis_id: need(p, "analysis"), framework: str(p, "framework") }));
  }
  const simulate = str(p, "simulate");
  if (simulate !== undefined) return tool("emfirge_simulate_breach", { query: simulate, analysis_id: need(p, "analysis") });

  if (p.positionals.length !== 1) throw new UsageError("Give one question, e.g. `emfirge context inventory`", p.verb);
  return tool("emfirge_context", dropUndefined({
    question: p.positionals[0],
    analysis_id: str(p, "analysis"),
    branch_id: str(p, "branch"),
    resource_id: str(p, "resource"),
  }));
}

async function branch(p: Parsed): Promise<unknown> {
  switch (p.sub) {
    case "open": return tool("emfirge_create_branch", { base_analysis_id: need(p, "analysis"), name: need(p, "name") });
    case "fork":
      return tool("emfirge_fork_branch", dropUndefined({ branch_id: oneId(p), name: need(p, "name"), branch_revision: str(p, "revision") }));
    case "list": return tool("emfirge_list_branches", dropUndefined({ base_analysis_id: str(p, "analysis") }));
    case "get": return tool("emfirge_get_branch", { branch_id: oneId(p) });
    case "rollback":
      return tool("emfirge_rollback_branch", dropUndefined({
        branch_id: oneId(p), expected_change_count: count(p, "expected-count"), branch_revision: str(p, "revision"),
      }));
    case "rollback-to":
      return tool("emfirge_rollback_branch_to_count", dropUndefined({
        branch_id: oneId(p), target_change_count: count(p, "count") ?? need(p, "count"), branch_revision: str(p, "revision"),
      }));
    case "discard":
      return tool("emfirge_discard_branch", dropUndefined({
        branch_id: oneId(p), expected_change_count: count(p, "expected-count"), branch_revision: str(p, "revision"),
      }));
    case "compare":
      if (p.positionals.length < 1) throw new UsageError("Give at least one BRANCH id", p.verb);
      return tool("emfirge_compare_branches", { branch_ids: p.positionals });
    default: throw new UsageError("Unknown branch command", p.verb);
  }
}

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
  } else {
    plan = await jsonInput(io, p.flags[kind] as string, p.verb);
    if (plan === null || typeof plan !== "object" || Array.isArray(plan)) {
      throw new UsageError(`--${kind} must be a JSON object`, p.verb);
    }
  }
  return tool("emfirge_plan_verdict", { branch_id: branchId, format: kind, plan });
}

async function check(p: Parsed): Promise<unknown> {
  const branchId = oneId(p);
  if (on(p, "verdict")) return tool("emfirge_branch_verdict", { branch_id: branchId });
  if (on(p, "diff")) return tool("emfirge_branch_diff", { branch_id: branchId });
  if (on(p, "policy")) {
    return tool("emfirge_policy_checks", dropUndefined({
      branch_id: branchId, approve: on(p, "approve") ? true : undefined, accept_estimate_id: str(p, "accept-estimate"),
    }));
  }
  if (on(p, "evidence")) {
    const sources = p.flags.source as string[] | undefined;
    return tool("emfirge_in_use_evidence", dropUndefined({
      branch_id: branchId, sources, accept_estimate_id: str(p, "accept-estimate"), role_arn: str(p, "role-arn"),
    }));
  }
  return checkBranch(branchId);
}

async function report(p: Parsed): Promise<unknown> {
  const branchId = oneId(p);
  const plan = str(p, "plan");
  if (plan !== undefined) return planHandback(branchId, plan);
  return tool("emfirge_branch_handback", dropUndefined({ branch_id: branchId, verify: on(p, "verify") ? true : undefined }));
}

async function connect(p: Parsed): Promise<unknown> {
  if (on(p, "link")) return tool("emfirge_link_project", {});
  const result = (await tool("emfirge_setup_help", {})) as { message?: string };
  const url = result.message?.match(/^Deploy URL: (\S+)/m)?.[1];
  return url ? { deploy_url: url, ...result } : result;
}

async function login(io: CliIo): Promise<unknown> {
  if (process.env.EMFIRGE_API_KEY) {
    return { signed_in: true, message: "EMFIRGE_API_KEY is set, so Emfirge uses that key. Unset it to use browser sign-in." };
  }
  const { getAccessToken } = await import("../auth/session.js");
  if (await getAccessToken()) return { signed_in: true, message: "You're already signed in." };
  const { startLogin } = await import("../auth/login.js");
  const { url, pending } = await startLogin();
  io.err(`Sign in with GitHub or Google. Opening your browser; if it does not open, go to ${url}\n`);
  if (!(await pending)) throw new CliError({ code: "not_signed_in", message: "Sign-in did not finish. Run: emfirge login", exit: 2 });
  return { signed_in: true, message: "Signed in." };
}

function usageInfo(message: string): ErrorInfo {
  return { code: "usage", message, exit: 1 };
}

function classify(e: unknown): ErrorInfo {
  if (e instanceof CliError) return e.info;
  if (e instanceof UsageError) return usageInfo(e.message);
  if (e instanceof ZodError) {
    const shown = e.issues.slice(0, 5).map((i) => `${i.path.length ? i.path.join(".") : "input"}: ${i.message}`);
    return usageInfo(String(redactDeep(`Invalid input: ${shown.join("; ")}`)));
  }
  const message = String(redactDeep(e instanceof Error ? e.message : String(e)));
  const status = (e as { status?: unknown } | null)?.status;
  if (status === 401 || status === 403) return { code: status === 401 ? "not_signed_in" : "forbidden", message, exit: 2 };
  if (status === 404) return { code: "not_found", message, exit: 3 };
  return { code: "server_error", message, exit: 4 };
}

export async function runCli(argv: string[], partial: Partial<CliIo> = {}): Promise<number> {
  const io: CliIo = { ...defaultIo, ...partial };
  const human = argv.includes("--human");

  const fail = (info: ErrorInfo, usage?: string): number => {
    io.err(formatError(info, human));
    if (usage) io.err(usage);
    return info.exit;
  };

  const [first] = argv;
  if (first === undefined) return fail(usageInfo("No command given."), topUsage());
  if (first === "--help" || first === "-h") { io.out(topUsage()); return 0; }
  if (first === "--version" || first === "-v") {
    const { version } = await import("./version.js");
    io.out(`${version()}\n`);
    return 0;
  }
  if (first === "help") {
    const topic = argv[1];
    if (topic === undefined) { io.out(topUsage()); return 0; }
    if (!VERB_NAMES.includes(topic)) return fail(usageInfo(`Unknown command: ${topic}`), topUsage());
    io.out(verbHelp(topic));
    return 0;
  }

  let parsed: Parsed;
  try {
    parsed = parseCommand(argv);
  } catch (e) {
    if (e instanceof UsageError) {
      return fail(usageInfo(e.message), e.verb ? verbHelp(e.verb) : topUsage());
    }
    return fail(classify(e));
  }
  if (parsed.help) { io.out(verbHelp(parsed.verb)); return 0; }

  setInteractiveLogin(false);
  try {
    let result: unknown;
    switch (parsed.verb) {
      case "context": result = await context(parsed); break;
      case "branch": result = await branch(parsed); break;
      case "try": result = await tryVerb(parsed, io); break;
      case "check": result = await check(parsed); break;
      case "report": result = await report(parsed); break;
      case "request":
        throw new CliError({
          code: "not_built",
          message: "emfirge request is not built yet (v2). Ask the owner yourself, then use `emfirge report` after you apply.",
          exit: 1,
        });
      case "connect": result = await connect(parsed); break;
      case "login": result = await login(io); break;
      case "logout": result = await tool("emfirge_logout", {}); break;
      case "guide": io.out(loadGuide()); return 0;
      default: throw new UsageError(`Unknown command: ${parsed.verb}`);
    }
    io.out(formatOk(result, parsed.human));
    return 0;
  } catch (e) {
    const info = classify(e);
    return fail(info, e instanceof UsageError && e.verb ? verbHelp(e.verb) : undefined);
  }
}
