// The generic command runner: any manifest command, with no code of its own.
//
// parse (args.ts) -> check the values against the manifest -> expand privacy tokens in id args -> build the request
// the manifest describes -> call the API with the normal client (auth, errors, exit codes) -> redact the answer.
// Redaction and token expansion are the same functions the MCP tool handlers use (tokenize.ts).

import { backendCall } from "../client.js";
import { expandTokens, redactDeep } from "../tokenize.js";
import { UsageError, type Parsed } from "./args.js";
import {
  unsupportedReason, updateNeededMessage, EXIT_UPDATE_NEEDED,
  type ManifestArg, type ManifestCommand, type ManifestRequest,
} from "./manifest.js";
import { CliError, jsonInput, type CliIo } from "./support.js";
import type { Override } from "./overrides.js";

export function updateNeeded(reason: string): CliError {
  return new CliError({ code: "update_needed", message: updateNeededMessage(reason), exit: EXIT_UPDATE_NEEDED });
}

const present = (p: Parsed, name: string): boolean => p.flags[name] !== undefined && p.flags[name] !== false;
const placeholder = (a: ManifestArg): string => a.name.toUpperCase().replace(/-/g, "_");

type Value = string | number | boolean | unknown | unknown[];

async function convert(a: ManifestArg, raw: string, io: CliIo, verb: string): Promise<Value> {
  const label = a.kind === "flag" ? `--${a.name}` : placeholder(a);
  switch (a.type) {
    case "string":
      if (a.choices && !a.choices.includes(raw)) throw new UsageError(`${label} must be one of: ${a.choices.join(", ")}`, verb);
      if (a.pattern && !new RegExp(a.pattern).test(raw)) throw new UsageError(`${label} is not in the expected form`, verb);
      return raw;
    case "integer":
    case "number": {
      const ok = a.type === "integer" ? /^-?\d+$/.test(raw) : raw.trim() !== "" && Number.isFinite(Number(raw));
      if (!ok) throw new UsageError(`${label} must be ${a.type === "integer" ? "a whole number" : "a number"}`, verb);
      const n = Number(raw);
      if (a.min !== undefined && n < a.min) throw new UsageError(`${label} must be at least ${a.min}`, verb);
      return n;
    }
    case "json":
      return jsonInput(io, raw, verb);
    default:
      return raw;
  }
}

/** The value of every argument the caller gave, converted and checked, keyed by argument name. */
async function collect(cmd: ManifestCommand, p: Parsed, io: CliIo): Promise<Map<string, Value>> {
  const values = new Map<string, Value>();
  const positionals = cmd.args.filter((a) => a.kind === "positional");
  const given = [...p.positionals];
  for (const a of positionals) {
    if (a.multiple) {
      if (given.length) values.set(a.name, await Promise.all(given.splice(0).map((g) => convert(a, g, io, p.verb))));
    } else if (given.length) {
      values.set(a.name, await convert(a, given.shift()!, io, p.verb));
    }
  }
  if (given.length) throw new UsageError(`Unexpected argument: ${given[0]}`, p.verb);

  const known = new Set(cmd.args.map((a) => a.name));
  for (const name of Object.keys(p.flags)) {
    if (!known.has(name)) throw new UsageError(`--${name} does not apply to ${cmd.name}`, p.verb);
  }
  for (const a of cmd.args.filter((x) => x.kind === "flag")) {
    const raw = p.flags[a.name];
    if (raw === undefined) continue;
    if (a.type === "bool") values.set(a.name, raw === true);
    else if (Array.isArray(raw)) values.set(a.name, await Promise.all(raw.map((r) => convert(a, r, io, p.verb))));
    else if (typeof raw === "string") values.set(a.name, a.multiple ? [await convert(a, raw, io, p.verb)] : await convert(a, raw, io, p.verb));
  }
  return values;
}

function requireArgs(cmd: ManifestCommand, names: string[], p: Parsed): void {
  for (const name of names) {
    const a = cmd.args.find((x) => x.name === name);
    if (!a) continue;
    const index = cmd.args.filter((x) => x.kind === "positional").indexOf(a);
    const given = a.kind === "flag" ? p.flags[name] !== undefined : p.positionals.length > index;
    if (!given) throw new UsageError(a.kind === "flag" ? `--${name} is required here` : `Missing argument: ${placeholder(a)}`, p.verb);
  }
}

const enc = (v: unknown): string => encodeURIComponent(String(v));

function buildRequest(req: ManifestRequest, values: Map<string, Value>, p: Parsed): { path: string; body?: Record<string, unknown> } {
  const path = req.path.replace(/\{([^{}]+)\}/g, (_m, name: string) => {
    const v = values.get(name);
    if (v === undefined || Array.isArray(v)) throw new UsageError(`Missing argument: ${name.toUpperCase().replace(/-/g, "_")}`, p.verb);
    return enc(v);
  });
  const query = new URLSearchParams();
  for (const [param, arg] of Object.entries(req.query ?? {})) {
    const v = values.get(arg);
    if (v === undefined) continue;
    for (const item of Array.isArray(v) ? v : [v]) query.append(param, String(item));
  }
  const qs = query.toString();
  const full = qs ? `${path}?${qs}` : path;
  if (req.body === undefined) return { path: full };
  const body: Record<string, unknown> = {};
  for (const [field, arg] of Object.entries(req.body)) {
    const v = values.get(arg);
    if (v !== undefined) body[field] = v;
    else if (req.null_unset) body[field] = null;
  }
  return { path: full, body };
}

/** Run one manifest command. `overrides` are the built-in handlers a command may name with `client`. */
export async function runManifestCommand(
  cmd: ManifestCommand, p: Parsed, io: CliIo, overrides: Record<string, Override>,
): Promise<unknown> {
  const why = unsupportedReason(cmd, Object.keys(overrides));
  if (why) throw updateNeeded(why);

  const variant = (cmd.variants ?? []).find((v) => present(p, v.when));
  requireArgs(cmd, [...cmd.args.filter((a) => a.required).map((a) => a.name), ...(variant ? variant.require ?? [] : cmd.require ?? [])], p);

  const clientKey = variant ? variant.client : cmd.client;
  if (clientKey !== undefined) return overrides[clientKey](p, io);

  const request = variant ? variant.request! : cmd.request!;
  const values = await collect(cmd, p, io);
  for (const a of cmd.args) {
    if (a.id && values.has(a.name)) values.set(a.name, expandTokens(values.get(a.name)));
  }
  const { path, body } = buildRequest(request, values, p);
  let result: unknown = await backendCall(request.method, path, body);
  const listKey = cmd.response?.list_key;
  if (listKey && Array.isArray(result)) result = { [listKey]: result, count: result.length };
  return redactDeep(result);
}
