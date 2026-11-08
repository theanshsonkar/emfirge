// Pieces shared by the runner, the generic command executor and the built-in commands.

import { tools } from "../tools-registry.js";
import { UsageError, type Parsed } from "./args.js";
import type { ErrorInfo } from "./output.js";

export interface CliIo {
  out: (s: string) => void;
  err: (s: string) => void;
  readFile: (path: string) => string;
  readStdin: () => Promise<string>;
  /** Where the command list comes from. Tests replace it; the default asks the server, then falls back to the bundled copy. */
  loadManifest?: () => Promise<import("./manifest.js").LoadedManifest>;
}

export class CliError extends Error {
  constructor(public readonly info: ErrorInfo) {
    super(info.message);
  }
}

type ToolResult = { content: Array<{ type: "text"; text: string }> };

/** Run an MCP tool handler (same request code, tokenizing and redaction) and return its JSON. */
export async function tool(name: string, args: Record<string, unknown>): Promise<unknown> {
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

export const str = (p: Parsed, name: string): string | undefined => {
  const v = p.flags[name];
  return typeof v === "string" ? v : undefined;
};
export const on = (p: Parsed, name: string): boolean => p.flags[name] === true;

export function need(p: Parsed, name: string): string {
  const v = str(p, name);
  if (v === undefined) throw new UsageError(`--${name} is required here`, p.verb);
  return v;
}

export function oneId(p: Parsed, what = "BRANCH"): string {
  if (p.positionals.length !== 1) throw new UsageError(`Give exactly one ${what} id`, p.verb);
  return p.positionals[0];
}

export function count(p: Parsed, name: string): number | undefined {
  const v = str(p, name);
  if (v === undefined) return undefined;
  if (!/^\d+$/.test(v)) throw new UsageError(`--${name} must be a whole number`, p.verb);
  return Number(v);
}

export function dropUndefined(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));
}

/** A JSON input: "-" is stdin, text starting with { or [ is inline, anything else is a file path. */
export async function jsonInput(io: Pick<CliIo, "readFile" | "readStdin">, value: string, verb: string): Promise<unknown> {
  let text: string;
  const t = value.trim();
  if (value === "-") text = await io.readStdin();
  else if (t.startsWith("{") || t.startsWith("[")) text = value;
  else {
    try { text = io.readFile(value); } catch { throw new UsageError(`Cannot read file: ${value}`, verb); }
  }
  try { return JSON.parse(text); } catch { throw new UsageError(`Input is not valid JSON: ${value === "-" ? "stdin" : t.slice(0, 40)}`, verb); }
}
