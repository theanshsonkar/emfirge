// The command manifest: the server's list of CLI commands (GET /cli/manifest), and a copy bundled in this package.
//
// The CLI is a generic runner over this document, so a command added on the server works in an already installed
// CLI. What the CLI must understand is versioned: SUPPORTED_PROTOCOL for the document format, FEATURES for optional
// capabilities a command can ask for, and the client keys for commands that run code built into the CLI. Anything
// beyond that is reported as "needs a newer emfirge", never skipped silently.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getBaseUrl } from "../client.js";

/** The manifest format this CLI reads. A server with a higher number needs a newer CLI. */
export const SUPPORTED_PROTOCOL = 1;

/** Optional capabilities a command may list under `requires`. None are defined yet; a command asking for one needs a newer CLI. */
export const FEATURES: ReadonlySet<string> = new Set<string>();

export const UPDATE_COMMAND = "npx emfirge@latest";
/** Exit code for "this needs a newer emfirge". */
export const EXIT_UPDATE_NEEDED = 6;

export type ArgType = "string" | "number" | "integer" | "bool" | "json";
const ARG_TYPES: ReadonlySet<string> = new Set(["string", "number", "integer", "bool", "json"]);

export interface ManifestArg {
  name: string;
  kind: "flag" | "positional";
  type: ArgType;
  help: string;
  required?: boolean;
  multiple?: boolean;
  /** May hold a privacy token (S3_001); expanded to the real id before anything is sent. */
  id?: boolean;
  choices?: string[];
  pattern?: string;
  min?: number;
}

export interface ManifestRequest {
  method: "GET" | "POST";
  path: string;
  query?: Record<string, string>;
  body?: Record<string, string>;
  null_unset?: boolean;
}

export interface ManifestVariant {
  when: string;
  request?: ManifestRequest;
  client?: string;
  require?: string[];
}

export interface HumanHint {
  title?: string;
  sections?: string[];
}

export interface ManifestCommand {
  name: string;
  summary: string;
  args: ManifestArg[];
  usage?: string[];
  examples?: string[];
  require?: string[];
  request?: ManifestRequest;
  client?: string;
  variants?: ManifestVariant[];
  variants_exclusive?: boolean;
  response?: { list_key?: string; reveal?: string[] };
  human?: HumanHint;
  requires?: string[];
}

export interface Manifest {
  protocol: number;
  groups?: Record<string, string>;
  commands: ManifestCommand[];
}

export type ManifestSource = "server" | "bundled";

export interface LoadedManifest {
  manifest: Manifest;
  source: ManifestSource;
  /** Set when the server's protocol is newer than SUPPORTED_PROTOCOL; `manifest` is then the bundled copy and must not be used to run commands. */
  tooNew?: number;
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** True when the document has the structure every protocol reads: a protocol number and named commands with args. */
export function looksLikeManifest(v: unknown): v is Manifest {
  if (!isObj(v) || !Number.isInteger(v.protocol) || (v.protocol as number) < 1 || !Array.isArray(v.commands)) return false;
  return v.commands.every((c) =>
    isObj(c) && typeof c.name === "string" && /^[a-z0-9][a-z0-9-]*( [a-z0-9][a-z0-9-]*)*$/.test(c.name) &&
    typeof c.summary === "string" && Array.isArray(c.args) &&
    c.args.every((a) => isObj(a) && typeof a.name === "string" && /^[a-z0-9][a-z0-9-]*$/.test(a.name) && typeof a.kind === "string" && typeof a.type === "string"));
}

/** Why this CLI cannot run the command, or null when it can. */
export function unsupportedReason(cmd: ManifestCommand, clientKeys?: Iterable<string>): string | null {
  const known = clientKeys ? new Set(clientKeys) : undefined;
  for (const f of cmd.requires ?? []) if (!FEATURES.has(f)) return `it needs the feature "${f}"`;
  for (const a of cmd.args) {
    if (a.kind !== "flag" && a.kind !== "positional") return `argument ${a.name} has an unknown kind "${a.kind}"`;
    if (!ARG_TYPES.has(a.type)) return `argument ${a.name} has an unknown type "${a.type}"`;
  }
  const checkRequest = (r: ManifestRequest | undefined): string | null => {
    if (r === undefined) return null;
    if (r.method !== "GET" && r.method !== "POST") return `it uses the method ${String(r.method)}`;
    if (typeof r.path !== "string" || !r.path.startsWith("/")) return "it has no usable path";
    return null;
  };
  const checkKey = (key: string | undefined): string | null =>
    key !== undefined && known !== undefined && !known.has(key) ? `it uses built-in code "${key}" this version does not have` : null;
  const problems = [checkRequest(cmd.request), checkKey(cmd.client)];
  if (cmd.request === undefined && cmd.client === undefined) problems.push("it describes no request");
  for (const v of cmd.variants ?? []) problems.push(checkRequest(v.request), checkKey(v.client), v.request === undefined && v.client === undefined ? "a mode describes no request" : null);
  return problems.find((p) => p !== null) ?? null;
}

export function updateNeededMessage(reason: string): string {
  return `This command needs a newer emfirge: run ${UPDATE_COMMAND} (${reason}).`;
}

export function bundledManifestPath(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "bundled-manifest.json");
}

let bundled: Manifest | undefined;

/** The manifest shipped inside this package (src/cli and dist/cli both hold bundled-manifest.json). */
export function bundledManifest(): Manifest {
  if (bundled) return bundled;
  const parsed: unknown = JSON.parse(readFileSync(bundledManifestPath(), "utf-8"));
  if (!looksLikeManifest(parsed)) throw new Error("The bundled command list is damaged. Reinstall emfirge.");
  bundled = parsed;
  return parsed;
}

export const MANIFEST_TIMEOUT_MS = 3000;

/** The server's manifest, or null on any failure (offline, timeout, old server without the endpoint, bad body). */
export async function fetchManifest(timeoutMs = MANIFEST_TIMEOUT_MS): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${getBaseUrl()}/cli/manifest`, {
      headers: { Accept: "application/json", "X-Source": "cli" },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return (await res.json()) as unknown;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Server manifest if it can be read, else the bundled one. Never throws for network reasons. */
export async function loadManifest(fetcher: () => Promise<unknown | null> = fetchManifest): Promise<LoadedManifest> {
  const fromServer = await fetcher();
  if (looksLikeManifest(fromServer)) {
    if (fromServer.protocol > SUPPORTED_PROTOCOL) return { manifest: bundledManifest(), source: "bundled", tooNew: fromServer.protocol };
    return { manifest: fromServer, source: "server" };
  }
  return { manifest: bundledManifest(), source: "bundled" };
}
