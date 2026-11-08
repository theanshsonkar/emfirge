// The verbs, their options and their --help text.
//
// Almost everything comes from the command manifest (see manifest.ts). Only the commands that need local files,
// secrets or a browser are described here: login, logout, connect, guide, and `request` (not built yet).

import {
  bundledManifest, unsupportedReason, UPDATE_COMMAND,
  type Manifest, type ManifestArg, type ManifestCommand,
} from "./manifest.js";

export type OptKind = "string" | "bool" | "multi";
export interface Opt { name: string; kind: OptKind; help: string }
export interface VerbSpec {
  summary: string;
  usage: string[];
  options: Opt[];
  examples: string[];
  /** The manifest commands under this verb (the first word of their name). Absent for built-in verbs. */
  cmds?: ManifestCommand[];
  /** Why this CLI cannot run a manifest command, by command name. */
  unsupported?: Record<string, string>;
}
export type Specs = Record<string, VerbSpec>;

const s = (name: string, help: string): Opt => ({ name, kind: "string", help });
const b = (name: string, help: string): Opt => ({ name, kind: "bool", help });

/** Commands that stay in the CLI because they need local files, secrets or a browser. */
export const LOCAL_VERBS: Specs = {
  request: {
    summary: "Ask the owner for approval. NOT BUILT YET (v2): exits 1 with a JSON error.",
    usage: ["emfirge request BRANCH [--reason TEXT]"],
    options: [s("reason", "Why you are asking.")],
    examples: ["emfirge request BRANCH_ID --reason \"needs prod approval\""],
  },
  connect: {
    summary: "Set up the read-only AWS role: prints the deploy link. --link joins an API-key project to your sign-in.",
    usage: ["emfirge connect", "emfirge connect --link"],
    options: [b("link", "Link your saved sign-in to an existing API-key project (needs EMFIRGE_API_KEY).")],
    examples: ["emfirge connect"],
  },
  login: {
    summary: "Sign in with GitHub or Google in your browser.",
    usage: ["emfirge login"],
    options: [],
    examples: ["emfirge login"],
  },
  logout: {
    summary: "Sign out on this device.",
    usage: ["emfirge logout"],
    options: [],
    examples: ["emfirge logout"],
  },
  guide: {
    summary: "Print the agent guide: the loop, the rules, the tool map and exit codes.",
    usage: ["emfirge guide"],
    options: [],
    examples: ["emfirge guide"],
  },
};

const optKind = (a: ManifestArg): OptKind => (a.type === "bool" ? "bool" : a.multiple ? "multi" : "string");

const placeholder = (a: ManifestArg): string => a.name.toUpperCase().replace(/-/g, "_");

/** The usage line for a command that does not carry its own. */
function generatedUsage(cmd: ManifestCommand): string {
  const parts = ["emfirge", cmd.name];
  for (const a of cmd.args.filter((x) => x.kind === "positional")) {
    const word = a.multiple ? `${placeholder(a)} [${placeholder(a)} ...]` : placeholder(a);
    parts.push(a.required ? word : `[${word}]`);
  }
  for (const a of cmd.args.filter((x) => x.kind === "flag")) {
    const word = a.type === "bool" ? `--${a.name}` : `--${a.name} ${placeholder(a)}`;
    parts.push(a.required ? word : `[${word}]`);
  }
  return parts.join(" ");
}

const subWords = (cmd: ManifestCommand): string[] => cmd.name.split(" ").slice(1);

function optionsOf(cmds: ManifestCommand[]): Opt[] {
  const seen = new Map<string, Opt>();
  for (const cmd of cmds) {
    for (const a of cmd.args) {
      if (a.kind === "flag" && !seen.has(a.name)) seen.set(a.name, { name: a.name, kind: optKind(a), help: a.help });
    }
  }
  return [...seen.values()];
}

/** The positional arguments of these commands, once each, for an "Arguments:" block. */
function argumentLines(cmds: ManifestCommand[]): string[] {
  const seen = new Map<string, string>();
  for (const cmd of cmds) {
    for (const a of cmd.args) {
      if (a.kind === "positional" && !seen.has(a.name)) seen.set(a.name, `  ${placeholder(a).padEnd(24)} ${a.help}`);
    }
  }
  return seen.size ? ["", "Arguments:", ...seen.values()] : [];
}

/** Specs for every verb: the manifest's commands grouped by first word, then the built-in verbs on top. */
export function buildSpecs(manifest: Manifest, clientKeys?: Iterable<string>): Specs {
  const groups = new Map<string, ManifestCommand[]>();
  for (const cmd of manifest.commands) {
    const verb = cmd.name.split(" ")[0];
    groups.set(verb, [...(groups.get(verb) ?? []), cmd]);
  }
  const specs: Specs = {};
  for (const [verb, cmds] of groups) {
    const unsupported: Record<string, string> = {};
    for (const c of cmds) {
      const why = unsupportedReason(c, clientKeys);
      if (why) unsupported[c.name] = why;
    }
    const subs = cmds.flatMap((c) => (subWords(c).length ? [subWords(c).join(" ")] : []));
    const only = cmds[0];
    const summary = manifest.groups?.[verb] ?? (cmds.length === 1 ? only.summary : `${only.summary.replace(/\.$/, "")} (and: ${subs.join(", ")}).`);
    specs[verb] = {
      summary,
      usage: cmds.flatMap((c) => (c.usage?.length ? c.usage : [generatedUsage(c)])),
      options: optionsOf(cmds),
      examples: cmds.flatMap((c) => c.examples ?? []),
      cmds,
      unsupported,
    };
  }
  // Built-in verbs win over a manifest command of the same name: they need local files, secrets or a browser.
  for (const [verb, spec] of Object.entries(LOCAL_VERBS)) specs[verb] = spec;
  return specs;
}

let defaultSpecs: Specs | undefined;

/** Specs from the bundled manifest: used for built-in help and as the default of the pure helpers. */
export function bundledSpecs(): Specs {
  return (defaultSpecs ??= buildSpecs(bundledManifest()));
}

export const VERB_NAMES: string[] = Object.keys(bundledSpecs());

const EXIT_LINE =
  "Output is JSON on stdout. Errors are JSON on stderr. Exit: 0 ok, 1 usage, 2 not signed in, 3 not found, 4 server, 5 conflict, " +
  `6 needs a newer emfirge (${UPDATE_COMMAND}).`;

function optionLines(options: Opt[]): string[] {
  const opts = [...options, { name: "human", kind: "bool" as OptKind, help: "Short readable output instead of JSON." }];
  const lines = ["", "Options:"];
  for (const o of opts) lines.push(`  --${(o.name + (o.kind === "bool" ? "" : " VALUE")).padEnd(22)} ${o.help}`);
  lines.push("  -h, --help".padEnd(25) + " Show this help.");
  return lines;
}

/** Help for a verb, or for one command of it when `sub` is given (`emfirge branch open --help`). */
export function verbHelp(verb: string, specs: Specs = bundledSpecs(), sub?: string): string {
  const v = specs[verb];
  const cmd = sub ? v.cmds?.find((c) => subWords(c).join(" ") === sub) : undefined;
  if (cmd) {
    const why = v.unsupported?.[cmd.name];
    const lines = [`emfirge ${cmd.name} - ${cmd.summary}`, "", "Usage:", ...(cmd.usage?.length ? cmd.usage : [generatedUsage(cmd)]).map((u) => `  ${u}`)];
    lines.push(...argumentLines([cmd]), ...optionLines(optionsOf([cmd])));
    if (cmd.examples?.length) lines.push("", "Examples:", ...cmd.examples.map((e) => `  ${e}`));
    if (why) lines.push("", `This command needs a newer emfirge: run ${UPDATE_COMMAND} (${why}).`);
    lines.push("", EXIT_LINE);
    return lines.join("\n") + "\n";
  }
  const lines = [`emfirge ${verb} - ${v.summary}`, "", "Usage:", ...v.usage.map((u) => `  ${u}`)];
  lines.push(...argumentLines(v.cmds ?? []), ...optionLines(v.options));
  if (v.cmds && v.cmds.some((c) => subWords(c).length)) {
    lines.push("", "Commands:");
    for (const c of v.cmds) lines.push(`  ${(subWords(c).join(" ") || "(none)").padEnd(14)} ${c.summary}`);
  }
  if (v.examples.length) lines.push("", "Examples:", ...v.examples.map((e) => `  ${e}`));
  const blocked = Object.entries(v.unsupported ?? {});
  if (blocked.length) {
    lines.push("", `Needs a newer emfirge (run ${UPDATE_COMMAND}): ${blocked.map(([name]) => name).join(", ")}.`);
  }
  lines.push("", EXIT_LINE);
  return lines.join("\n") + "\n";
}

export function topUsage(specs: Specs = bundledSpecs()): string {
  const lines = [
    "Usage: emfirge <command> [options]",
    "",
    "Emfirge tells you what is true about the cloud. It never changes it, and it gives facts, not fixes.",
    "",
    "Commands:",
  ];
  for (const [name, spec] of Object.entries(specs)) lines.push(`  ${name.padEnd(9)} ${spec.summary}`);
  lines.push(
    "",
    "Run `emfirge <command> --help` for options, or `emfirge guide` for the full agent guide.",
    "Global: --human (readable output), --version.",
    `Exit codes: 0 ok, 1 usage or rejected input, 2 not signed in, 3 not found, 4 server or rate limit, 5 conflict, 6 needs a newer emfirge (${UPDATE_COMMAND}).`,
  );
  return lines.join("\n") + "\n";
}
