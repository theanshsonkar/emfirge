// Argument parsing for the emfirge CLI. Pure: no network, no auth, no fs.

import { bundledSpecs, type OptKind, type Specs, type VerbSpec } from "./verbs.js";
import type { ManifestCommand } from "./manifest.js";

export class UsageError extends Error {
  constructor(message: string, public readonly verb?: string) {
    super(message);
    this.name = "UsageError";
  }
}

export type FlagValue = string | boolean | string[];

export interface Parsed {
  verb: string;
  sub?: string;
  positionals: string[];
  flags: Record<string, FlagValue>;
  human: boolean;
  help: boolean;
  /** The manifest command this resolved to (absent for built-in verbs). */
  command?: ManifestCommand;
}

export function parseCommand(argv: string[], specs: Specs = bundledSpecs()): Parsed {
  const [verb, ...rest] = argv;
  if (!verb) throw new UsageError("No command given.");
  const spec: VerbSpec | undefined = Object.hasOwn(specs, verb) ? specs[verb] : undefined;
  if (!spec) throw new UsageError(`Unknown command: ${verb}`);

  const kinds = new Map<string, OptKind>(spec.options.map((o) => [o.name, o.kind]));
  kinds.set("human", "bool");
  kinds.set("help", "bool");

  const flags: Record<string, FlagValue> = {};
  const positionals: string[] = [];
  let human = false;
  let help = false;

  for (let i = 0; i < rest.length; i++) {
    const tok = rest[i];
    if (tok === "-h") { help = true; continue; }
    if (!tok.startsWith("--")) { positionals.push(tok); continue; }

    const eq = tok.indexOf("=");
    const name = eq === -1 ? tok.slice(2) : tok.slice(2, eq);
    const inline = eq === -1 ? undefined : tok.slice(eq + 1);
    const kind = kinds.get(name);
    if (!kind) throw new UsageError(`Unknown option for ${verb}: --${name}`, verb);

    if (kind === "bool") {
      if (inline !== undefined) throw new UsageError(`--${name} takes no value`, verb);
      if (name === "human") human = true;
      else if (name === "help") help = true;
      else flags[name] = true;
      continue;
    }

    let value = inline;
    if (value === undefined) {
      const next = rest[i + 1];
      // A value may be "-" (stdin) but not another option.
      if (next === undefined || (next.startsWith("--") && next.length > 2)) {
        throw new UsageError(`--${name} needs a value`, verb);
      }
      value = next;
      i++;
    }
    if (kind === "multi") {
      const list = (flags[name] as string[] | undefined) ?? [];
      list.push(value);
      flags[name] = list;
    } else {
      flags[name] = value;
    }
  }

  const parsed: Parsed = { verb, positionals, flags, human, help };

  if (spec.cmds) resolveCommand(parsed, spec, help);

  const cmd = parsed.command;
  if (cmd?.variants_exclusive && !help) {
    const group = (cmd.variants ?? []).map((v) => v.when);
    const used = group.filter((n) => flags[n] !== undefined);
    if (used.length > 1) {
      throw new UsageError(`Use only one of: ${group.map((n) => `--${n}`).join(", ")}`, verb);
    }
  }
  return parsed;
}

const subWords = (cmd: ManifestCommand): string[] => cmd.name.split(" ").slice(1);

/**
 * Pick the manifest command from the leading words: `branch open ...` is the command "branch open". The longest
 * match wins; a bare command (`check B`) is used when no sub-command word matches. In help mode nothing is an error.
 */
function resolveCommand(parsed: Parsed, spec: VerbSpec, help: boolean): void {
  const cmds = spec.cmds ?? [];
  const { verb, positionals } = parsed;
  let best: ManifestCommand | undefined;
  for (const c of cmds) {
    const words = subWords(c);
    if (words.length > positionals.length || !words.every((w, i) => positionals[i] === w)) continue;
    if (!best || words.length > subWords(best).length) best = c;
  }
  if (!best) {
    if (help) return;
    const subs = cmds.map((c) => subWords(c).join(" ")).filter(Boolean);
    const bare = cmds.find((c) => subWords(c).length === 0);
    if (bare) best = bare;
    else if (!positionals.length) throw new UsageError(`${verb} needs one of: ${subs.join(", ")}`, verb);
    else throw new UsageError(`Unknown ${verb} command: ${positionals[0]}. Use one of: ${subs.join(", ")}`, verb);
  }
  const words = subWords(best);
  positionals.splice(0, words.length);
  parsed.command = best;
  if (words.length) parsed.sub = words.join(" ");
}
