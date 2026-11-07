// Argument parsing for the emfirge CLI. Pure: no network, no auth, no fs.

import { VERBS, BRANCH_SUBS, type OptKind, type VerbSpec } from "./verbs.js";

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
}

/** Flags where more than one of these in one call is a mistake. */
const EXCLUSIVE_GROUPS: Record<string, string[]> = {
  context: ["refresh", "findings", "attack-paths", "compliance", "simulate"],
};

export function parseCommand(argv: string[]): Parsed {
  const [verb, ...rest] = argv;
  if (!verb) throw new UsageError("No command given.");
  const spec: VerbSpec | undefined = Object.hasOwn(VERBS, verb) ? VERBS[verb] : undefined;
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

  if (verb === "branch" && !help) {
    const sub = positionals.shift();
    if (!sub) throw new UsageError(`branch needs one of: ${BRANCH_SUBS.join(", ")}`, verb);
    if (!(BRANCH_SUBS as readonly string[]).includes(sub)) {
      throw new UsageError(`Unknown branch command: ${sub}. Use one of: ${BRANCH_SUBS.join(", ")}`, verb);
    }
    parsed.sub = sub;
  }

  const group = EXCLUSIVE_GROUPS[verb];
  if (group && !help) {
    const used = group.filter((n) => flags[n] !== undefined);
    if (used.length > 1) {
      throw new UsageError(`Use only one of: ${group.map((n) => `--${n}`).join(", ")}`, verb);
    }
  }
  return parsed;
}
