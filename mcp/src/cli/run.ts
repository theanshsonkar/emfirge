// The emfirge CLI. Thin by design: sign in, tokenize, send the command, print the answer.
// All logic lives on the hosted engine. The list of commands comes from the server (GET /cli/manifest, with a copy
// bundled in this package), so a command added on the server works here without a new release. Token expansion and
// redaction are the same code the MCP tools use. Only login, logout, connect, guide and the commands that need local
// code (overrides.ts) are built in.
//
// Exit codes: 0 ok, 1 usage error (also HTTP 400 and 422), 2 not signed in / forbidden, 3 not found,
// 4 server, network or rate limit (HTTP 429), 5 conflict (HTTP 409), 6 needs a newer emfirge.

import { readFileSync } from "node:fs";
import { ZodError } from "zod";
import { setInteractiveLogin } from "../client.js";
import { redactDeep } from "../tokenize.js";
import { parseCommand, UsageError, type Parsed } from "./args.js";
import { buildSpecs, bundledSpecs, LOCAL_VERBS, verbHelp, topUsage, type Specs } from "./verbs.js";
import { formatOk, formatError, type ErrorInfo } from "./output.js";
import { loadGuide } from "./guide.js";
import { loadManifest, updateNeededMessage, EXIT_UPDATE_NEEDED, SUPPORTED_PROTOCOL, type LoadedManifest } from "./manifest.js";
import { OVERRIDES, CLIENT_KEYS } from "./overrides.js";
import { runManifestCommand } from "./generic.js";
import { CliError, tool, on, type CliIo } from "./support.js";
import { startSpinner } from "./spinner.js";

export type { CliIo } from "./support.js";

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

// ---- built-in commands ----

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
  if (status === 400 || status === 422) return usageInfo(message);
  if (status === 409) return { code: "conflict", message, exit: 5 };
  if (status === 429) return { code: "rate_limited", message, exit: 4 };
  return { code: "server_error", message, exit: 4 };
}

const isLocal = (name: string | undefined): boolean => name !== undefined && Object.hasOwn(LOCAL_VERBS, name);

export async function runCli(argv: string[], partial: Partial<CliIo> = {}): Promise<number> {
  const io: CliIo = { ...defaultIo, ...partial };
  const human = argv.includes("--human");

  const fail = (info: ErrorInfo, usage?: string): number => {
    // Usage errors echo what the caller typed (a bad command, option or file name), so every
    // error message goes through the same redaction as tool output before it is printed.
    io.err(formatError({ ...info, message: String(redactDeep(info.message)) }, human));
    if (usage) io.err(usage);
    return info.exit;
  };

  const [first] = argv;
  if (first === "--version" || first === "-v") {
    const { version } = await import("./version.js");
    io.out(`${version()}\n`);
    return 0;
  }

  // The command list: from the server (short timeout), else the copy bundled in this package. The built-in
  // commands (login, logout, connect, guide, request) need no list, so they never wait for the network.
  const builtIn = isLocal(first) || (first === "help" && isLocal(argv[1]));
  let loaded: LoadedManifest | undefined;
  let specs: Specs = bundledSpecs();
  if (!builtIn) {
    loaded = await (io.loadManifest ?? loadManifest)();
    if (loaded.tooNew !== undefined) {
      return fail({
        code: "update_needed",
        message: updateNeededMessage(`the server's command list is protocol ${loaded.tooNew}; this emfirge reads up to ${SUPPORTED_PROTOCOL}`),
        exit: EXIT_UPDATE_NEEDED,
      });
    }
    specs = buildSpecs(loaded.manifest, CLIENT_KEYS);
  }
  const offlineNote = loaded?.source === "bundled"
    ? " (the server's command list could not be read, so this is the list built into this emfirge; a newer command may exist: " +
      "check your connection, or run npx emfirge@latest)"
    : "";

  if (first === undefined) return fail(usageInfo("No command given."), topUsage(specs));
  if (first === "--help" || first === "-h") { io.out(topUsage(specs)); return 0; }
  if (first === "help") {
    const topic = argv[1];
    if (topic === undefined) { io.out(topUsage(specs)); return 0; }
    if (!Object.hasOwn(specs, topic)) return fail(usageInfo(`Unknown command: ${topic}${offlineNote}`), topUsage(specs));
    const sub = argv.slice(2).filter((w) => !w.startsWith("-")).join(" ") || undefined;
    io.out(verbHelp(topic, specs, sub));
    return 0;
  }

  let parsed: Parsed;
  try {
    parsed = parseCommand(argv, specs);
  } catch (e) {
    if (e instanceof UsageError) {
      const unknown = e.message.startsWith("Unknown command:") ? offlineNote : "";
      return fail(usageInfo(e.message + unknown), e.verb ? verbHelp(e.verb, specs) : topUsage(specs));
    }
    return fail(classify(e));
  }
  if (parsed.help) { io.out(verbHelp(parsed.verb, specs, parsed.sub)); return 0; }

  setInteractiveLogin(false);
  try {
    let result: unknown;
    if (parsed.command && !isLocal(parsed.verb)) {
      const stop = (io.spinner ?? startSpinner)("Asking Emfirge");
      try {
        result = await runManifestCommand(parsed.command, parsed, io, OVERRIDES);
      } finally {
        stop();
      }
      io.out(formatOk(result, parsed.human, parsed.command.human));
      return 0;
    }
    switch (parsed.verb) {
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
    return fail(info, e instanceof UsageError && e.verb ? verbHelp(e.verb, specs, parsed.sub) : undefined);
  }
}
