// CLI for `npx @emfirge/mcp <subcommand>`.
// Detects MCP-compatible clients on the machine and patches their config.

import { homedir, platform } from "node:os";
import { join, dirname } from "node:path";
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  unlinkSync,
} from "node:fs";

import { clearTokenStore, listTokens, tokenStorePath } from "./tokenize.js";

export type Subcommand = "install" | "uninstall" | "status" | "tokens" | "purge" | "privacy";

interface ClientConfig {
  name: string;
  paths: { darwin: string; linux: string; win32: string };
}

// JSON-config clients — all use the same { mcpServers: { ... } } shape, so a
// single patcher handles them. Paths verified against each tool's official
// docs as of 2026-06.
const CLIENTS: ClientConfig[] = [
  {
    name: "Claude Desktop",
    paths: {
      darwin: "Library/Application Support/Claude/claude_desktop_config.json",
      linux: ".config/Claude/claude_desktop_config.json",
      win32: "AppData/Roaming/Claude/claude_desktop_config.json",
    },
  },
  {
    // Claude Code (CLI). User-scope MCP servers live at the top-level
    // `mcpServers` key in ~/.claude.json. Same shape as Claude Desktop.
    // Ref: https://docs.claude.com/en/docs/claude-code/mcp#user-scope
    name: "Claude Code",
    paths: {
      darwin: ".claude.json",
      linux: ".claude.json",
      win32: ".claude.json",
    },
  },
  {
    name: "Cursor",
    paths: {
      darwin: ".cursor/mcp.json",
      linux: ".cursor/mcp.json",
      win32: ".cursor/mcp.json",
    },
  },
  {
    // Kiro (CLI + IDE share the same path).
    // Ref: https://kiro.dev/docs/mcp/configuration#configuration-locations
    name: "Kiro",
    paths: {
      darwin: ".kiro/settings/mcp.json",
      linux: ".kiro/settings/mcp.json",
      win32: ".kiro/settings/mcp.json",
    },
  },
  {
    name: "Cline",
    paths: {
      darwin: "Library/Application Support/Cline/cline_mcp_settings.json",
      linux: ".config/Cline/cline_mcp_settings.json",
      win32: "AppData/Roaming/Cline/cline_mcp_settings.json",
    },
  },
  {
    name: "Continue",
    paths: {
      darwin: ".continue/config.json",
      linux: ".continue/config.json",
      win32: ".continue/config.json",
    },
  },
];

// Privacy mode is hoisted here because both install (via buildEmfirgeEntry)
// and the Codex TOML helper need it, and we validate it from CLI args too.
type PrivacyMode = "strict" | "balanced" | "off";
const VALID_PRIVACY_MODES = new Set<PrivacyMode>(["strict", "balanced", "off"]);

function buildEmfirgeEntry(privacy: PrivacyMode) {
  return {
    command: "npx",
    args: ["-y", "@emfirge/mcp"],
    env: {
      EMFIRGE_PRIVACY: privacy,
    },
  };
}

// ---------------------------------------------------------------------------
// Codex CLI (TOML config) - separate code path because every other client is
// JSON. Ref: https://developers.openai.com/codex/mcp/
// We avoid pulling in a TOML parser (would 3x the package size) and instead
// do line-based block manipulation on the [mcp_servers.emfirge] section.
// ---------------------------------------------------------------------------
const CODEX_NAME = "Codex CLI";
const CODEX_RELATIVE_PATH = ".codex/config.toml";

function codexConfigPath(): string {
  return join(homedir(), CODEX_RELATIVE_PATH);
}

function buildCodexBlock(privacy: PrivacyMode = "strict"): string {
  return [
    "[mcp_servers.emfirge]",
    'command = "npx"',
    'args = ["-y", "@emfirge/mcp"]',
    "",
    "[mcp_servers.emfirge.env]",
    `EMFIRGE_PRIVACY = "${privacy}"`,
  ].join("\n");
}

// Find the contiguous range of lines that belong to our server in config.toml.
// Includes [mcp_servers.emfirge] and any [mcp_servers.emfirge.foo] children
// that follow it. Returns null if the server isn't installed.
function findCodexEmfirgeRange(
  lines: string[],
): { start: number; end: number } | null {
  let start = -1;
  let end = -1;
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    const isEmfirgeSection = trimmed.startsWith("[mcp_servers.emfirge");
    if (isEmfirgeSection) {
      if (start === -1) start = i;
      end = i;
    } else if (start !== -1) {
      if (trimmed.startsWith("[")) break; // hit a different section
      end = i; // body line of current emfirge section
    }
  }
  if (start === -1) return null;
  while (end > start && lines[end].trim() === "") end--;
  return { start, end };
}

type CodexPatchInput = "install" | "uninstall";

function patchCodexConfig(action: CodexPatchInput, privacy: PrivacyMode = "strict"): PatchResult {
  const path = codexConfigPath();
  let content = "";
  if (existsSync(path)) {
    try {
      content = readFileSync(path, "utf-8");
    } catch {
      return "error";
    }
  }

  const lines = content.length > 0 ? content.split(/\r?\n/) : [];
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();

  const range = findCodexEmfirgeRange(lines);

  if (action === "install") {
    if (range !== null) return "noop";
    const block = buildCodexBlock(privacy);
    if (lines.length > 0) {
      lines.push("", ...block.split("\n"));
    } else {
      lines.push(...block.split("\n"));
    }
  } else {
    if (range === null) return "noop";
    // Trim a leading blank line if present so we don't accumulate blanks
    // across install/uninstall cycles.
    const removeStart =
      range.start > 0 && lines[range.start - 1].trim() === ""
        ? range.start - 1
        : range.start;
    lines.splice(removeStart, range.end - removeStart + 1);
  }

  try {
    if (!existsSync(dirname(path))) mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, lines.join("\n") + "\n");
    return "patched";
  } catch {
    return "error";
  }
}

interface CodexState {
  parentDirExists: boolean;
  configExists: boolean;
  hasEmfirge: boolean;
  privacy?: string;
  path: string;
}

function detectCodex(): CodexState {
  const path = codexConfigPath();
  const parentDirExists = existsSync(dirname(path));
  if (!existsSync(path)) {
    return { parentDirExists, configExists: false, hasEmfirge: false, path };
  }
  let content: string;
  try {
    content = readFileSync(path, "utf-8");
  } catch {
    return { parentDirExists, configExists: true, hasEmfirge: false, path };
  }
  const lines = content.split(/\r?\n/);
  const range = findCodexEmfirgeRange(lines);
  if (!range) {
    return { parentDirExists, configExists: true, hasEmfirge: false, path };
  }

  let privacy: string | undefined;
  for (let i = range.start; i <= range.end; i++) {
    const m = lines[i].match(/^\s*EMFIRGE_PRIVACY\s*=\s*"([^"]*)"/);
    if (m) {
      privacy = m[1];
      break;
    }
  }
  return { parentDirExists, configExists: true, hasEmfirge: true, privacy, path };
}

function setCodexPrivacy(mode: PrivacyMode): {
  result: PatchResult;
  before?: string;
} {
  const path = codexConfigPath();
  if (!existsSync(path)) return { result: "noop" };
  let content: string;
  try {
    content = readFileSync(path, "utf-8");
  } catch {
    return { result: "error" };
  }
  const lines = content.split(/\r?\n/);
  const range = findCodexEmfirgeRange(lines);
  if (!range) return { result: "noop" };

  let before: string | undefined;
  let updated = false;
  for (let i = range.start; i <= range.end; i++) {
    const m = lines[i].match(/^\s*EMFIRGE_PRIVACY\s*=\s*"([^"]*)"/);
    if (m) {
      before = m[1];
      if (before === mode) return { result: "noop", before };
      lines[i] = `EMFIRGE_PRIVACY = "${mode}"`;
      updated = true;
      break;
    }
  }

  if (!updated) {
    // No env section yet — append [mcp_servers.emfirge.env]
    lines.splice(
      range.end + 1,
      0,
      "",
      "[mcp_servers.emfirge.env]",
      `EMFIRGE_PRIVACY = "${mode}"`,
    );
  }

  try {
    writeFileSync(path, lines.join("\n"));
    return { result: "patched", before: before ?? "strict" };
  } catch {
    return { result: "error" };
  }
}

function resolveClientPath(client: ClientConfig): string {
  const plat = platform();
  const rel =
    plat === "darwin"
      ? client.paths.darwin
      : plat === "win32"
        ? client.paths.win32
        : client.paths.linux;
  return join(homedir(), rel);
}

interface DetectedClient {
  name: string;
  path: string;
  configExists: boolean;
  hasEmfirge: boolean;
}

function detectClients(): DetectedClient[] {
  return CLIENTS.map((c) => {
    const path = resolveClientPath(c);
    const configExists = existsSync(path);
    let hasEmfirge = false;

    if (configExists) {
      try {
        const cfg = JSON.parse(readFileSync(path, "utf-8"));
        hasEmfirge = Boolean(cfg?.mcpServers?.emfirge);
      } catch {
        // malformed - treat as not installed
      }
    }

    return { name: c.name, path, configExists, hasEmfirge };
  }).filter((c) => c.configExists || existsSync(dirname(c.path)));
}

type PatchResult = "patched" | "noop" | "error";

function patchConfig(
  path: string,
  action: "install" | "uninstall",
  privacy: PrivacyMode = "strict",
): PatchResult {
  let cfg: Record<string, any> = {};

  if (existsSync(path)) {
    try {
      cfg = JSON.parse(readFileSync(path, "utf-8"));
      if (typeof cfg !== "object" || cfg === null) cfg = {};
    } catch {
      return "error";
    }
  }

  cfg.mcpServers = cfg.mcpServers ?? {};

  if (action === "install") {
    if (cfg.mcpServers.emfirge) return "noop";
    cfg.mcpServers.emfirge = buildEmfirgeEntry(privacy);
  } else {
    if (!cfg.mcpServers.emfirge) return "noop";
    delete cfg.mcpServers.emfirge;
  }

  try {
    if (!existsSync(dirname(path))) mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(cfg, null, 2));
    return "patched";
  } catch {
    return "error";
  }
}

// Prompt the user once at install time. Skips silently when:
//   - stdin isn't a TTY (CI scripts, piped install)
//   - --privacy=<mode> was passed
//   - emfirge is already wired into at least one client (returning user)
// Defaults to strict in all skip cases.
async function promptForPrivacy(): Promise<PrivacyMode> {
  if (!process.stdin.isTTY) return "strict";

  console.log("");
  console.log("Privacy mode controls what your host LLM (Claude / GPT / Gemini) actually sees:");
  console.log("  strict    Tokenize every AWS ID before sending to the LLM (SG_001 instead of");
  console.log("            sg-0a1b2c3d). Mapping stays local at ~/.emfirge/tokens.json. Recommended.");
  console.log("  balanced  Tokenize ARNs, IAM names, IPs, and account IDs only. Generic IDs");
  console.log("            (subnet, VPC, volume) stay raw.");
  console.log("  off       Send everything raw. Best LLM output, least private.");
  console.log("");
  console.log("You can change this any time with: npx @emfirge/mcp privacy <mode>");
  console.log("");

  const readline = await import("node:readline/promises");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  let answer: string;
  try {
    answer = await rl.question("Mode? [strict]: ");
  } finally {
    rl.close();
  }

  const choice = (answer ?? "").trim().toLowerCase();
  if (choice === "" || choice === "strict") return "strict";
  if (choice === "balanced") return "balanced";
  if (choice === "off") return "off";

  console.log(`Unknown mode "${choice}". Using strict.`);
  return "strict";
}

// Parses --privacy=<mode> from CLI args. Returns null if absent or invalid.
function parsePrivacyFlag(args: string[]): PrivacyMode | null {
  const flag = args.find((a) => a.startsWith("--privacy="));
  if (!flag) return null;
  const v = flag.slice("--privacy=".length).toLowerCase();
  return VALID_PRIVACY_MODES.has(v as PrivacyMode) ? (v as PrivacyMode) : null;
}

async function runInstallOrUninstall(
  action: "install" | "uninstall",
  args: string[],
): Promise<void> {
  const detected = detectClients();
  const codex = detectCodex();
  const codexPresent = codex.parentDirExists || codex.configExists;

  if (detected.length === 0 && !codexPresent) {
    console.log("No MCP-compatible clients detected.\n");
    console.log("Install one of these first:");
    console.log("  Claude Desktop  https://claude.ai/download");
    console.log("  Claude Code     https://docs.claude.com/en/docs/claude-code");
    console.log("  Cursor          https://cursor.com");
    console.log("  Kiro            https://kiro.dev");
    console.log("  Codex CLI       https://developers.openai.com/codex");
    console.log("  Cline           VS Code extension");
    console.log("  Continue        VS Code / JetBrains extension");
    return;
  }

  // Privacy mode resolution for install:
  //   1. --privacy=<mode> CLI flag wins outright (great for CI / scripts)
  //   2. Otherwise, prompt only if no existing emfirge install (first-time user)
  //   3. Otherwise default strict (re-running install on a wired machine)
  let privacy: PrivacyMode = "strict";
  if (action === "install") {
    const flag = parsePrivacyFlag(args);
    const anyExisting =
      detected.some((c) => c.hasEmfirge) || codex.hasEmfirge;
    if (flag !== null) {
      privacy = flag;
    } else if (!anyExisting) {
      privacy = await promptForPrivacy();
    }
  }

  console.log(`${action === "install" ? "Wiring" : "Removing"} Emfirge MCP...\n`);
  const results: Array<{ name: string; status: PatchResult }> = [];

  for (const client of detected) {
    const status = patchConfig(client.path, action, privacy);
    results.push({ name: client.name, status });
  }

  if (codexPresent) {
    const status = patchCodexConfig(action, privacy);
    results.push({ name: CODEX_NAME, status });
  }

  for (const r of results) {
    const icon =
      r.status === "patched" ? "+" : r.status === "noop" ? "." : "!";
    const word =
      r.status === "patched"
        ? action === "install"
          ? "added"
          : "removed"
        : r.status === "noop"
          ? action === "install"
            ? "already installed"
            : "not installed"
          : "error (malformed config)";
    console.log(`  ${icon} ${r.name.padEnd(18)} ${word}`);
  }

  const anyPatched = results.some((r) => r.status === "patched");

  if (anyPatched) {
    console.log("\nDone. Restart your MCP client(s).\n");
    if (action === "install") {
      console.log("Then ask your assistant:");
      console.log('  "Scan my AWS account, role <YOUR_ROLE_ARN>, region us-east-1"\n');
      console.log("If you don't have a role yet, ask:");
      console.log('  "Help me set up Emfirge"\n');
      console.log(`Privacy mode: ${privacy}  (change with: npx @emfirge/mcp privacy <mode>)`);
      console.log("Limit: 15 scans/day per AWS account.");
    }
  } else {
    console.log(
      action === "install"
        ? "\nNothing changed - all clients already have Emfirge wired up."
        : "\nNothing changed - Emfirge wasn't installed in any client.",
    );
  }
}

function runStatus(): void {
  const detected = detectClients();
  const codex = detectCodex();
  const codexPresent = codex.parentDirExists || codex.configExists;

  if (detected.length === 0 && !codexPresent) {
    console.log("No MCP-compatible clients detected on this machine.");
    return;
  }

  console.log("Detected MCP clients:\n");
  for (const c of detected) {
    const icon = c.hasEmfirge ? "+" : ".";
    const status = c.hasEmfirge ? "wired" : "not wired";
    console.log(`  ${icon} ${c.name.padEnd(18)} ${status.padEnd(12)} ${c.path}`);
  }
  if (codexPresent) {
    const icon = codex.hasEmfirge ? "+" : ".";
    const status = codex.hasEmfirge ? "wired" : "not wired";
    console.log(`  ${icon} ${CODEX_NAME.padEnd(18)} ${status.padEnd(12)} ${codex.path}`);
  }

  console.log(`\nBackend: ${process.env.EMFIRGE_BASE_URL ?? "https://emfirge.cloud/api"}`);
  console.log(`Privacy: ${process.env.EMFIRGE_PRIVACY ?? "strict"}  (change with: npx @emfirge/mcp privacy <strict|balanced|off>)`);
  console.log(`Tokens:  ${tokenStorePath()}`);
}

function runTokens(): void {
  const tokens = listTokens();

  if (tokens.length === 0) {
    console.log("No tokens stored yet. Run a scan first.");
    console.log(`(File: ${tokenStorePath()})`);
    return;
  }

  console.log("Token mappings (local-only, never sent anywhere):\n");
  const longest = Math.max(...tokens.map((t) => t.token.length));
  for (const { token, real } of tokens) {
    console.log(`  ${token.padEnd(longest)}  ->  ${real}`);
  }
  console.log(`\nFile: ${tokenStorePath()}`);
  console.log(`Wipe these and your server-side data: npx @emfirge/mcp purge --role-arn <ARN>`);
}

interface PurgeResponse {
  status?: string;
  aws_account_id?: string;
  deleted?: Record<string, number>;
}

async function runPurge(args: string[]): Promise<void> {
  const roleArnIdx = args.findIndex((a) => a === "--role-arn");
  if (roleArnIdx === -1 || !args[roleArnIdx + 1]) {
    console.log("Usage: npx @emfirge/mcp purge --role-arn <ARN> [--region us-east-1]\n");
    console.log("This will:");
    console.log("  1. Re-assume your role to verify you control the AWS account");
    console.log("  2. Delete all your scan data, findings, drift events, and S3 snapshots");
    console.log("  3. Wipe your local ~/.emfirge/tokens.json mapping");
    process.exit(1);
  }

  const roleArn = args[roleArnIdx + 1];
  const regionIdx = args.findIndex((a) => a === "--region");
  const region = regionIdx >= 0 && args[regionIdx + 1] ? args[regionIdx + 1] : "us-east-1";

  const baseUrl = process.env.EMFIRGE_BASE_URL ?? "https://emfirge.cloud/api";

  console.log(`Purging Emfirge data for ${roleArn}...`);
  console.log(`Backend: ${baseUrl}\n`);

  let res: Response;
  try {
    res = await fetch(`${baseUrl}/privacy/purge`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Source": "mcp-cli",
      },
      body: JSON.stringify({ role_arn: roleArn, region }),
    });
  } catch (e) {
    console.error(`Network error: ${e instanceof Error ? e.message : String(e)}`);
    console.error("Local token store NOT cleared - re-run when the backend is reachable.");
    process.exit(1);
  }

  if (!res.ok) {
    const text = await res.text();
    console.error(`Purge failed (HTTP ${res.status}):`);
    console.error(text.slice(0, 500));
    console.error("\nLocal token store NOT cleared.");
    process.exit(1);
  }

  const result = (await res.json()) as PurgeResponse;

  console.log(`Server-side data deleted for AWS account ${result.aws_account_id ?? "(unknown)"}:\n`);
  if (result.deleted) {
    const longest = Math.max(...Object.keys(result.deleted).map((k) => k.length));
    for (const [table, count] of Object.entries(result.deleted)) {
      console.log(`  ${table.padEnd(longest)}  ${count} record${count === 1 ? "" : "s"}`);
    }
  }

  try {
    clearTokenStore();
    const tokFile = tokenStorePath();
    if (existsSync(tokFile)) {
      unlinkSync(tokFile);
    }
    console.log(`\nLocal token mappings cleared (~/.emfirge/tokens.json).`);
  } catch (e) {
    console.error(
      `\nWarning: could not clear local token file: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  console.log("\nAll Emfirge data has been deleted.");
}

function runPrivacy(args: string[]): void {
  const mode = args[0]?.toLowerCase();

  // No arg - show current per-client state and usage
  if (!mode) {
    const detected = detectClients();
    const codex = detectCodex();
    const codexPresent = codex.parentDirExists || codex.configExists;

    if (detected.length === 0 && !codexPresent) {
      console.log("No MCP-compatible clients detected on this machine.");
      console.log("\nUsage: npx @emfirge/mcp privacy <strict|balanced|off>");
      return;
    }

    console.log("Current privacy mode per client:\n");
    for (const c of detected) {
      let current = "(not wired)";
      if (c.hasEmfirge) {
        try {
          const cfg = JSON.parse(readFileSync(c.path, "utf-8"));
          current = cfg?.mcpServers?.emfirge?.env?.EMFIRGE_PRIVACY ?? "strict";
        } catch {
          current = "(unreadable)";
        }
      }
      console.log(`  ${c.name.padEnd(18)} ${current}`);
    }
    if (codexPresent) {
      const current = codex.hasEmfirge ? (codex.privacy ?? "strict") : "(not wired)";
      console.log(`  ${CODEX_NAME.padEnd(18)} ${current}`);
    }
    console.log("\nUsage: npx @emfirge/mcp privacy <strict|balanced|off>");
    console.log("Modes:");
    console.log("  strict    hide all AWS IDs from the host LLM (default)");
    console.log("  balanced  hide IAM, secrets, KMS, account IDs, IPs only");
    console.log("  off       send real AWS IDs to the host LLM (not recommended)");
    return;
  }

  if (!VALID_PRIVACY_MODES.has(mode as PrivacyMode)) {
    console.error(`Invalid mode: ${mode}`);
    console.error("Must be one of: strict, balanced, off");
    process.exit(1);
  }

  const detected = detectClients();
  const codex = detectCodex();
  const wired = detected.filter((c) => c.hasEmfirge);
  const codexWired = codex.hasEmfirge;

  if (wired.length === 0 && !codexWired) {
    console.log("Emfirge is not wired into any MCP client yet.");
    console.log("Run `npx @emfirge/mcp install` first.");
    return;
  }

  const total = wired.length + (codexWired ? 1 : 0);
  console.log(`Setting EMFIRGE_PRIVACY=${mode} on ${total} client(s):\n`);

  let patched = 0;
  for (const c of wired) {
    try {
      const cfg = JSON.parse(readFileSync(c.path, "utf-8"));
      const entry = cfg?.mcpServers?.emfirge;
      if (!entry) {
        console.log(`  -  ${c.name.padEnd(18)} (not wired)`);
        continue;
      }
      entry.env = entry.env ?? {};
      const before = entry.env.EMFIRGE_PRIVACY;
      if (before === mode) {
        console.log(`  =  ${c.name.padEnd(18)} already ${mode}`);
        continue;
      }
      entry.env.EMFIRGE_PRIVACY = mode;
      writeFileSync(c.path, JSON.stringify(cfg, null, 2));
      console.log(`  +  ${c.name.padEnd(18)} ${before ?? "strict"} -> ${mode}`);
      patched++;
    } catch (e) {
      console.log(`  x  ${c.name.padEnd(18)} error: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  if (codexWired) {
    const { result, before } = setCodexPrivacy(mode as PrivacyMode);
    if (result === "noop") {
      console.log(`  =  ${CODEX_NAME.padEnd(18)} already ${mode}`);
    } else if (result === "patched") {
      console.log(`  +  ${CODEX_NAME.padEnd(18)} ${before ?? "strict"} -> ${mode}`);
      patched++;
    } else {
      console.log(`  x  ${CODEX_NAME.padEnd(18)} error writing ${codex.path}`);
    }
  }

  if (patched > 0) {
    console.log("\nDone. Restart your MCP client(s) for the change to take effect.");
  }
}

export async function runInstaller(cmd: Subcommand, args: string[]): Promise<void> {
  switch (cmd) {
    case "install":
      await runInstallOrUninstall("install", args);
      return;
    case "uninstall":
      await runInstallOrUninstall("uninstall", args);
      return;
    case "status":
      runStatus();
      return;
    case "tokens":
      runTokens();
      return;
    case "purge":
      await runPurge(args);
      return;
    case "privacy":
      runPrivacy(args);
      return;
    default: {
      const exhaustive: never = cmd;
      throw new Error(`Unknown subcommand: ${exhaustive}`);
    }
  }
}
