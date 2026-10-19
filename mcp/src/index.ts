#!/usr/bin/env node
// MCP server entrypoint.
// Subcommands (install, uninstall, status, tokens, purge, privacy) delegate to installer.ts.
// Otherwise we run an MCP server on stdio for Claude Desktop / Cursor / Kiro / etc.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";

import { getBaseUrl } from "./client.js";
import { privacyMode } from "./tokenize.js";

// Read the published version from package.json so the value advertised over
// the MCP protocol can never drift from what npm shipped. dist/index.js and
// src/index.ts (dev via tsx) both sit one dir below package.json.
function readPackageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf-8")) as {
      version?: string;
    };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const VERSION = readPackageVersion();

const SUBCOMMANDS = new Set(["install", "uninstall", "status", "tokens", "purge", "privacy"]);
const subcommand = process.argv[2];

// --version / --help are handled here (not in installer) so `npx @emfirge/mcp
// --help` in a terminal prints usage instead of silently hanging on the stdio
// server waiting for an MCP client that will never connect.
if (subcommand === "--version" || subcommand === "-v" || subcommand === "version") {
  process.stdout.write(`${VERSION}\n`);
  process.exit(0);
}

if (subcommand === "--help" || subcommand === "-h" || subcommand === "help") {
  process.stdout.write(
    [
      `Emfirge MCP v${VERSION} — privacy-first AWS security inside your AI.`,
      "",
      "Usage:",
      "  npx @emfirge/mcp <command>",
      "",
      "Commands:",
      "  install [--privacy=<mode>]   Wire Emfirge into all detected MCP clients",
      "  uninstall                    Remove Emfirge from all clients",
      "  status                       Show wired clients, backend URL, privacy mode",
      "  privacy [<mode>]             Show or set privacy mode (strict|balanced|off)",
      "  tokens                       List local token mappings (never sent anywhere)",
      "  purge --role-arn <ARN>       Delete all your scan data (local + server)",
      "  --version, -v                Print version and exit",
      "  --help, -h                   Print this help and exit",
      "",
      "With no command, runs as an MCP stdio server for your AI client.",
      "Docs: https://github.com/theanshsonkar/emfirge/tree/main/mcp",
      "",
    ].join("\n"),
  );
  process.exit(0);
}

if (subcommand && SUBCOMMANDS.has(subcommand)) {
  const { runInstaller } = await import("./installer.js");
  await runInstaller(
    subcommand as "install" | "uninstall" | "status" | "tokens" | "purge" | "privacy",
    process.argv.slice(3),
  );
  process.exit(0);
}

// One-time stderr notice on first run (so we don't spook the protocol stream).
function maybeShowFirstRunNotice(): void {
  const flagDir = join(homedir(), ".emfirge");
  const flagFile = join(flagDir, "notice-shown");
  if (existsSync(flagFile)) return;

  process.stderr.write(
    [
      "",
      "Emfirge MCP - first run",
      `  backend:  ${getBaseUrl()}`,
      `  privacy:  ${privacyMode()}`,
      "  See PRIVACY.md or run: npx @emfirge/mcp purge --role-arn <ARN>",
      "",
    ].join("\n") + "\n",
  );

  try {
    if (!existsSync(flagDir)) mkdirSync(flagDir, { recursive: true });
    writeFileSync(flagFile, new Date().toISOString());
  } catch {
    // non-fatal, will show again next time
  }
}

maybeShowFirstRunNotice();

const server = new Server(
  { name: "emfirge", version: VERSION },
  { capabilities: { tools: {} } },
);

import { tools, zodToJsonSchema, dispatchTool } from "./tools-registry.js";

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: zodToJsonSchema(t.zodObject),
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) =>
  dispatchTool(req.params.name, req.params.arguments),
);

const transport = new StdioServerTransport();
await server.connect(transport);
