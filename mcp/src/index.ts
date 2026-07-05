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
import { z } from "zod";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";

import { getBaseUrl } from "./client.js";
import { privacyMode } from "./tokenize.js";

import { setupSchema, setupZodObject, setupHandler } from "./tools/setup.js";
import { scanSchema, scanZodObject, scanHandler } from "./tools/scan.js";
import { findingsSchema, findingsZodObject, findingsHandler } from "./tools/findings.js";
import {
  attackPathsSchema,
  attackPathsZodObject,
  attackPathsHandler,
} from "./tools/attack-paths.js";
import {
  verifyFixSchema,
  verifyFixZodObject,
  verifyFixHandler,
} from "./tools/verify-fix.js";
import {
  complianceSchema,
  complianceZodObject,
  complianceHandler,
} from "./tools/compliance.js";
import { simulateSchema, simulateZodObject, simulateHandler } from "./tools/simulate.js";

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

interface ToolRegistration {
  name: string;
  description: string;
  schema: Record<string, z.ZodTypeAny>;
  zodObject: z.ZodObject<z.ZodRawShape>;
  handler: (args: any) => Promise<{ content: Array<{ type: "text"; text: string }> }>;
}

const tools: ToolRegistration[] = [
  {
    name: "emfirge_setup_help",
    description:
      "Returns the AWS CloudFormation deploy URL for setting up the read-only IAM role. " +
      "Call this when the user does not have a role ARN yet, or if emfirge_scan returns 403. " +
      "CRITICAL: After calling this tool, paste the deploy URL verbatim in your reply to the user. " +
      "Many MCP clients (Claude Code, Codex CLI, Kiro CLI) hide tool output by default, so saying " +
      "'click the link above' will leave the user with nothing to click.",
    schema: setupSchema as Record<string, z.ZodTypeAny>,
    zodObject: setupZodObject as z.ZodObject<z.ZodRawShape>,
    handler: setupHandler,
  },
  {
    name: "emfirge_scan",
    description:
      "Scan an AWS account for security risks. Returns risk score (0-100), finding counts, " +
      "and an analysis_id for the other tools. Resource IDs are tokenized by default.",
    schema: scanSchema as Record<string, z.ZodTypeAny>,
    zodObject: scanZodObject as z.ZodObject<z.ZodRawShape>,
    handler: scanHandler,
  },
  {
    name: "emfirge_get_findings",
    description:
      "Get the full findings list for a previous scan, optionally filtered by severity " +
      "(Critical/Moderate/Low). Each finding has rule_id, issue, recommendation, attack_path, blast_radius, MITRE mapping.",
    schema: findingsSchema as Record<string, z.ZodTypeAny>,
    zodObject: findingsZodObject as z.ZodObject<z.ZodRawShape>,
    handler: findingsHandler,
  },
  {
    name: "emfirge_attack_paths",
    description:
      "Get attack paths from the internet to internal resources. Shows pivot routes from " +
      "public-facing resources to crown jewels. Also returns chokepoint and orphaned resources.",
    schema: attackPathsSchema as Record<string, z.ZodTypeAny>,
    zodObject: attackPathsZodObject as z.ZodObject<z.ZodRawShape>,
    handler: attackPathsHandler,
  },
  {
    name: "emfirge_verify_fix",
    description:
      "Simulate fixing a finding without applying changes. Clones the infra, applies the rule's " +
      "mutation, rebuilds the graph, re-runs all rules, returns score delta + which other findings get resolved.",
    schema: verifyFixSchema as Record<string, z.ZodTypeAny>,
    zodObject: verifyFixZodObject as z.ZodObject<z.ZodRawShape>,
    handler: verifyFixHandler,
  },
  {
    name: "emfirge_check_compliance",
    description:
      "Get CIS AWS Foundations 1.5 or SOC 2 compliance status. Returns per-control pass/fail with the findings that triggered each failure.",
    schema: complianceSchema as Record<string, z.ZodTypeAny>,
    zodObject: complianceZodObject as z.ZodObject<z.ZodRawShape>,
    handler: complianceHandler,
  },
  {
    name: "emfirge_simulate_breach",
    description:
      "Walk a full kill chain end-to-end against the infrastructure graph. Given a " +
      "natural-language scenario or 'what if' query, returns verdict + severity + every " +
      "stage of the attack (entry → pivot → impact) + blast radius + follow-up moves. " +
      "Read-only — no AWS changes.",
    schema: simulateSchema as Record<string, z.ZodTypeAny>,
    zodObject: simulateZodObject as z.ZodObject<z.ZodRawShape>,
    handler: simulateHandler,
  },
];

// zod -> JSON Schema (just the types we use)
function zodFieldToJsonSchema(field: z.ZodTypeAny): Record<string, unknown> {
  let inner = field;
  while (
    inner instanceof z.ZodOptional ||
    inner instanceof z.ZodDefault ||
    inner instanceof z.ZodNullable
  ) {
    inner = (inner as any)._def.innerType;
  }

  const base: Record<string, unknown> = {};
  if (field.description) base.description = field.description;

  if (inner instanceof z.ZodString) {
    base.type = "string";
  } else if (inner instanceof z.ZodNumber) {
    base.type = "number";
  } else if (inner instanceof z.ZodBoolean) {
    base.type = "boolean";
  } else if (inner instanceof z.ZodEnum) {
    base.type = "string";
    base.enum = (inner as any)._def.values;
  } else {
    base.type = "string";
  }

  return base;
}

function zodToJsonSchema(zodObject: z.ZodObject<z.ZodRawShape>): Record<string, unknown> {
  const shape = zodObject.shape;
  const properties: Record<string, unknown> = {};
  const required: string[] = [];

  for (const [key, field] of Object.entries(shape)) {
    properties[key] = zodFieldToJsonSchema(field as z.ZodTypeAny);
    if (!(field as z.ZodTypeAny).isOptional()) {
      required.push(key);
    }
  }

  const out: Record<string, unknown> = { type: "object", properties };
  if (required.length > 0) out.required = required;
  return out;
}

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: zodToJsonSchema(t.zodObject),
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const tool = tools.find((t) => t.name === req.params.name);
  if (!tool) {
    throw new Error(`Unknown tool: ${req.params.name}`);
  }

  try {
    const args = tool.zodObject.parse(req.params.arguments ?? {});
    return await tool.handler(args);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return {
      content: [{ type: "text" as const, text: `Error: ${message}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
