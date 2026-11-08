// The guide is part of the CLI, and its tool mapping must not drift from the registry.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const home = mkdtempSync(join(tmpdir(), "emfirge-cli-guide-"));
process.env.HOME = home;
process.env.USERPROFILE = home;

const here = dirname(fileURLToPath(import.meta.url));
const guidePath = join(here, "..", "..", "..", "docs", "AGENT-GUIDE.md");
const guide = readFileSync(guidePath, "utf-8");

const { tools } = await import("../tools-registry.js");
const { runCli } = await import("./run.js");
const { VERB_NAMES } = await import("./verbs.js");

test("every MCP tool in the registry appears in the guide mapping table", () => {
  const rows = guide.split("\n").filter((l) => l.trim().startsWith("|"));
  const missing: string[] = [];
  for (const t of tools) {
    const row = rows.find((l) => l.includes(`\`${t.name}\``));
    if (!row) { missing.push(t.name); continue; }
    assert.ok(
      VERB_NAMES.some((v) => new RegExp(`emfirge ${v}\\b`).test(row)),
      `${t.name} row has no emfirge command`,
    );
  }
  assert.deepEqual(missing, []);
});

test("the guide names no tool the registry does not have", () => {
  const known = new Set(tools.map((t) => t.name));
  const named = new Set(guide.match(/emfirge_[a-z_]+/g) ?? []);
  for (const n of named) assert.ok(known.has(n), `guide mentions unknown tool ${n}`);
});

test("the guide documents every verb, the exit codes, and stays short", () => {
  for (const v of ["context", "branch", "try", "check", "request", "report"]) {
    assert.match(guide, new RegExp(`emfirge ${v}`));
  }
  for (const code of ["0", "1", "2", "3", "4"]) assert.match(guide, new RegExp(`\\|\\s*${code}\\s*\\|`));
  assert.ok(guide.split("\n").length <= 150, "guide is over 150 lines");
});

test("emfirge guide prints the guide on stdout", async () => {
  let stdout = "";
  let stderr = "";
  const code = await runCli(["guide"], { out: (s) => { stdout += s; }, err: (s) => { stderr += s; } });
  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.equal(stdout.trim(), guide.trim());
});
