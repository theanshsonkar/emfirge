// The CLI is published as the npm package `emfirge` (folder cli/), a thin
// package over @emfirge/mcp. These checks keep the two in step.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mcpDir = join(here, "..", "..");
const cliDir = join(mcpDir, "..", "cli");
const mcpPkg = JSON.parse(readFileSync(join(mcpDir, "package.json"), "utf-8"));
const cliPkg = JSON.parse(readFileSync(join(cliDir, "package.json"), "utf-8"));

test("the CLI package is named emfirge and gives the emfirge command", () => {
  assert.equal(cliPkg.name, "emfirge");
  assert.deepEqual(Object.keys(cliPkg.bin), ["emfirge"]);
});

test("the CLI package pins @emfirge/mcp to the same version as itself and mcp", () => {
  assert.equal(cliPkg.dependencies["@emfirge/mcp"], mcpPkg.version);
  assert.equal(cliPkg.version, mcpPkg.version);
});

test("the CLI package imports the real CLI entry from @emfirge/mcp", () => {
  const entry = readFileSync(join(cliDir, cliPkg.bin.emfirge), "utf-8");
  assert.match(entry, /^#!\/usr\/bin\/env node/);
  assert.match(entry, /import "@emfirge\/mcp\/dist\/cli\/index\.js";/);
  assert.ok(existsSync(join(mcpDir, "src", "cli", "index.ts")));
  assert.ok(mcpPkg.files.includes("dist"));
});

test("@emfirge/mcp no longer installs an emfirge command of its own (no clash)", () => {
  assert.ok(!("emfirge" in mcpPkg.bin));
});
