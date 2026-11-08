// The CLI is published as the npm package `emfirge` (folder cli/), built
// from the mcp/src/cli source into one file. It must not depend on @emfirge/mcp.
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

test("the CLI package has no dependency on @emfirge/mcp (it publishes alone)", () => {
  for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
    assert.ok(!(cliPkg[field] && "@emfirge/mcp" in cliPkg[field]), `${field} must not name @emfirge/mcp`);
  }
  assert.equal(cliPkg.version, mcpPkg.version);
});

test("the CLI package builds a single bundled file from the mcp source", () => {
  assert.equal(cliPkg.bin.emfirge, "./dist/emfirge.js");
  assert.ok(cliPkg.scripts.build, "build script exists");
  assert.equal(cliPkg.scripts.prepublishOnly, "npm run build");
  assert.ok(cliPkg.files.includes("dist"));
  assert.ok(existsSync(join(cliDir, "scripts", "build.mjs")));
  assert.ok(existsSync(join(mcpDir, "src", "cli", "index.ts")));
  assert.ok(!existsSync(join(cliDir, "index.js")));
});

test("@emfirge/mcp no longer installs an emfirge command of its own (no clash)", () => {
  assert.ok(!("emfirge" in mcpPkg.bin));
});
