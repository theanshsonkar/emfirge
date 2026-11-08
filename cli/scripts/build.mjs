// Builds the standalone `emfirge` CLI: one ESM file, no runtime dependencies.
// The source is mcp/src/cli (and the mcp/src modules it uses); nothing is copied into cli/.
// The entry file carries the #!/usr/bin/env node line; esbuild keeps it.
// Needs mcp/node_modules installed (zod is inlined from there) and esbuild.
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const cliDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const mcpDir = join(cliDir, "..", "mcp");
const dist = join(cliDir, "dist");

async function loadEsbuild() {
  for (const base of [cliDir, mcpDir]) {
    try {
      return await import(pathToFileURL(createRequire(join(base, "package.json")).resolve("esbuild")).href);
    } catch {}
  }
  throw new Error("esbuild not found: run npm install in cli/ (or mcp/)");
}
const esbuild = await loadEsbuild();

const pkg = JSON.parse(readFileSync(join(cliDir, "package.json"), "utf-8"));
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

await esbuild.build({
  entryPoints: [join(mcpDir, "src", "cli", "index.ts")],
  outfile: join(dist, "emfirge.js"),
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  define: { __EMFIRGE_VERSION__: JSON.stringify(pkg.version) },
  legalComments: "none", // licenses are shipped in THIRD_PARTY_NOTICES.txt instead
  logLevel: "warning",
});
chmodSync(join(dist, "emfirge.js"), 0o755);

// Files the CLI reads at run time, next to the bundle.
const guide = join(cliDir, "..", "docs", "AGENT-GUIDE.md");
const manifest = join(mcpDir, "src", "cli", "bundled-manifest.json");
for (const f of [guide, manifest]) if (!existsSync(f)) throw new Error(`build: ${f} not found`);
copyFileSync(guide, join(dist, "AGENT-GUIDE.md"));
copyFileSync(manifest, join(dist, "bundled-manifest.json"));

// Licence text of the third-party code inlined in the bundle (zod, MIT).
const zodDir = join(mcpDir, "node_modules", "zod");
const zodPkg = JSON.parse(readFileSync(join(zodDir, "package.json"), "utf-8"));
const zodLicense = readFileSync(join(zodDir, "LICENSE"), "utf-8");
writeFileSync(
  join(dist, "THIRD_PARTY_NOTICES.txt"),
  `This package bundles the following third-party software.\n\nzod ${zodPkg.version} (MIT)\nhttps://github.com/colinhacks/zod\n\n${zodLicense}\n`,
);
console.log(`built ${pkg.name}@${pkg.version} -> ${join(dist, "emfirge.js")}`);
