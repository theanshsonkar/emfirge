// Build step: ship the agent guide inside the package so `emfirge guide` works after npm install.
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "..", "docs", "AGENT-GUIDE.md");
if (existsSync(src)) {
  mkdirSync(join(root, "dist"), { recursive: true });
  copyFileSync(src, join(root, "dist", "AGENT-GUIDE.md"));
} else {
  console.error(`copy-guide: ${src} not found; skipping`);
}

// Also ship the bundled command list (the fallback when the server cannot be reached).
// tsc does not copy JSON that is read at run time, so it is copied here, next to dist/cli/manifest.js.
const manifestSrc = join(root, "src", "cli", "bundled-manifest.json");
if (!existsSync(manifestSrc)) {
  console.error(`copy-guide: ${manifestSrc} not found; the CLI would have no offline command list`);
  process.exit(1);
}
mkdirSync(join(root, "dist", "cli"), { recursive: true });
copyFileSync(manifestSrc, join(root, "dist", "cli", "bundled-manifest.json"));
