// Build step: ship the agent guide inside the package so `emfirge guide` works after npm install.
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "..", "docs", "AGENT-GUIDE.md");
if (!existsSync(src)) {
  console.error(`copy-guide: ${src} not found; skipping`);
  process.exit(0);
}
mkdirSync(join(root, "dist"), { recursive: true });
copyFileSync(src, join(root, "dist", "AGENT-GUIDE.md"));
