// `emfirge guide` prints docs/AGENT-GUIDE.md.
// In the repo (src/cli or dist/cli) that file is three levels up in docs/.
// In the standalone `emfirge` bundle it sits next to emfirge.js (cli/scripts/build.mjs).
// In the @emfirge/mcp package, scripts/copy-guide.mjs copies it to dist/AGENT-GUIDE.md at build time.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export function loadGuide(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "AGENT-GUIDE.md"), // standalone bundle: next to emfirge.js
    join(here, "..", "AGENT-GUIDE.md"),
    join(here, "..", "..", "..", "docs", "AGENT-GUIDE.md"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return readFileSync(p, "utf-8");
  }
  throw new Error("Agent guide not found in this install. Read docs/AGENT-GUIDE.md in the Emfirge repo.");
}
