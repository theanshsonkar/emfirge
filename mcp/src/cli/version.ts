import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Set by the standalone build (cli/scripts/build.mjs) to the `emfirge` package version. */
declare const __EMFIRGE_VERSION__: string | undefined;

/** The package version. In the standalone bundle it is fixed at build time; in mcp, src/cli and dist/cli sit two levels below package.json. */
export function version(): string {
  if (typeof __EMFIRGE_VERSION__ === "string") return __EMFIRGE_VERSION__;
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "..", "package.json"), "utf-8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}
