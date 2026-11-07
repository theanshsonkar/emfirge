#!/usr/bin/env node
// emfirge CLI entry. The logic is in run.ts; this only wires argv and the exit code.
//
// TODO(owner): the package/bin NAME is undecided. The bin entry `emfirge` in
// mcp/package.json points here. Renaming is a one-line change in the "bin" map
// (and the `emfirge ...` strings in verbs.ts / docs/AGENT-GUIDE.md if the command changes).

import { runCli } from "./run.js";

process.exit(await runCli(process.argv.slice(2)));
