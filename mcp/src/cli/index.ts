#!/usr/bin/env node
// emfirge CLI entry. The logic is in run.ts; this only wires argv and the exit code.
//
// The `emfirge` command is published as the npm package `emfirge` (folder cli/),
// a thin package that imports this file. The code lives here only.

import { runCli } from "./run.js";

process.exit(await runCli(process.argv.slice(2)));
