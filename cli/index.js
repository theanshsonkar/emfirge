#!/usr/bin/env node
// The `emfirge` package is only a name. All CLI code lives in @emfirge/mcp
// (mcp/src/cli), so there is one source and one build. Keep the dependency in
// package.json pinned to the same version as mcp/package.json.
import "@emfirge/mcp/dist/cli/index.js";
