// The CLI runs commands from the server's manifest. fetch is stubbed; the manifest below is NOT in the CLI code.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-cli-manifest-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

const { runCli } = await import("./run.js");
const manifestMod = await import("./manifest.js");
const { bundledManifest, loadManifest, fetchManifest, looksLikeManifest, SUPPORTED_PROTOCOL } = manifestMod;
const { CLIENT_KEYS } = await import("./overrides.js");
const { buildSpecs } = await import("./verbs.js");

const SG = "sg-0abc123def4567890";
const BUCKET = "zz-planted-bucket-7731";
const ACCOUNT = "123456789012";

type Call = { method: string; path: string; headers: Record<string, string>; body?: any };

// A command that exists only on the "server": the CLI has no code for `audit show` or `audit notes`.
const NEW_COMMANDS = [
  {
    name: "audit show",
    summary: "Show audit entries for a resource.",
    examples: ["emfirge audit show RESOURCE --since 3"],
    args: [
      { name: "resource", kind: "positional", type: "string", required: true, id: true, help: "Resource id or token." },
      { name: "since", kind: "flag", type: "integer", min: 0, help: "Entries from the last N days." },
      { name: "filter", kind: "flag", type: "json", help: "Filter as JSON." },
      { name: "kind", kind: "flag", type: "string", multiple: true, choices: ["read", "write"], help: "Entry kinds (repeatable)." },
      { name: "verbose", kind: "flag", type: "bool", help: "Include details." },
    ],
    request: {
      method: "POST", path: "/audit/{resource}/entries", query: { since: "since", kind: "kind" },
      body: { filter: "filter", verbose: "verbose" }, null_unset: true,
    },
    human: { title: "Audit for {resource_label}", sections: ["entries"] },
  },
  {
    name: "audit notes",
    summary: "List audit notes.",
    args: [],
    request: { method: "GET", path: "/audit/notes" },
    response: { list_key: "notes" },
  },
];

function manifestWith(extra: unknown[], protocol = SUPPORTED_PROTOCOL) {
  const b = bundledManifest();
  return { ...b, protocol, groups: { ...b.groups, audit: "Read the audit trail." }, commands: [...b.commands, ...extra] };
}

type Handler = (call: Call) => { status?: number; body: unknown } | "network" | "hang";

function server(manifest: unknown | "down", api: Handler = () => ({ body: {} })): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    const call: Call = {
      method: init?.method ?? "GET",
      path: String(url).replace("http://stub.invalid/api", ""),
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(call);
    let r: ReturnType<Handler>;
    if (call.path === "/cli/manifest") {
      if (manifest === "down") throw new TypeError("fetch failed");
      r = { body: manifest };
    } else r = api(call);
    if (r === "network") throw new TypeError("fetch failed");
    if (r === "hang") {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      });
    }
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}

const apiCalls = (calls: Call[]): Call[] => calls.filter((c) => c.path !== "/cli/manifest");

async function run(argv: string[], files: Record<string, string> = {}) {
  let stdout = "";
  let stderr = "";
  const code = await runCli(argv, {
    out: (s) => { stdout += s; },
    err: (s) => { stderr += s; },
    readFile: (p) => { if (p in files) return files[p]; throw new Error(`ENOENT ${p}`); },
    readStdin: async () => "",
  });
  return { code, stdout, stderr };
}

// ---- the key test: a command only the server knows ----

test("a command that exists only in the server manifest works end to end", async () => {
  // 1. The agent sees a token, never the id.
  server(manifestWith(NEW_COMMANDS), () => ({ body: { question: "x", facts: [{ resource_id: SG }], known: [], unknown: [] } }));
  const seen = JSON.parse((await run(["context", "inventory"])).stdout).facts[0].resource_id as string;
  assert.match(seen, /^SG_\d{3}$/);

  // 2. Help shows the new command, built from the manifest.
  const top = await run(["--help"]);
  assert.equal(top.code, 0);
  assert.match(top.stdout, /audit\s+Read the audit trail\./);
  const help = await run(["audit", "show", "--help"]);
  assert.equal(help.code, 0, help.stderr);
  assert.match(help.stdout, /emfirge audit show - Show audit entries for a resource\./);
  assert.match(help.stdout, /emfirge audit show RESOURCE \[--since SINCE\] \[--filter FILTER\] \[--kind KIND\] \[--verbose\]/);
  assert.match(help.stdout, /--since VALUE\s+Entries from the last N days\./);
  assert.match(help.stdout, /--verbose\s+Include details\./);
  assert.match(help.stdout, /emfirge audit show RESOURCE --since 3/);
  assert.equal((await run(["help", "audit", "show"])).stdout, help.stdout);

  // 3-5. Args parse by the manifest, the token is expanded, the right request is made, the answer is redacted.
  const calls = server(manifestWith(NEW_COMMANDS), () => ({
    body: {
      resource_label: "r1",
      entries: [{ resource_id: SG, resource_type: "security_group" }, { resource_id: BUCKET, resource_type: "s3_bucket", account_id: ACCOUNT }],
      secret_note: "x",
    },
  }));
  const r = await run(["audit", "show", seen, "--since", "3", "--filter", '{"actor":"ci"}', "--kind", "read", "--kind=write", "--verbose"]);
  assert.equal(r.code, 0, r.stderr);
  const [call] = apiCalls(calls);
  assert.equal(call.method, "POST");
  assert.equal(call.path, `/audit/${SG}/entries?since=3&kind=read&kind=write`);
  assert.deepEqual(call.body, { filter: { actor: "ci" }, verbose: true });
  assert.equal(call.headers.Authorization, "Bearer synthetic-test-api-key");
  for (const secret of [SG, BUCKET, ACCOUNT]) assert.equal(r.stdout.includes(secret), false, `leaked ${secret}`);
  assert.match(JSON.parse(r.stdout).entries[0].resource_id, /^SG_\d{3}$/);

  // The generic --human layout from the manifest hint.
  const human = await run(["audit", "show", seen, "--human"]);
  assert.equal(human.code, 0, human.stderr);
  assert.match(human.stdout, /^Audit for r1\nentries:\n/);
  assert.equal(human.stdout.includes(SG), false);
  assert.equal(human.stdout.includes("secret_note"), false, "only the hinted sections are printed");
});

test("a new command: nulls for unset body fields, list wrapping, required and typed args", async () => {
  let calls = server(manifestWith(NEW_COMMANDS));
  let r = await run(["audit", "show", "r1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(apiCalls(calls)[0].path, "/audit/r1/entries");
  assert.deepEqual(apiCalls(calls)[0].body, { filter: null, verbose: null });

  calls = server(manifestWith(NEW_COMMANDS), () => ({ body: [{ id: 1 }] }));
  r = await run(["audit", "notes"]);
  assert.deepEqual(JSON.parse(r.stdout), { notes: [{ id: 1 }], count: 1 });
  assert.equal(apiCalls(calls)[0].method, "GET");
  assert.equal(apiCalls(calls)[0].body, undefined);

  for (const argv of [
    ["audit", "show"],                                   // missing positional
    ["audit", "show", "r1", "--since", "x"],             // not a whole number
    ["audit", "show", "r1", "--since", "-1"],            // below min
    ["audit", "show", "r1", "--filter", "{bad"],         // not JSON
    ["audit", "show", "r1", "--kind", "delete"],         // not a choice
    ["audit", "show", "r1", "r2"],                       // extra argument
    ["audit", "show", "r1", "--nope"],                   // unknown option
    ["audit", "notes", "--since", "1"],                  // option of another command
    ["audit"],                                           // group needs a sub-command
    ["audit", "explode"],
  ]) {
    calls = server(manifestWith(NEW_COMMANDS));
    r = await run(argv);
    assert.equal(r.code, 1, argv.join(" "));
    assert.equal(r.stdout, "");
    assert.equal(apiCalls(calls).length, 0, `no request for ${argv.join(" ")}`);
  }
});

test("a new command's json arg can come from a file, and errors use the usual exit codes", async () => {
  const calls = server(manifestWith(NEW_COMMANDS));
  const r = await run(["audit", "show", "r1", "--filter", "f.json"], { "f.json": '{"a":1}' });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(apiCalls(calls)[0].body.filter, { a: 1 });

  for (const [status, code] of [[401, 2], [404, 3], [409, 5], [429, 4], [500, 4]] as const) {
    server(manifestWith(NEW_COMMANDS), () => ({ status, body: { detail: "x" } }));
    assert.equal((await run(["audit", "notes"])).code, code, String(status));
  }
});

// ---- fallback to the bundled manifest ----

test("server down: the bundled manifest still runs the existing commands", async () => {
  const calls = server("down", () => ({ body: { id: "b1" } }));
  const r = await run(["branch", "get", "b1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(apiCalls(calls)[0].path, "/branches/b1");
  const help = await run(["--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /branch/);
  assert.doesNotMatch(help.stdout, /audit/);
});

test("old server without the endpoint (404) or a broken body falls back to the bundled manifest", async () => {
  for (const manifest of [null, "not a manifest", { protocol: "1", commands: [] }, { protocol: 1, commands: [{ name: 5 }] }]) {
    const calls = server(manifest, () => ({ body: { id: "b1" } }));
    const r = await run(["branch", "get", "b1"]);
    assert.equal(r.code, 0, JSON.stringify(manifest) + r.stderr);
    assert.equal(apiCalls(calls).length, 1);
  }
  globalThis.fetch = (async () => new Response("{}", { status: 404 })) as typeof fetch;
  const loaded = await loadManifest();
  assert.equal(loaded.source, "bundled");
});

test("a command unknown to the bundled list says why, and points at the connection and the update", async () => {
  server("down");
  const r = await run(["audit", "notes"]);
  assert.equal(r.code, 1);
  const err = JSON.parse(r.stderr.split("\n")[0]).error;
  assert.match(err.message, /Unknown command: audit/);
  assert.match(err.message, /could not be read/);
  assert.match(err.message, /npx emfirge@latest/);
  server(manifestWith(NEW_COMMANDS));
  const online = await run(["frobnicate"]);
  assert.doesNotMatch(online.stderr, /could not be read/);
});

test("a hanging server does not hang the CLI: the manifest fetch times out", async () => {
  server(null, () => ({ body: {} }));
  globalThis.fetch = (async (_url: string | URL, init?: RequestInit) =>
    new Promise((_res, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))))) as typeof fetch;
  const started = Date.now();
  assert.equal(await fetchManifest(60), null);
  assert.ok(Date.now() - started < 2000);
  assert.equal((await loadManifest(() => fetchManifest(60))).source, "bundled");
});

test("built-in commands never wait for the command list", async () => {
  const calls = server(manifestWith(NEW_COMMANDS));
  const guide = await run(["guide"]);
  assert.equal(guide.code, 0);
  const help = await run(["login", "--help"]);
  assert.equal(help.code, 0);
  assert.equal((await run(["--version"])).code, 0);
  assert.equal((await run(["request", "b1"])).code, 1);
  assert.equal(calls.length, 0);
});

// ---- newer than this CLI ----

test("a manifest protocol newer than the CLI reads: clear message, exit 6, no request", async () => {
  for (const argv of [["branch", "get", "b1"], ["--help"], ["check", "b1"]]) {
    const calls = server(manifestWith(NEW_COMMANDS, SUPPORTED_PROTOCOL + 1));
    const r = await run(argv);
    assert.equal(r.code, 6, argv.join(" "));
    assert.equal(r.stdout, "");
    const err = JSON.parse(r.stderr.split("\n")[0]).error;
    assert.equal(err.code, "update_needed");
    assert.equal(err.exit, 6);
    assert.match(err.message, /needs a newer emfirge: run npx emfirge@latest/);
    assert.equal(apiCalls(calls).length, 0);
  }
  const human = await run(["branch", "list", "--human"]);
  assert.match(human.stderr, /^Error: .*npx emfirge@latest/);
  // Built-in commands still work with a server this CLI cannot read.
  server(manifestWith([], SUPPORTED_PROTOCOL + 1));
  assert.equal((await run(["guide"])).code, 0);
});

test("a command that needs something this CLI lacks: exit 6 for that command only", async () => {
  const future = [
    { name: "future feature", summary: "Needs a feature.", args: [], requires: ["streaming-v2"], request: { method: "GET", path: "/f" } },
    { name: "future type", summary: "Unknown arg type.", args: [{ name: "x", kind: "flag", type: "datetime", help: "x" }], request: { method: "GET", path: "/f" } },
    { name: "future method", summary: "Unknown method.", args: [], request: { method: "DELETE", path: "/f" } },
    { name: "future builtin", summary: "Unknown built-in code.", args: [], client: "does.not.exist" },
    { name: "future mode", summary: "A mode with unknown code.", args: [{ name: "go", kind: "flag", type: "bool", help: "go" }], request: { method: "GET", path: "/f" }, variants: [{ when: "go", client: "nope" }] },
  ];
  for (const argv of [["future", "feature"], ["future", "type"], ["future", "method"], ["future", "builtin"], ["future", "mode"]]) {
    const calls = server(manifestWith(future));
    const r = await run(argv);
    assert.equal(r.code, 6, argv.join(" "));
    assert.match(JSON.parse(r.stderr.split("\n")[0]).error.message, /needs a newer emfirge: run npx emfirge@latest/);
    assert.equal(apiCalls(calls).length, 0);
  }
  // Its help still works and says so; the other commands are untouched.
  server(manifestWith(future));
  const help = await run(["future", "feature", "--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /needs a newer emfirge: run npx emfirge@latest/);
  const calls = server(manifestWith(future), () => ({ body: { id: "b1" } }));
  assert.equal((await run(["branch", "get", "b1"])).code, 0);
  assert.equal(apiCalls(calls).length, 1);
});

// ---- the bundled copy ----

test("the bundled manifest is valid, readable by this CLI, and uses only built-in code this CLI has", () => {
  const b = bundledManifest();
  assert.ok(looksLikeManifest(b));
  assert.ok(b.protocol <= SUPPORTED_PROTOCOL);
  const specs = buildSpecs(b, CLIENT_KEYS);
  for (const spec of Object.values(specs)) assert.deepEqual(spec.unsupported ?? {}, {});
  const used = new Set<string>();
  for (const c of b.commands) {
    if (c.client) used.add(c.client);
    for (const v of c.variants ?? []) if (v.client) used.add(v.client);
  }
  assert.deepEqual([...used].sort(), [...CLIENT_KEYS].sort(), "every built-in handler is used, and every named one exists");
});

test("the existing verbs are all in the bundled manifest", () => {
  const names = bundledManifest().commands.map((c) => c.name);
  for (const n of ["context", "try", "check", "report", "branch open", "branch fork", "branch list", "branch get",
    "branch rollback", "branch rollback-to", "branch discard", "branch compare"]) assert.ok(names.includes(n), n);
});

test("the agent guide documents exit 6 and the update rule", async () => {
  const { readFileSync } = await import("node:fs");
  const guide = readFileSync(new URL("../../../docs/AGENT-GUIDE.md", import.meta.url), "utf-8");
  assert.match(guide, /^\| 6 \|[^\n]*needs a newer emfirge[^\n]*npx emfirge@latest/m);
  assert.match(guide, /Commands come from the server/);
  assert.ok(guide.split("\n").length <= 150);
});
