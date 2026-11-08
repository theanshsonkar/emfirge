// API keys: `emfirge key create` shows the new key; nothing else ever does, in the CLI or in MCP tool output.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const home = mkdtempSync(join(tmpdir(), "emfirge-api-key-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

const { runCli } = await import("./run.js");
const { bundledManifest, SUPPORTED_PROTOCOL } = await import("./manifest.js");
const { redactDeep, maskApiKeys, listTokens } = await import("../tokenize.js");

const KEY = "emf_" + randomBytes(32).toString("base64url");
const OTHER = "emf_" + randomBytes(32).toString("base64url");

function server(manifest: unknown, answer: unknown) {
  globalThis.fetch = (async (url: string | URL) => {
    const path = String(url).replace("http://stub.invalid/api", "");
    const body = path === "/cli/manifest" ? manifest : answer;
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

async function run(argv: string[]) {
  let stdout = "", stderr = "";
  const code = await runCli(argv, { out: (s) => { stdout += s; }, err: (s) => { stderr += s; }, readFile: () => "", readStdin: async () => "" });
  return { code, stdout, stderr };
}

const withCommands = (extra: unknown[]) => {
  const b = bundledManifest();
  return { ...b, protocol: SUPPORTED_PROTOCOL, commands: [...b.commands.filter((c) => !extra.some((e: any) => e.name === c.name)), ...extra] };
};

test("the bundled manifest: only `key create` reveals, and only the key field", () => {
  const withReveal = bundledManifest().commands.filter((c) => c.response?.reveal !== undefined);
  assert.deepEqual(withReveal.map((c) => [c.name, c.response!.reveal]), [["key create", ["key"]]]);
});

test("key create prints the real key (JSON and --human); the other fields are still redacted", async () => {
  const answer = { key: KEY, key_id: 4, prefix: KEY.slice(4, 12), created_at: "2026-01-01T00:00:00", warning: `Store ${OTHER} safely` };
  server(withCommands([]), answer);
  const r = await run(["key", "create", "--name", "ci"]);
  assert.equal(r.code, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.key, KEY);
  assert.equal(out.key_id, 4);
  assert.equal(out.warning.includes(OTHER), false, "an emf_ key outside the key field must stay masked");
  const h = await run(["key", "create", "--human"]);
  assert.ok(h.stdout.includes(KEY), h.stdout);
});

test("reveal works for the named top-level field only", async () => {
  const cmd = { name: "key create", summary: "x", args: [], request: { method: "POST", path: "/auth/api-keys" }, response: { reveal: ["key"] } };
  server(withCommands([cmd]), { key: KEY, nested: { key: OTHER }, list: [OTHER], other: OTHER, id: KEY });
  const out = JSON.parse((await run(["key", "create"])).stdout);
  assert.equal(out.key, KEY);
  for (const k of ["nested", "list", "other", "id"]) assert.equal(JSON.stringify(out[k]).includes(OTHER) || JSON.stringify(out[k]).includes(KEY), false, k);
});

test("reveal never shows a value that is not an API key", async () => {
  const cmd = { name: "key create", summary: "x", args: [], request: { method: "POST", path: "/auth/api-keys" }, response: { reveal: ["key", "resource"] } };
  server(withCommands([cmd]), { key: "sg-0abc123def4567890", resource: "sg-0abc123def4567890" });
  const r = await run(["key", "create"]);
  assert.equal(r.stdout.includes("sg-0abc123def4567890"), false);
});

test("a key in the answer of any other command is masked, even in a field called key", async () => {
  server(bundledManifest(), { keys: [{ key_id: 1, key: KEY, name: OTHER, note: `leaked ${KEY}.` }] });
  const r = await run(["key", "list"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stdout.includes(KEY) || r.stdout.includes(OTHER), false, r.stdout);
  assert.ok(r.stdout.includes("emf_REDACTED"), r.stdout);
  const other = withCommands([{ name: "audit notes", summary: "x", args: [], request: { method: "GET", path: "/a" }, response: { reveal: [] } }]);
  server(other, { key: KEY });
  assert.equal((await run(["audit", "notes"])).stdout.includes(KEY), false);
});

test("redactDeep (the MCP tool path) masks keys in every shape and every privacy mode", () => {
  const shapes: unknown[] = [KEY, { key: KEY }, { name: KEY }, { id: KEY }, [KEY], { a: { b: [`Authorization: Bearer ${KEY}`] } },
    `use ${KEY} now`, `EMFIRGE_API_KEY=${KEY}`, { label: KEY }, { tags: { owner: KEY } }, { message: `x"${KEY}"y` }];
  for (const s of shapes) assert.equal(JSON.stringify(redactDeep(s)).includes(KEY), false, JSON.stringify(s));
  assert.equal(maskApiKeys(`a ${KEY} b`), "a emf_REDACTED b");
  assert.equal(maskApiKeys("emf_ and emf_short and EMFIRGE_API_KEY"), "emf_ and emf_short and EMFIRGE_API_KEY");
  assert.equal(listTokens().some((t) => t.real.includes(KEY)), false, "a key must never reach the on-disk token store");
});

test("masking does not depend on the privacy mode (off included)", async () => {
  const { execFileSync } = await import("node:child_process");
  const code = `import("./src/tokenize.ts").then(t=>{const k=process.argv[1];const o=JSON.stringify(t.redactDeep({key:k,msg:"x "+k}));process.stdout.write(o.includes(k)?"LEAK":"ok")})`;
  for (const mode of ["off", "balanced", "strict"]) {
    const out = execFileSync(process.execPath, ["--import", "tsx", "-e", code, KEY], { cwd: join(import.meta.dirname, "..", ".."), env: { ...process.env, EMFIRGE_PRIVACY: mode, HOME: home }, encoding: "utf-8" });
    assert.equal(out, "ok", mode);
  }
});
