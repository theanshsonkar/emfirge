import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const home = fs.mkdtempSync(path.join(os.tmpdir(), "emfirge-purge-"));
process.env.HOME = home;
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
delete process.env.EMFIRGE_API_KEY;

const { runInstaller } = await import("./installer.js");
const { tokenStorePath } = await import("./tokenize.js");

type Call = { url: string; headers: Record<string, string> };
let calls: Call[];
let errors: string[];
let exitCode: number | undefined;
let status = 200;

const realFetch = globalThis.fetch;
const realExit = process.exit;
const realErr = console.error;
const realLog = console.log;

class ExitSignal extends Error {}

function seedTokens() {
  fs.mkdirSync(path.dirname(tokenStorePath()), { recursive: true });
  fs.writeFileSync(tokenStorePath(), JSON.stringify({ x: 1 }));
}

async function purge(): Promise<void> {
  try {
    await runInstaller("purge", ["--role-arn", "arn:aws:iam::123456789012:role/r"]);
  } catch (e) {
    if (!(e instanceof ExitSignal)) throw e;
  }
}

beforeEach(() => {
  calls = [];
  errors = [];
  exitCode = undefined;
  status = 200;
  fs.rmSync(path.join(home, ".emfirge"), { recursive: true, force: true });
  delete process.env.EMFIRGE_API_KEY;
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), headers: { ...(init?.headers as Record<string, string>) } });
    return new Response(JSON.stringify({ aws_account_id: "123456789012", deleted: {} }), { status });
  }) as typeof fetch;
  process.exit = ((code?: number) => {
    exitCode = code;
    throw new ExitSignal();
  }) as typeof process.exit;
  console.error = (...a: unknown[]) => { errors.push(a.join(" ")); };
  console.log = () => {};
});

test.after(() => {
  globalThis.fetch = realFetch;
  process.exit = realExit;
  console.error = realErr;
  console.log = realLog;
});

test("L71i purge sends the Authorization header and clears local tokens after success", async () => {
  process.env.EMFIRGE_API_KEY = "key-123";
  seedTokens();
  await purge();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://stub.invalid/api/privacy/purge");
  assert.equal(calls[0].headers.Authorization, "Bearer key-123");
  assert.equal(fs.existsSync(tokenStorePath()), false);
});

test("L71i purge without credentials sends no request, says to sign in, exits non-zero, keeps tokens", async () => {
  seedTokens();
  await purge();
  assert.equal(calls.length, 0);
  assert.equal(exitCode, 1);
  assert.match(errors.join("\n"), /emfirge_login/);
  assert.equal(fs.existsSync(tokenStorePath()), true);
});

test("L71i purge keeps local tokens when the server refuses", async () => {
  process.env.EMFIRGE_API_KEY = "key-123";
  status = 401;
  seedTokens();
  await purge();
  assert.equal(exitCode, 1);
  assert.equal(fs.existsSync(tokenStorePath()), true);
});
