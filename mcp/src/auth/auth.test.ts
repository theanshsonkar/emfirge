import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import nodeTest, { after, afterEach, before, beforeEach } from "node:test";
import { assertPublicKey, browserSignInApplies } from "./config.js";
import { credentialsPath } from "./credentials.js";
import { _resetForTests as _resetLoginForTests, startLogin } from "./login.js";
import { _resetForTests, getAccessToken } from "./session.js";
import { authHeader } from "../client.js";
import { loginHandler, logoutHandler } from "../tools/login.js";


const test = (name: string, fn: () => void | Promise<void>) => nodeTest(name, { concurrency: false }, fn);
type RequestRecord = {
  path: string;
  query: Record<string, string>;
  headers: http.IncomingHttpHeaders;
  body: string;
};

let supabase: http.Server;
let supabaseBase: string;
let requests: RequestRecord[];
let rejectRefresh = false;
let home: string;
let oldEnv: NodeJS.ProcessEnv;

function credentialsFile(): string {
  return path.join(home, ".emfirge", "credentials.json");
}

function startFakeSupabase(): Promise<void> {
  supabase = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", supabaseBase || "http://127.0.0.1");
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const record: RequestRecord = {
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
        headers: req.headers,
        body: Buffer.concat(chunks).toString(),
      };
      requests.push(record);
      if (req.method === "POST" && url.pathname === "/auth/v1/token") {
        if (url.searchParams.get("grant_type") === "pkce") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            access_token: "ACCESS-SECRET-1",
            refresh_token: "REFRESH-SECRET-1",
            expires_in: 3600,
          }));
          return;
        }
        if (url.searchParams.get("grant_type") === "refresh_token") {
          if (rejectRefresh) {
            res.writeHead(400);
            res.end("rejected");
            return;
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            access_token: "ACCESS-SECRET-2",
            refresh_token: "REFRESH-SECRET-2",
            expires_in: 3600,
          }));
          return;
        }
      }
      if (req.method === "POST" && url.pathname === "/auth/v1/logout") {
        res.writeHead(204);
        res.end();
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  return new Promise((resolve) => {
    supabase.listen(0, "127.0.0.1", () => {
      const address = supabase.address() as { port: number };
      supabaseBase = `http://127.0.0.1:${address.port}`;
      resolve();
    });
  });
}

function loopbackHost(url: string): string {
  return new URL(url).host;
}

function requestWithHost(url: string, host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const request = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: "GET",
      headers: { Host: host },
    }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode ?? 0));
    });
    request.on("error", reject);
    request.end();
  });
}

async function requestLoginStart(provider = "github"): Promise<{ pending: Awaited<ReturnType<typeof startLogin>>; location: URL; host: string }> {
  const pending = await startLogin();
  const host = loopbackHost(pending.url);
  const response = await fetch(`${pending.url}start/${provider}`, {
    redirect: "manual",
    headers: { Host: host },
  });
  assert.equal(response.status, 302);
  const location = new URL(response.headers.get("location") ?? "");
  return { pending, location, host };
}

async function completeLogin(): Promise<{ pending: Awaited<ReturnType<typeof startLogin>>; response: Response }> {
  const { pending, location, host } = await requestLoginStart();
  const redirect = new URL(location.searchParams.get("redirect_to") ?? "");
  const response = await fetch(`${redirect}?code=AUTHCODE-SECRET`, {
    redirect: "manual",
    headers: { Host: host },
  });
  await pending.pending;
  return { pending, response };
}

before(async () => {
  await startFakeSupabase();
});

beforeEach(() => {
  oldEnv = { ...process.env };
  requests = [];
  rejectRefresh = false;
  home = fs.mkdtempSync(path.join(os.tmpdir(), "emfirge-auth-"));
  process.env.EMFIRGE_SUPABASE_URL = supabaseBase;
  process.env.EMFIRGE_SUPABASE_ANON_KEY = "test-anon";
  process.env.EMFIRGE_NO_BROWSER = "1";
  process.env.HOME = home;
  delete process.env.EMFIRGE_API_KEY;
  delete process.env.EMFIRGE_BASE_URL;
  _resetForTests();
});

afterEach(() => {
  _resetForTests();
  _resetLoginForTests();
  process.env = oldEnv;
});

after(async () => {
  await new Promise<void>((resolve, reject) => supabase.close((error) => error ? reject(error) : resolve()));
});

test("auth public keys reject service credentials", () => {
  assert.throws(() => assertPublicKey("sb_secret_x"), /Sign-in is misconfigured/);
  const payload = Buffer.from(JSON.stringify({ role: "service_role" })).toString("base64url");
  assert.throws(() => assertPublicKey(`e30.${payload}.sig`), /Sign-in is misconfigured/);
});

test("wrong state rejects without exchanging token, then correct state succeeds", async () => {
  const { pending, location, host } = await requestLoginStart();
  const redirect = new URL(location.searchParams.get("redirect_to") ?? "");
  const wrong = await fetch(`${redirect.origin}/callback/wrong?code=AUTHCODE-SECRET`, { headers: { Host: host } });
  assert.equal(wrong.status, 400);
  assert.equal(requests.filter((request) => request.path === "/auth/v1/token").length, 0);
  assert.equal(fs.existsSync(credentialsFile()), false);
  const correct = await fetch(`${redirect}?code=AUTHCODE-SECRET`, { headers: { Host: host } });
  assert.equal(correct.status, 200);
  assert.equal(await pending.pending, true);
});

test("correct state saves only refresh credentials with restricted permissions and closes server", async () => {
  const { pending, response } = await completeLogin();
  assert.equal(response.status, 200);
  const body = await response.text();
  assert.equal(body.includes("ACCESS-SECRET-1"), false);
  const fileStat = fs.statSync(credentialsFile());
  const dirStat = fs.statSync(path.dirname(credentialsFile()));
  assert.equal(fileStat.mode & 0o777, 0o600);
  assert.equal(dirStat.mode & 0o777, 0o700);
  const saved = fs.readFileSync(credentialsFile(), "utf8");
  assert.equal(saved.includes("REFRESH-SECRET-1"), true);
  assert.equal(saved.includes("ACCESS-SECRET-1"), false);
  assert.equal(await pending.pending, true);
  await assert.rejects(fetch(`${pending.url}`, { headers: { Host: loopbackHost(pending.url) } }));
});

test("PKCE start includes S256 challenge and exchanges matching verifier", async () => {
  const { pending, location, host } = await requestLoginStart();
  assert.equal(location.searchParams.get("provider"), "github");
  assert.equal(location.searchParams.get("code_challenge_method"), "s256");
  const redirect = new URL(location.searchParams.get("redirect_to") ?? "");
  assert.match(redirect.href, new RegExp(`^http://127\\.0\\.0\\.1:${new URL(pending.url).port}/callback/`));
  await fetch(`${redirect}?code=AUTHCODE-SECRET`, { headers: { Host: host } });
  const tokenRequest = requests.find((request) => request.path === "/auth/v1/token");
  assert.ok(tokenRequest);
  const exchange = JSON.parse(tokenRequest.body) as { code_verifier: string };
  const challenge = createHash("sha256").update(exchange.code_verifier).digest("base64url");
  assert.equal(location.searchParams.get("code_challenge"), challenge);
});

test("wrong Host header is rejected", async () => {
  const pending = await startLogin({ timeoutMs: 200 });
  assert.equal(await requestWithHost(pending.url, "evil.example"), 400);
  assert.equal(await pending.pending, false);
});

test("refresh works and rotates the stored refresh token", async () => {
  await completeLogin();
  _resetForTests();
  assert.equal(await getAccessToken(), "ACCESS-SECRET-2");
  const saved = fs.readFileSync(credentialsFile(), "utf8");
  assert.equal(saved.includes("REFRESH-SECRET-2"), true);
  assert.equal(saved.includes("REFRESH-SECRET-1"), false);
  assert.equal(fs.statSync(credentialsFile()).mode & 0o777, 0o600);
  const refreshRequest = requests.find((request) => request.query.grant_type === "refresh_token");
  assert.equal(refreshRequest?.headers.apikey, "test-anon");
});

test("rejected refresh removes credentials and returns null", async () => {
  await completeLogin();
  rejectRefresh = true;
  _resetForTests();
  assert.equal(await getAccessToken(), null);
  assert.equal(fs.existsSync(credentialsFile()), false);
});

test("API key wins and login tool reports that it is in use", async () => {
  process.env.EMFIRGE_API_KEY = "key-123";
  assert.equal(await authHeader(), "Bearer key-123");
  const result = await loginHandler({});
  assert.match(result.content[0].text, /EMFIRGE_API_KEY is set/);
  assert.equal(requests.length, 0);
});

test("self-hosted backend preserves origin no-key behavior and does not start login", async () => {
  process.env.EMFIRGE_BASE_URL = "http://localhost:8000";
  delete process.env.EMFIRGE_SUPABASE_URL;
  assert.equal(browserSignInApplies(), false);
  assert.equal(await authHeader(), "");
  assert.equal(requests.length, 0);
});

test("no secret appears in output or tool results", async () => {
  const secrets = ["ACCESS-SECRET-1", "ACCESS-SECRET-2", "REFRESH-SECRET-1", "REFRESH-SECRET-2", "AUTHCODE-SECRET"];
  const captured: string[] = [];
  const stdout = process.stdout.write;
  const stderr = process.stderr.write;
  const methods = ["log", "info", "warn", "error", "debug"] as const;
  const originals = methods.map((method) => console[method]);
  try {
    process.stdout.write = ((chunk: unknown) => { captured.push(String(chunk)); return true; }) as typeof process.stdout.write;
    process.stderr.write = ((chunk: unknown) => { captured.push(String(chunk)); return true; }) as typeof process.stderr.write;
    for (const method of methods) console[method] = ((...args: unknown[]) => captured.push(args.join(" "))) as never;
    await completeLogin();
    _resetForTests();
    await getAccessToken();
    rejectRefresh = true;
    _resetForTests();
    await getAccessToken();
    process.env.EMFIRGE_API_KEY = "key-for-test";
    const loginResult = await loginHandler({});
    delete process.env.EMFIRGE_API_KEY;
    const logoutResult = await logoutHandler({});
    process.env.EMFIRGE_BASE_URL = "https://emfirge.cloud/api";
    process.env.EMFIRGE_SUPABASE_URL = supabaseBase;
    try {
      await authHeader();
    } catch (error) {
      captured.push(String(error));
    }
    _resetLoginForTests();
    captured.push(loginResult.content[0].text, logoutResult.content[0].text);
    const exchange = requests.find((request) => request.query.grant_type === "pkce");
    if (exchange) {
      secrets.push((JSON.parse(exchange.body) as { code_verifier: string }).code_verifier);
    }
    for (const secret of secrets) {
      assert.equal(captured.some((text) => text.includes(secret)), false, secret);
    }
  } finally {
    process.stdout.write = stdout;
    process.stderr.write = stderr;
    methods.forEach((method, index) => { console[method] = originals[index]; });
  }
});

test("timeout resolves false, closes the port, and a later login gets a new URL", async () => {
  const first = await startLogin({ timeoutMs: 200 });
  assert.equal(await first.pending, false);
  await assert.rejects(fetch(first.url));
  const second = await startLogin({ timeoutMs: 200 });
  assert.notEqual(second.url, first.url);
  assert.equal(await second.pending, false);
});

test("logout revokes the access token and removes credentials", async () => {
  await completeLogin();
  const result = await logoutHandler({});
  assert.equal(result.content[0].text, "Signed out.");
  const logout = requests.find((request) => request.path === "/auth/v1/logout");
  assert.equal(logout?.headers.authorization, "Bearer ACCESS-SECRET-1");
  assert.equal(fs.existsSync(credentialsFile()), false);
  assert.equal(await getAccessToken(), null);
});

test("single pending login returns the same URL", async () => {
  const first = await startLogin({ timeoutMs: 200 });
  const second = await startLogin({ timeoutMs: 200 });
  assert.equal(second.url, first.url);
  assert.equal(await first.pending, false);
});
