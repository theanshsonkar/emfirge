// HTTP status to exit code, and AWS CLI shorthand. fetch is stubbed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-cli-exit-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

const { runCli } = await import("./run.js");
const { bundledManifest } = await import("./manifest.js");

function stub(status: number, body: unknown): { calls: number } {
  const state = { calls: 0 };
  globalThis.fetch = (async () => {
    state.calls += 1;
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return state;
}

async function run(argv: string[]) {
  let stdout = "";
  let stderr = "";
  const code = await runCli(argv, {
    loadManifest: async () => ({ manifest: bundledManifest(), source: "bundled" as const }),
    out: (s) => { stdout += s; },
    err: (s) => { stderr += s; },
    readFile: () => { throw new Error("ENOENT"); },
    readStdin: async () => "",
  });
  return { code, stdout, stderr };
}

test("400 and 422 are usage errors (exit 1), not server errors", async () => {
  for (const status of [400, 422]) {
    stub(status, { detail: "Command 1: unknown option --nope" });
    const r = await run(["branch", "get", "b1"]);
    assert.equal(r.code, 1, String(status));
    assert.equal(r.stdout, "");
    const err = JSON.parse(r.stderr.split("\n")[0]).error;
    assert.equal(err.exit, 1);
    assert.equal(err.code, "usage");
    assert.match(err.message, /unknown option --nope/);
  }
});

test("409 is a conflict with its own exit code 5, and 429 is rate_limited on the existing try-later code 4", async () => {
  stub(409, { detail: "The branch changed since you read it." });
  let r = await run(["branch", "get", "b1"]);
  assert.equal(r.code, 5);
  assert.deepEqual([JSON.parse(r.stderr.split("\n")[0]).error.code, JSON.parse(r.stderr).error.exit], ["conflict", 5]);
  stub(429, { detail: "Daily limit reached." });
  r = await run(["branch", "get", "b1"]);
  assert.equal(r.code, 4);
  assert.deepEqual([JSON.parse(r.stderr.split("\n")[0]).error.code, JSON.parse(r.stderr).error.exit], ["rate_limited", 4]);
});

test("the other statuses keep their codes", async () => {
  for (const [status, code] of [[401, 2], [403, 2], [404, 3], [500, 4], [502, 4]] as const) {
    stub(status, { detail: "x" });
    assert.equal((await run(["branch", "get", "b1"])).code, code, String(status));
  }
});

test("the agent guide documents every exit code the CLI can return", () => {
  const guide = readFileSync(new URL("../../../docs/AGENT-GUIDE.md", import.meta.url), "utf-8");
  for (const code of [0, 1, 2, 3, 4, 5]) assert.match(guide, new RegExp(`^\\| ${code} \\|`, "m"), `exit ${code}`);
  assert.match(guide, /\| 5 \|[^\n]*conflict/i);
});

test("AWS shorthand is refused before any request, with a message that says to pass JSON", async () => {
  const cases = [
    "aws scheduler create-schedule --name s --schedule-expression 'rate(5 minutes)' --flexible-time-window Mode=OFF --target Arn=arn:aws:lambda:us-east-1:123456789012:function:f,RoleArn=arn:aws:iam::123456789012:role/r",
    "aws scheduler create-schedule --name s --flexible-time-window=Mode=OFF",
    "aws ec2 create-tags --resources i-1 --tags Key=a,Value=b",
  ];
  for (const command of cases) {
    const state = stub(200, {});
    const r = await run(["try", "b1", "--aws-cli", command]);
    assert.equal(r.code, 1, command);
    assert.equal(state.calls, 0, "no request is sent");
    const err = JSON.parse(r.stderr.split("\n")[0]).error;
    assert.equal(err.code, "usage");
    assert.match(err.message, /shorthand/i);
    assert.match(err.message, /not supported/i);
    assert.match(err.message, /JSON/);
    assert.match(err.message, /Command 1/);
  }
});

test("shorthand is named by option, and JSON values and plain values are not mistaken for it", async () => {
  stub(200, {});
  let r = await run(["try", "b1", "--aws-cli", "aws scheduler create-schedule --name s --flexible-time-window Mode=OFF"]);
  assert.match(JSON.parse(r.stderr.split("\n")[0]).error.message, /--flexible-time-window/);
  const ok = [
    `aws scheduler create-schedule --name s --flexible-time-window '{"Mode":"OFF"}' --target '{"Arn":"a","RoleArn":"r"}'`,
    "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0",
  ];
  for (const command of ok) {
    const state = stub(200, { verdict: "x" });
    r = await run(["try", "b1", "--aws-cli", command]);
    assert.ok(state.calls > 0, command);
  }
});
