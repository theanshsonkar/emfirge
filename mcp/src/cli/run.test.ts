// What each verb sends, what it prints, and how it exits. fetch is stubbed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-cli-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

const { runCli } = await import("./run.js");

type Call = { method: string; url: string; headers: Record<string, string>; body?: any };
type Reply = { status?: number; body: unknown } | "network";

function stub(...replies: Reply[]): Call[] {
  const calls: Call[] = [];
  const queue = replies.slice();
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      method: init?.method ?? "GET",
      url: String(url).replace("http://stub.invalid/api", ""),
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    const r = queue.length > 1 ? queue.shift()! : queue[0] ?? { body: {} };
    if (r === "network") throw new TypeError("fetch failed");
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}

async function run(argv: string[], files: Record<string, string> = {}, stdin = "") {
  let stdout = "";
  let stderr = "";
  const code = await runCli(argv, {
    out: (s) => { stdout += s; },
    err: (s) => { stderr += s; },
    readFile: (p) => { if (p in files) return files[p]; throw new Error(`ENOENT ${p}`); },
    readStdin: async () => stdin,
  });
  return { code, stdout, stderr };
}

const BUCKET = "zz-planted-bucket-7731";
const SG = "sg-0abc123def4567890";
const INSTANCE = "i-0123456789abcdef0";
const ACCOUNT = "123456789012";
const TAGVAL = "zz-secret-team-value";

// ---- context ----
test("context sends the question with explicit nulls", async () => {
  const calls = stub({ body: { question: "inventory", facts: [], known: [], unknown: [] } });
  const r = await run(["context", "inventory"]);
  assert.equal(r.code, 0);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].url, "/context");
  assert.deepEqual(calls[0].body, { question: "inventory", analysis_id: null, branch_id: null, resource_id: null });
  assert.equal(calls[0].headers.Authorization, "Bearer synthetic-test-api-key");
  assert.equal(JSON.parse(r.stdout).question, "inventory");
});

test("context expands a token back to the real id and masks the answer", async () => {
  const reply = {
    question: "reachable",
    facts: [
      { resource_id: BUCKET, resource_type: "s3_bucket", resource_ids: [SG, INSTANCE] },
      { resource_id: INSTANCE, resource_type: "ec2_instance", tags: { team: TAGVAL } },
    ],
    known: [], unknown: [],
  };
  stub({ body: reply });
  const first = await run(["context", "reachable", "--branch", "br-1"]);
  assert.equal(first.code, 0);
  for (const secret of [BUCKET, SG, INSTANCE, TAGVAL]) assert.equal(first.stdout.includes(secret), false, `leaked ${secret}`);
  const body = JSON.parse(first.stdout);
  const token = body.facts[0].resource_id as string;
  assert.match(token, /^NAME_\d{3}$/);
  assert.match(body.facts[1].tags.team, /^TAG_\d{3}$/);

  const calls = stub({ body: { question: "resource", facts: [], known: [], unknown: [] } });
  await run(["context", "resource", "--resource", token, "--branch", "br-1"]);
  assert.equal(calls[0].body.resource_id, BUCKET);
  assert.equal(calls[0].body.branch_id, "br-1");
});

test("context modes call the existing endpoints", async () => {
  let calls = stub({ body: { findings: [] } });
  let r = await run(["context", "--findings", "--analysis", "a1", "--severity", "Critical"]);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(calls.length >= 1);
  calls = stub({ body: { attack_paths: [] } });
  r = await run(["context", "--attack-paths", "--analysis", "a1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(calls.length >= 1);
  calls = stub({ body: { frameworks: [] } });
  r = await run(["context", "--compliance", "--analysis", "a1", "--framework", "soc2"]);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(calls.length >= 1);
  calls = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(url).replace("http://stub.invalid/api", ""), headers: {}, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(`event: complete\ndata: ${JSON.stringify({ verdict: "x" })}\n\n`, { status: 200, headers: { "content-type": "text/event-stream" } });
  }) as typeof fetch;
  r = await run(["context", "--simulate", "what if SG_001 opens port 80", "--analysis", "a1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(calls.length >= 1);
});

test("context --refresh runs the scan (SSE)", async () => {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(url).replace("http://stub.invalid/api", ""), headers: {}, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (String(url).includes("/usage/remaining")) return new Response("{}", { status: 404 });
    const sse = `event: complete\ndata: ${JSON.stringify({ analysis_id: "an-9", risk_score: 12 })}\n\n`;
    return new Response(sse, { status: 200, headers: { "content-type": "text/event-stream" } });
  }) as typeof fetch;
  const r = await run(["context", "--refresh", "--role-arn", `arn:aws:iam::${ACCOUNT}:role/emfirge`, "--region", "ap-south-1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(calls[0].url, "/analyze/stream");
  assert.deepEqual(calls[0].body, { role_arn: `arn:aws:iam::${ACCOUNT}:role/emfirge`, region: "ap-south-1" });
  assert.equal(JSON.parse(r.stdout).analysis_id, "an-9");
  assert.equal(r.stdout.includes(ACCOUNT), false);
});

test("context --refresh without role-arn and region is a usage error", async () => {
  const r = await run(["context", "--refresh"]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, "");
});

// ---- branch ----
test("branch verbs send the right request", async () => {
  const cases: Array<[string[], string, string, any]> = [
    [["branch", "open", "--analysis", "a1", "--name", "fix"], "POST", "/branches", { base_analysis_id: "a1", name: "fix" }],
    [["branch", "fork", "b1", "--name", "copy"], "POST", "/branches/b1/fork", { name: "copy" }],
    [["branch", "list", "--analysis", "a1"], "GET", "/branches?base_analysis_id=a1", undefined],
    [["branch", "get", "b1"], "GET", "/branches/b1", undefined],
    [["branch", "rollback", "b1"], "POST", "/branches/b1/rollback", {}],
    [["branch", "rollback-to", "b1", "--count", "2"], "POST", "/branches/b1/rollback-to-count", { target_change_count: 2 }],
    [["branch", "discard", "b1"], "POST", "/branches/b1/discard", {}],
    [["branch", "compare", "b1", "b2"], "POST", "/branches/compare", { branch_ids: ["b1", "b2"] }],
  ];
  for (const [argv, method, url, body] of cases) {
    const calls = stub({ body: [] });
    const r = await run(argv);
    assert.equal(r.code, 0, argv.join(" ") + r.stderr);
    assert.equal(calls[0].method, method, argv.join(" "));
    assert.equal(calls[0].url, url, argv.join(" "));
    assert.deepEqual(calls[0].body, body, argv.join(" "));
    JSON.parse(r.stdout);
  }
});

test("branch list wraps an array as {branches,count}", async () => {
  stub({ body: [{ status: "open" }] });
  const r = await run(["branch", "list"]);
  assert.deepEqual(JSON.parse(r.stdout), { branches: [{ status: "open" }], count: 1 });
});

test("branch missing a required option is a usage error", async () => {
  assert.equal((await run(["branch", "open", "--name", "x"])).code, 1);
  assert.equal((await run(["branch", "get"])).code, 1);
  assert.equal((await run(["branch", "rollback-to", "b1"])).code, 1);
});

test("branch output is masked", async () => {
  stub({ body: { id: "b1", changes: [{ resource_id: SG }] } });
  const r = await run(["branch", "get", "b1"]);
  assert.equal(r.stdout.includes(SG), false);
});

// ---- try ----
test("try --typed applies a typed change, expanding tokens", async () => {
  stub({ body: { question: "x", facts: [{ resource_id: SG }], known: [], unknown: [] } });
  const seen = JSON.parse((await run(["context", "inventory"])).stdout).facts[0].resource_id as string;
  assert.match(seen, /^SG_\d{3}$/);
  const calls = stub({ body: { change_count: 1 } });
  const change = JSON.stringify({ op: "modify", resource_type: "security_group", resource_id: seen, fields: { ip_ranges: ["10.0.0.0/8"] } });
  const r = await run(["try", "b1", "--typed", change]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].url, "/branches/b1/changes");
  assert.equal(calls[0].body.resource_id, SG);
  assert.equal(calls[0].body.op, "modify");
  assert.equal(calls[0].body.branch_id, undefined);
});

test("try plan formats go to /plans/<format>, then verdict and handback", async () => {
  const ingest = { plan_id: "p1", input_sha256: "a".repeat(64), applied: [], rejected: [], unmodeled: [], unknown_fields: [] };
  const handback = { plan_id: "p1", input_sha256: "a".repeat(64), verdict_id: "v", branch_revision: "r", calls: [] };
  const replies: Reply[] = [{ body: ingest }, { body: { verdict: "warn", reasons: [] } }, { body: handback }];
  let calls = stub(...replies);
  let r = await run(["try", "b1", "--aws-cli", "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(calls[0].url, "/branches/b1/plans/aws-cli");
  assert.equal(calls[0].body.commands.length, 1);
  assert.equal(calls[0].body.format, "aws-cli/1");
  assert.equal(calls[1].url, "/branches/b1/verdict");
  assert.equal(calls[2].url, "/branches/b1/plans/p1/handback");
  assert.equal(JSON.parse(r.stdout).plan_id, "p1");

  const api = { format: "aws-api-calls/1", calls: [{ service: "ec2", operation: "DeleteVolume", parameters: {} }] };
  calls = stub(...replies);
  r = await run(["try", "b1", "--aws-api", JSON.stringify(api)]);
  assert.equal(calls[0].url, "/branches/b1/plans/aws-api");
  assert.deepEqual(calls[0].body, api);

  calls = stub(...replies);
  r = await run(["try", "b1", "--terraform", "plan.json"], { "plan.json": '{"resource_changes":[]}' });
  assert.equal(calls[0].url, "/branches/b1/plans/terraform");
  assert.deepEqual(calls[0].body, { resource_changes: [] });

  calls = stub(...replies);
  r = await run(["try", "b1", "--cloudformation", "-"], {}, '{"Changes":[]}');
  assert.equal(calls[0].url, "/branches/b1/plans/cloudformation");
  assert.deepEqual(calls[0].body, { Changes: [] });
});

test("try needs exactly one input; bad JSON is a usage error", async () => {
  assert.equal((await run(["try", "b1"])).code, 1);
  assert.equal((await run(["try", "b1", "--typed", "{}", "--terraform", "x"])).code, 1);
  assert.equal((await run(["try", "b1", "--typed", "{not json"])).code, 1);
  assert.equal((await run(["try", "b1", "--terraform", "missing.json"])).code, 1);
  assert.equal((await run(["try"])).code, 1);
});

test("try --verify-fix calls the verify-fix endpoint", async () => {
  const calls = stub({ body: { score_delta: 3 } });
  const r = await run(["try", "--verify-fix", "--rule", "EC2-002", "--resource", "sg-1", "--analysis", "a1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(calls[0].method, "POST");
  assert.ok(calls.length >= 1);
});

// ---- check ----
const checkReply = {
  branch_id: "b1", base_analysis_id: "a1", branch_revision: "r", changes: 1,
  answers: ["data", "exposure", "money", "availability", "control", "outside_world"].map((damage) => ({
    damage, facts: damage === "exposure" ? [{ resource_id: SG, state: "open" }] : [], checked: ["x"], unknown: [],
  })),
  baseline: null,
};

test("check calls GET /branches/{id}/check and masks the answer", async () => {
  const calls = stub({ body: checkReply });
  const r = await run(["check", "b1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[0].url, "/branches/b1/check");
  assert.equal(r.stdout.includes(SG), false);
  assert.equal(JSON.parse(r.stdout).answers.length, 6);
  assert.equal(r.stderr, "");
});

test("check options map to verdict, diff, policy and evidence", async () => {
  let calls = stub({ body: { verdict: "pass" } });
  await run(["check", "b1", "--verdict"]);
  assert.equal(calls[0].url, "/branches/b1/verdict");
  calls = stub({ body: {} });
  await run(["check", "b1", "--diff"]);
  assert.equal(calls[0].url, "/branches/b1/diff");
  calls = stub({ body: { estimate: {} } });
  let r = await run(["check", "b1", "--policy"]);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(calls.length >= 1);
  calls = stub({ body: { estimate: {} } });
  r = await run(["check", "b1", "--evidence"]);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(calls.length >= 1);
});

test("check --human prints a short readable form, not JSON", async () => {
  stub({ body: checkReply });
  const r = await run(["check", "b1", "--human"]);
  assert.equal(r.code, 0, r.stderr);
  assert.throws(() => JSON.parse(r.stdout));
  assert.match(r.stdout, /exposure/);
  assert.match(r.stdout, /unknown/i);
  assert.equal(r.stdout.includes(SG), false);
});

// ---- report ----
test("report maps to the handback", async () => {
  let calls = stub({ body: { calls: [], input_sha256: "a".repeat(64), base_analysis_id: "a1", branch_revision: "r", verdict_id: "v" } });
  let r = await run(["report", "b1"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(calls[0].url, "/branches/b1/handback");
  calls = stub({ body: { plan_id: "p1" } });
  r = await run(["report", "b1", "--plan", "p1"]);
  assert.equal(calls[0].url, "/branches/b1/plans/p1/handback");
  calls = stub({ body: { calls: [] } }, { body: { ok: true } });
  r = await run(["report", "b1", "--verify"]);
  assert.equal(calls[1].url, "/branches/b1/handback/verify");
});

// ---- request ----
test("request is not built: JSON error on stderr, exit 1, no network", async () => {
  const calls = stub({ body: {} });
  const r = await run(["request", "b1", "--reason", "need approval"]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, "");
  assert.equal(calls.length, 0);
  const err = JSON.parse(r.stderr);
  assert.equal(err.error.code, "not_built");
  assert.match(err.error.message, /not built yet/i);
  assert.match(err.error.message, /v2/);
});

// ---- output + exit codes ----
test("stdout is exactly one JSON document, logs go to stderr", async () => {
  stub({ body: { question: "inventory", facts: [], known: [], unknown: [] } });
  const r = await run(["context", "inventory"]);
  assert.equal(r.stderr, "");
  assert.doesNotThrow(() => JSON.parse(r.stdout));
  assert.ok(r.stdout.endsWith("\n"));
});

test("exit codes: 401/403 -> 2, 404 -> 3, 500 and network -> 4", async () => {
  const expectations: Array<[Reply, number]> = [
    [{ status: 401, body: { detail: "bad key" } }, 2],
    [{ status: 403, body: { detail: "forbidden" } }, 2],
    [{ status: 404, body: { detail: "nope" } }, 3],
    [{ status: 500, body: { detail: "boom" } }, 4],
    ["network", 4],
  ];
  for (const [reply, code] of expectations) {
    stub(reply);
    const r = await run(["branch", "get", "b1"]);
    assert.equal(r.code, code, JSON.stringify(reply));
    assert.equal(r.stdout, "", "no stdout on error");
    const err = JSON.parse(r.stderr);
    assert.equal(err.error.exit, code);
    assert.equal(typeof err.error.message, "string");
  }
});

test("errors never leak ids, and --human errors are plain text", async () => {
  stub({ status: 500, body: { detail: `failed on ${SG}` } });
  const r = await run(["branch", "get", "b1", "--human"]);
  assert.equal(r.code, 4);
  assert.equal(r.stderr.includes(SG), false);
  assert.match(r.stderr, /^Error:/);
});

test("not signed in exits 2 without waiting for a browser", async () => {
  const saved = process.env.EMFIRGE_API_KEY;
  delete process.env.EMFIRGE_API_KEY;
  try {
    const calls = stub({ body: {} });
    const started = Date.now();
    const r = await run(["branch", "list"]);
    assert.equal(r.code, 2);
    assert.equal(calls.length, 0);
    assert.ok(Date.now() - started < 5000);
    assert.match(JSON.parse(r.stderr).error.message, /sign in|login/i);
  } finally {
    process.env.EMFIRGE_API_KEY = saved;
  }
});
