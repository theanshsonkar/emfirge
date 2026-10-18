import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
process.env.EMFIRGE_API_KEY = "test-key";
process.env.EMFIRGE_EXTERNAL_ID = "external-test";

const client = await import("./client.js");
const branches = await import("./tools/branches.js");
const setup = await import("./tools/setup.js");
const scan = await import("./tools/scan.js");
const findings = await import("./tools/findings.js");
const attack = await import("./tools/attack-paths.js");
const verify = await import("./tools/verify-fix.js");
const compliance = await import("./tools/compliance.js");
const simulate = await import("./tools/simulate.js");
const { formatToolError } = await import("./tool-error.js");

type Call = { method: string; url: string; body?: unknown };
let calls: Call[];
let response: Response;
function stub(status: number, body: unknown, sse = false) {
  calls = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(url), body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return response ?? new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  response = sse
    ? new Response(`event: complete\ndata: ${JSON.stringify(body)}\n\n`, { status, headers: { "content-type": "text/event-stream" } })
    : new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
async function rejectsDetail(fn: () => Promise<unknown>, detail: string) {
  await assert.rejects(fn, (e: Error) => e.message.includes(detail));
}

beforeEach(() => { response = undefined as unknown as Response; });

test("client surfaces 409 string detail", async () => {
  stub(409, { detail: "Branch region us-west-2 does not match scan region us-east-1" });
  await rejectsDetail(() => client.backendCall("GET", "/branches/x"), "Branch region us-west-2 does not match scan region us-east-1");
});
test("client surfaces 422 structured detail", async () => {
  stub(422, { detail: [{ loc: ["body", "x"], msg: "field required" }] });
  await rejectsDetail(() => client.backendCall("GET", "/x"), "field required");
});
test("client uses backend detail for 403 and fallback without body", async () => {
  stub(403, { detail: "role denied by backend" });
  await rejectsDetail(() => client.backendCall("GET", "/x"), "role denied by backend");
  stub(403, "");
  await assert.rejects(() => client.backendCall("GET", "/x"), /Access denied\. Check the role's trust policy/);
});
test("404 messages are path-aware for regular and SSE clients", async () => {
  stub(404, { detail: "Branch missing" });
  await assert.rejects(() => client.backendCall("GET", "/branches/x"), (e: Error) => e.message.includes("Branch not found") && e.message.includes("emfirge_list_branches") && !e.message.includes("emfirge_scan"));
  stub(404, { detail: "Not Found" });
  await assert.rejects(() => client.backendCall("GET", "/logs/by-uuid/x"), /emfirge_scan/);
  stub(404, { detail: "Branch missing" }, true);
  await assert.rejects(() => client.backendCallSSE("GET", "/branches/x"), (e: Error) => e.message.includes("Branch not found") && e.message.includes("emfirge_list_branches") && !e.message.includes("emfirge_scan"));
  stub(404, { detail: "Not Found" }, true);
  await assert.rejects(() => client.backendCallSSE("GET", "/logs/by-uuid/x"), /emfirge_scan/);
});
test("list_branches wraps an array", async () => {
  stub(200, [{ id: "b1" }, { id: "b2" }]);
  const out = await branches.listBranchesHandler({});
  const parsed = JSON.parse(out.content[0].text) as { branches: unknown[]; count: number };
  assert.equal(parsed.count, 2);
  assert.equal(parsed.branches.length, 2);
});
test("real findings handler plus index error wrapper preserves slashes", async () => {
  stub(404, { detail: "Not Found" });
  await assert.rejects(() => findings.findingsHandler({ analysis_id: "missing-analysis" }), (e: Error) => {
    const wrapped = formatToolError(e);
    return wrapped.includes("/logs/by-uuid/missing-analysis");
  });
});

test("setup_help sends GET /project and includes response field", async () => {
  stub(200, { external_id: "ext-123", project: "p1" });
  const out = await setup.setupHandler({});
  assert.equal(calls[0].method, "GET"); assert.equal(calls[0].url, "http://stub.invalid/api/project"); assert.match(out.content[0].text, /ext-123/);
});
test("scan sends POST stream body and includes response field", async () => {
  stub(200, { analysis_id: "a1", risk_score: 42 }, true);
  const out = await scan.scanHandler({ role_arn: "arn:aws:iam::123456789012:role/Read", region: "us-east-1" });
  assert.equal(calls[0].method, "POST"); assert.equal(calls[0].url, "http://stub.invalid/api/analyze/stream"); assert.deepEqual(calls[0].body, { role_arn: "arn:aws:iam::123456789012:role/Read", region: "us-east-1" }); assert.match(out.content[0].text, /risk_score/);
});
test("get_findings sends exact GET path and includes field", async () => { stub(200, { findings_json: { critical_risks: [{ rule_id: "R1" }] } }); const out = await findings.findingsHandler({ analysis_id: "a1" }); assert.equal(calls[0].method, "GET"); assert.equal(calls[0].url, "http://stub.invalid/api/logs/by-uuid/a1"); assert.match(out.content[0].text, /R1/); });
test("attack_paths sends exact GET path and includes field", async () => { stub(200, { attack_paths: [{ title: "pivot" }] }); const out = await attack.attackPathsHandler({ analysis_id: "a1" }); assert.equal(calls[0].method, "GET"); assert.equal(calls[0].url, "http://stub.invalid/api/egraph/a1"); assert.match(out.content[0].text, /pivot/); });
test("verify_fix sends normalized POST body and includes field", async () => { stub(200, { can_simulate: true, score_delta: 7 }); const out = await verify.verifyFixHandler({ rule_id: "EC2-002", resource_id: "i-real", analysis_id: "a1" }); assert.equal(calls[0].method, "POST"); assert.equal(calls[0].url, "http://stub.invalid/api/remediation/verify-fix"); assert.deepEqual(calls[0].body, { rule_id: "EMFIRGE-EC2-002", resource_id: "i-real", analysis_id: "a1" }); assert.match(out.content[0].text, /score_delta/); });
test("check_compliance sends exact GET path and includes field", async () => { stub(200, { frameworks: [{ id: "cis-aws-1.5", passed: 3 }] }); const out = await compliance.complianceHandler({ analysis_id: "a1", framework: "cis-aws-1.5" }); assert.equal(calls[0].method, "GET"); assert.equal(calls[0].url, "http://stub.invalid/api/compliance/a1"); assert.match(out.content[0].text, /passed/); });
test("simulate_breach sends SSE POST body and includes field", async () => { stub(200, { verdict: "high", stages: ["entry"] }, true); const out = await simulate.simulateHandler({ query: "show attack path", analysis_id: "a1" }); assert.equal(calls[0].method, "POST"); assert.equal(calls[0].url, "http://stub.invalid/api/simulate"); assert.deepEqual(calls[0].body, { query: "show attack path", analysis_id: "a1" }); assert.match(out.content[0].text, /high/); });

for (const [name, fn] of [
  ["setup_help", () => setup.setupHandler({})],
  ["scan", () => scan.scanHandler({ role_arn: "arn:aws:iam::123456789012:role/Read", region: "us-east-1" })],
  ["get_findings", () => findings.findingsHandler({ analysis_id: "a1" })],
  ["attack_paths", () => attack.attackPathsHandler({ analysis_id: "a1" })],
  ["verify_fix", () => verify.verifyFixHandler({ rule_id: "EC2-002", resource_id: "i-real", analysis_id: "a1" })],
  ["check_compliance", () => compliance.complianceHandler({ analysis_id: "a1" })],
  ["simulate_breach", () => simulate.simulateHandler({ query: "show attack path", analysis_id: "a1" })],
] as const) {
  test(`${name} propagates backend detail`, async () => {
    stub(400, { detail: `${name} backend failure` }, name === "scan" || name === "simulate_breach");
    if (name === "setup_help") {
      const old = process.env.EMFIRGE_EXTERNAL_ID;
      delete process.env.EMFIRGE_EXTERNAL_ID;
      try { await rejectsDetail(fn, `${name} backend failure`); } finally { process.env.EMFIRGE_EXTERNAL_ID = old; }
    } else {
      await rejectsDetail(fn, `${name} backend failure`);
    }
  });
}

test("formatToolError redacts ARN account and role path in strict mode", () => {
  const out = formatToolError(new Error("Backend 403 on /x: role arn:aws:iam::123456789012:role/team/Admin denied"));
  assert.equal(out.includes("123456789012"), false);
  assert.equal(out.includes("team/Admin"), false);
});

test("formatToolError redacts ARN account and role path in balanced mode", () => {
  const script = `import { formatToolError } from './src/tool-error.ts'; console.log(formatToolError(new Error('Backend 403 on /x: role arn:aws:iam::123456789012:role/team/Admin denied')))`;
  const out = execFileSync(process.execPath, ["--import", "tsx", "--eval", script], {
    cwd: process.cwd(),
    env: { ...process.env, EMFIRGE_PRIVACY: "balanced" },
    encoding: "utf8",
  });
  assert.equal(out.includes("123456789012"), false);
  assert.equal(out.includes("team/Admin"), false);
});
