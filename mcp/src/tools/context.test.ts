import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-context-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

type Call = { method: string; url: string; headers: Record<string, string>; body?: any };
const context = await import("./context.js");
const registry = await import("../tools-registry.js");
const { listTokens } = await import("../tokenize.js");

function stubFetch(body: unknown, status = 200): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      method: init?.method ?? "GET",
      url: String(url),
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}

function text(result: { content: Array<{ text: string }> }): string {
  return result.content[0].text;
}

const BUCKET = "zz-planted-bucket-7731";
const ROLE = "zzPlantedRoleApp7731";
const LAMBDA = "zz-planted-lambda-7731";
const DB = "zz-planted-db-7731";
const INSTANCE = "i-0123456789abcdef0";
const SG = "sg-0abc123def4567890";
const ACCOUNT = "123456789012";
const ARN = `arn:aws:iam::${ACCOUNT}:role/${ROLE}`;

const sample = {
  question: "reachable",
  source: { kind: "branch", analysis_id: "scan-1", branch_id: "br-1", collected_at: "2026-10-01T00:00:00Z", region: "ap-south-1" },
  facts: [
    { resource_id: INSTANCE, resource_type: "ec2_instance", protocol: "tcp", ports: [443, 443], source: "0.0.0.0/0", resource_ids: [SG], state: "reachable" },
    { resource_id: DB, resource_type: "rds_instance", protocol: "tcp", ports: [5432, 5432], source: "10.20.0.0/16", resource_ids: [SG], state: "modeled" },
    { resource_id: LAMBDA, resource_type: "lambda_function", protocol: null, ports: [], source: "::/0", resource_ids: [], state: "reachable" },
    { resource_id: `iam-role-${ROLE}`, resource_ids: [BUCKET, ARN], escalation: ["iam-passrole-lambda"] },
    { resource_id: BUCKET, resource_type: "s3_bucket", has_recovery_point: false, recovery_resource_ids: [`snap-${"a".repeat(17)}`, DB], recovery_kinds: ["snapshot"] },
    { resource_id: DB, resource_type: "rds_instance", relationship: "uses", depth: 1, path: [INSTANCE, SG, BUCKET] },
    { resource_id: INSTANCE, resource_type: "ec2_instance", category: "compute", region: "ap-south-1", tags: { team: "web" },
      edges: [{ relationship: "uses", source: INSTANCE, target: BUCKET }] },
    { resource_id: BUCKET, resource_type: "s3_bucket", monthly_usd: null, basis: "usage-based-unknown" },
    { resource_id: INSTANCE, used: null, last_used_at: null, window_days: 14, basis: "branch:evidence" },
  ],
  known: [{ topic: "pricing", detail: "3 of 4 resources priced", resource_id: null }],
  unknown: [
    { topic: "cost", reason: "usage-based pricing is not embedded", resource_id: BUCKET },
    { topic: "last_used", reason: "last-used timestamp could not be read", resource_id: `iam-role-${ROLE}` },
    { topic: "evidence", reason: "cloudwatch_metrics evidence status is 'denied'", resource_id: INSTANCE },
    { topic: "tags:ec2_instance", reason: "tags were not collected for 1 ec2_instance resource(s)", resource_id: null },
    { topic: "collector_skipped", reason: "S3 scan skipped: unexpected error", resource_id: null },
  ],
};

test("sends the question with explicit nulls and auth headers to POST /context", async () => {
  const calls = stubFetch({ ...sample, facts: [] });
  await context.contextHandler({ question: "inventory" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].url, "http://stub.invalid/api/context");
  assert.deepEqual(calls[0].body, { question: "inventory", analysis_id: null, branch_id: null, resource_id: null });
  assert.equal(calls[0].headers.Authorization, "Bearer synthetic-test-api-key");
  assert.equal(calls[0].headers["X-MCP"], "1");
});

test("passes analysis_id, branch_id and resource_id through", async () => {
  const calls = stubFetch({ ...sample, facts: [] });
  await context.contextHandler({ question: "resource", analysis_id: "scan-1", resource_id: "web-server-1" });
  assert.deepEqual(calls[0].body, { question: "resource", analysis_id: "scan-1", branch_id: null, resource_id: "web-server-1" });
  await context.contextHandler({ question: "live", branch_id: "br-1" });
  assert.deepEqual(calls[1].body, { question: "live", analysis_id: null, branch_id: "br-1", resource_id: null });
});

test("a tokenized resource_id is detokenized before it is sent", async () => {
  stubFetch(sample);
  const first = JSON.parse(text(await context.contextHandler({ question: "reachable" })));
  const bucketToken = JSON.parse(text(await context.contextHandler({ question: "reachable" }))).facts[4].resource_id as string;
  assert.match(bucketToken, /^NAME_\d{3}$/);
  const instanceToken = first.facts[0].resource_id as string;
  assert.match(instanceToken, /^EC2_\d{3}$/);
  const calls = stubFetch({ ...sample, facts: [] });
  await context.contextHandler({ question: "resource", resource_id: bucketToken });
  await context.contextHandler({ question: "dependents", resource_id: instanceToken });
  assert.equal(calls[0].body.resource_id, BUCKET);
  assert.equal(calls[1].body.resource_id, INSTANCE);
});

test("every planted name and AWS id in the answer is masked", async () => {
  stubFetch(sample);
  const out = text(await context.contextHandler({ question: "reachable" }));
  for (const secret of [BUCKET, ROLE, LAMBDA, DB, INSTANCE, SG, ACCOUNT, ARN, "a".repeat(17)]) {
    assert.equal(out.includes(secret), false, `leaked ${secret}`);
  }
  assert.equal(JSON.stringify(listTokens()).includes(ACCOUNT), true); // the mapping stays local
});

test("ids under identifier keys get one stable token everywhere", async () => {
  stubFetch(sample);
  const body = JSON.parse(text(await context.contextHandler({ question: "reachable" })));
  const bucket = body.facts[4].resource_id;
  assert.equal(body.facts[3].resource_ids[0], bucket);
  assert.equal(body.facts[5].path[2], bucket);
  assert.equal(body.facts[6].edges[0].target, bucket);
  assert.equal(body.unknown[0].resource_id, bucket);
  assert.equal(body.facts[6].edges[0].source, body.facts[0].resource_id);
  assert.equal(body.unknown[2].resource_id, body.facts[0].resource_id);
  assert.equal(body.facts[4].recovery_resource_ids[1], body.facts[1].resource_id);
});

test("CIDRs in source stay readable, IPv4 private ranges included, as tokenize.ts already treats them", async () => {
  stubFetch(sample);
  const body = JSON.parse(text(await context.contextHandler({ question: "reachable" })));
  assert.equal(body.facts[0].source, "0.0.0.0/0");
  assert.equal(body.facts[1].source, "10.20.0.0/16");
  assert.equal(body.facts[2].source, "::/0");
  stubFetch({ ...sample, facts: ["172.16.0.0/12", "192.168.1.0/24", "203.0.113.0/24", "2001:db8::/32"].map((source) => ({ resource_id: INSTANCE, source })) });
  const more = JSON.parse(text(await context.contextHandler({ question: "reachable" })));
  assert.deepEqual(more.facts.map((f: any) => f.source), ["172.16.0.0/12", "192.168.1.0/24", "203.0.113.0/24", "2001:db8::/32"]);
});

test("a bare IP address is still masked", async () => {
  stubFetch({ ...sample, facts: [{ resource_id: INSTANCE, source: "198.51.100.23" }] });
  const out = text(await context.contextHandler({ question: "reachable" }));
  assert.equal(out.includes("198.51.100.23"), false);
});

test("generic vocabulary survives unmasked", async () => {
  stubFetch(sample);
  const body = JSON.parse(text(await context.contextHandler({ question: "reachable" })));
  assert.equal(body.question, "reachable");
  assert.deepEqual(body.facts[0].ports, [443, 443]);
  assert.equal(body.facts[0].resource_type, "ec2_instance");
  assert.equal(body.facts[0].protocol, "tcp");
  assert.equal(body.facts[0].state, "reachable");
  assert.equal(body.facts[1].state, "modeled");
  assert.equal(body.facts[3].escalation[0], "iam-passrole-lambda");
  assert.equal(body.facts[4].recovery_kinds[0], "snapshot");
  assert.equal(body.facts[5].relationship, "uses");
  assert.equal(body.facts[6].category, "compute");
  assert.equal(body.facts[6].edges[0].relationship, "uses");
  assert.equal(body.facts[7].basis, "usage-based-unknown");
  assert.equal(body.facts[8].basis, "branch:evidence");
  assert.deepEqual(body.known[0], { topic: "pricing", detail: "3 of 4 resources priced", resource_id: null });
  assert.deepEqual(body.unknown.map((u: any) => u.topic), ["cost", "last_used", "evidence", "tags:ec2_instance", "collector_skipped"]);
  assert.equal(body.unknown[0].reason, "usage-based pricing is not embedded");
  assert.equal(body.source.kind, "branch");
  assert.equal(body.source.region, "ap-south-1");
});

test("backend errors go through redaction and carry no ids", async () => {
  stubFetch({ detail: `bad ${BUCKET} ${INSTANCE}` }, 500);
  await assert.rejects(context.contextHandler({ question: "inventory" }), (error: Error) => {
    assert.equal(error.message.includes(INSTANCE), false);
    return true;
  });
  const result = await registry.dispatchTool("emfirge_context", { question: "advise" });
  assert.equal((result as any).isError, true);
});

test("is registered with the documented schema and a facts-only description", () => {
  const tool = registry.tools.find((entry) => entry.name === "emfirge_context");
  assert.ok(tool);
  const schema = registry.zodToJsonSchema(tool.zodObject) as any;
  assert.deepEqual(schema.required, ["question"]);
  assert.deepEqual(schema.properties.question.enum,
    ["inventory", "resource", "depends_on", "dependents", "reachable", "access", "data", "cost", "live", "marks", "baseline"]);
  assert.deepEqual(Object.keys(schema.properties).sort(), ["analysis_id", "branch_id", "question", "resource_id"]);
  assert.match(tool.description, /never advice/i);
  assert.match(tool.description, /unknown/i);
});
