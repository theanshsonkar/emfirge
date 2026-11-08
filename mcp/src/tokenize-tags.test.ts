// Resource tag VALUES never reach the host in strict/balanced mode; tag KEYS stay readable.
// Every shape tags arrive in is covered, through the real tool handlers where one exists.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-tags-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

const { redactDeep, expandTokens } = await import("./tokenize.js");
const { contextHandler } = await import("./tools/context.js");
const branches = await import("./tools/branches.js");
const { branchHandbackHandler } = await import("./tools/branch-handback.js");
const { findingsHandler } = await import("./tools/findings.js");
const { inUseEvidenceHandler } = await import("./tools/evidence.js");
const { policyChecksHandler } = await import("./tools/policy-checks.js");

type Call = { method: string; url: string; body?: any };
function stubFetch(body: unknown): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(url), body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}
const textOf = (r: { content: Array<{ text: string }> }) => r.content.map((p) => p.text).join("\n");

// Planted values: none is an AWS id shape or a known name.
const V_OWNER = "acme-payroll";
const V_ENV = "prod";
const V_AWS = "arn-stack-zz91";
const V_CASE = "Quarterly Close Team";
const V_PLAIN = "payroll";
const ALL = [V_OWNER, V_ENV, V_AWS, V_CASE, V_PLAIN];

function assertMasked(out: string, values = ALL) {
  for (const v of values) assert.ok(!out.includes(v), `tag value ${v} leaked in: ${out}`);
}

test("tag dict: values become tokens, keys stay readable", () => {
  const out = redactDeep({ tags: { owner: V_OWNER, env: V_ENV, Name: V_CASE, "aws:cloudformation:stack-name": V_AWS } }) as any;
  assert.deepEqual(Object.keys(out.tags), ["owner", "env", "Name", "aws:cloudformation:stack-name"]);
  for (const v of Object.values(out.tags)) assert.match(v as string, /^TAG_\d{3}$/);
  assertMasked(JSON.stringify(out));
});

test("same value gets the same token; different values differ", () => {
  const out = redactDeep({ tags: { a: V_OWNER, b: V_OWNER, c: V_ENV } }) as any;
  assert.match(out.tags.a, /^TAG_\d{3}$/);
  assert.equal(out.tags.a, out.tags.b);
  assert.notEqual(out.tags.a, out.tags.c);
  const again = redactDeep({ Tags: [{ Key: "x", Value: V_OWNER }] }) as any;
  assert.equal(again.Tags[0].Value, out.tags.a);
});

test("AWS [{Key,Value}] and [{key,value}] lists under any tag-ish key", () => {
  const out = redactDeep({
    Tags: [{ Key: "owner", Value: V_OWNER }, { Key: "aws:cloudformation:stack-name", Value: V_AWS }],
    tag_set: [{ key: "env", value: V_ENV }],
    TagSet: [{ Key: "k", Value: V_PLAIN }],
    params: { TagSpecifications: [{ ResourceType: "natgateway", Tags: [{ Key: "Name", Value: V_CASE }] }] },
  }) as any;
  const s = JSON.stringify(out);
  assertMasked(s);
  for (const k of ["owner", "aws:cloudformation:stack-name", "env", "Name"]) assert.ok(s.includes(`"${k}"`), `key ${k} must stay`);
  assert.equal(out.Tags[0].Key, "owner");
});

test("bare AWS Key/Value pair list outside a tags key is masked", () => {
  const s = JSON.stringify(redactDeep({ resource: { description: [{ Key: "owner", Value: V_OWNER }] } }));
  assertMasked(s, [V_OWNER]);
  assert.ok(s.includes('"owner"'));
});

test("tag values that look like ids or never-sensitive words are still masked", () => {
  const out = redactDeep({ tags: { a: "high", b: "80", c: "sg-0abc123def4567890", d: "", e: "ABC_123" } }) as any;
  assert.notEqual(out.tags.a, "high");
  assert.notEqual(out.tags.b, "80");
  assert.notEqual(out.tags.c, "sg-0abc123def4567890");
  assert.equal(out.tags.d, "");
  assert.match(out.tags.e, /^TAG_\d{3}$/);
});

test("null tags (not collected) stay null", () => {
  assert.deepEqual(redactDeep({ tags: null }), { tags: null });
});

test("tag values do not leak through prose in the same response", () => {
  const out = JSON.stringify(redactDeep({
    facts: [{ resource_id: "i-0123456789abcdef0", tags: { owner: V_OWNER } }],
    known: [{ topic: "owner", detail: `owned by ${V_OWNER} team` }],
  }));
  assertMasked(out, [V_OWNER]);
});

test("context: inventory and marks facts", async () => {
  stubFetch({
    question: "marks", source: { kind: "analysis" },
    facts: [
      { resource_id: "i-0123456789abcdef0", resource_type: "ec2_instance", category: "compute", tags: { owner: V_OWNER, env: V_ENV }, edges: [] },
      { resource_id: "sg-0abc123def4567890", tags: { Name: V_CASE, "aws:cloudformation:stack-name": V_AWS, team: V_PLAIN } },
    ],
    known: [], unknown: [],
  });
  for (const question of ["inventory", "marks"] as const) {
    const out = textOf(await contextHandler({ question, analysis_id: "a-1" } as any));
    assertMasked(out);
    for (const k of ["owner", "env", "Name", "aws:cloudformation:stack-name", "team"].slice(0, 2)) assert.ok(out.includes(`"${k}"`));
  }
});

test("branch get / diff / verdict / handback / evidence / policy-checks responses", async () => {
  const payload = {
    resources_modified: [{ id: "i-0123456789abcdef0", resource_type: "ec2_instance", changed: ["tags"], before: { tags: { owner: V_OWNER } }, after: { Tags: [{ Key: "owner", Value: V_ENV }] } }],
    reasons: [{ resources: ["i-0123456789abcdef0"], tags: { "aws:createdBy": V_AWS } }],
    calls: [{ service: "ec2", operation: "CreateTags", params: { Resources: ["i-0123456789abcdef0"], Tags: [{ Key: "Name", Value: V_CASE }, { Key: "team", Value: V_PLAIN }] } }],
  };
  for (const run of [
    () => branches.getBranchHandler({ branch_id: "br-1" }),
    () => branches.branchDiffHandler({ branch_id: "br-1" }),
    () => branches.branchVerdictHandler({ branch_id: "br-1" }),
    () => branchHandbackHandler({ branch_id: "br-1" } as any),
    () => inUseEvidenceHandler({ branch_id: "br-1", sources: ["cloudtrail_events"] } as any),
    () => policyChecksHandler({ branch_id: "br-1" } as any),
  ]) {
    stubFetch(payload);
    const out = textOf(await run() as any);
    assertMasked(out);
    assert.ok(out.includes('"owner"') || out.includes('"Name"'));
  }
});

test("findings: tags inside finding resources", async () => {
  stubFetch({ findings: { critical_risks: [{ rule_id: "R1", issue: "x", resource: { tags: { owner: V_OWNER }, Tags: [{ Key: "env", Value: V_ENV }] } }] }, infrastructure: {} });
  const out = textOf(await findingsHandler({ analysis_id: "a-1" } as any));
  assertMasked(out, [V_OWNER, V_ENV]);
});

test("a token read from output round-trips to the real value in a tag-setting branch change", async () => {
  const minted = redactDeep({ resource_id: "i-0123456789abcdef0", tags: { owner: V_OWNER, "aws:cloudformation:stack-name": V_AWS } }) as any;
  const tok = minted.tags.owner;
  assert.match(tok, /^TAG_\d{3}$/);
  const calls = stubFetch({ status: "applied" });
  await branches.applyChangeHandler({
    branch_id: "br-1", op: "modify", resource_type: "ec2_instance", resource_id: minted.resource_id,
    fields: { tags: { owner: tok, env: "brand-new-value", "aws:cloudformation:stack-name": minted.tags["aws:cloudformation:stack-name"] } },
  } as any);
  assert.equal(calls[0].body.resource_id, "i-0123456789abcdef0");
  assert.deepEqual(calls[0].body.fields.tags, { owner: V_OWNER, env: "brand-new-value", "aws:cloudformation:stack-name": V_AWS });
  assert.deepEqual(expandTokens({ Tags: [{ Key: "owner", Value: tok }] }), { Tags: [{ Key: "owner", Value: V_OWNER }] });
});

// Per-mode behaviour (fresh module instances; keep these last, they change HOME).
let n = 0;
async function loadMode(mode: "strict" | "balanced" | "off") {
  process.env.HOME = mkdtempSync(join(tmpdir(), "emfirge-tagmode-"));
  process.env.USERPROFILE = process.env.HOME;
  process.env.EMFIRGE_PRIVACY = mode;
  return (await import(`./tokenize.ts?tags=${mode}-${n++}`)) as typeof import("./tokenize.js");
}

test("balanced masks tag values like other names; keys stay readable", async () => {
  const t = await loadMode("balanced");
  const out = t.redactDeep({ tags: { owner: V_OWNER }, Tags: [{ Key: "env", Value: V_ENV }] }) as any;
  assert.match(out.tags.owner, /^TAG_\d{3}$/);
  assert.match(out.Tags[0].Value, /^TAG_\d{3}$/);
  assert.equal(out.Tags[0].Key, "env");
  assert.equal(t.expandTokens(out.tags.owner), V_OWNER);
});

test("off leaves tag values raw, as for other names", async () => {
  const t = await loadMode("off");
  const input = { tags: { owner: V_OWNER }, Tags: [{ Key: "env", Value: V_ENV }] };
  assert.deepEqual(t.redactDeep(input), input);
});
