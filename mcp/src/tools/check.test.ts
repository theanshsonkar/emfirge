// emfirge_check: GET /branches/{id}/check, tokens expanded going out, ids masked coming back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-check-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";

const { redactDeep } = await import("../tokenize.js");
const { tools } = await import("../tools-registry.js");
const check = await import("./check.js");

type Call = { method: string; url: string };
function stubFetch(body: unknown, status = 200): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(url) });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}
const text = (r: { content: Array<{ text: string }> }) => r.content.map((c) => c.text).join("\n");

const SG = "sg-0123456789abcdef0";
const BUCKET = "acme-secret-payroll-bucket";
const ROLE = "arn:aws:iam::123456789012:role/AcmeDeployRole";
const DAMAGES = ["data", "exposure", "money", "availability", "control", "outside_world"];

const reply = {
  branch_id: "b1", base_analysis_id: "a1", branch_revision: "r".repeat(64),
  changes: [{ change: "added", resource_ids: [] }, { change: "removed", resource_ids: [BUCKET] }, { change: "modified", resource_ids: [SG] }],
  answers: DAMAGES.map((damage) => ({
    damage,
    facts:
      damage === "data" ? [{ resource_id: BUCKET, resource_type: "s3_bucket", change: "deleted", has_recovery_point: false, recovery_resource_ids: [ROLE] }]
      : damage === "exposure" ? [{ resource_id: SG, resource_type: "security_group", source: BUCKET, resource_ids: [SG], path: [SG, BUCKET] }]
      : damage === "outside_world" ? [{ action: "ses.SendEmail", service: "Amazon SES", source_url: "https://docs.aws.amazon.com/ses/latest/dg/", resource_id: ROLE }]
      : [],
    checked: ["x"], unknown: [],
  })),
  baseline: null,
};

test("registry lists emfirge_check with a plain description", () => {
  const t = tools.find((x) => x.name === "emfirge_check");
  assert.ok(t);
  assert.match(t!.description, /unknown means not checked, never safe/i);
});

test("check requests GET /branches/{id}/check", async () => {
  const calls = stubFetch(reply);
  await check.checkHandler({ branch_id: "b1" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "GET");
  assert.ok(calls[0].url.endsWith("/branches/b1/check"), calls[0].url);
});

test("check expands a tokenized branch id", async () => {
  const real = "branch/with space";
  const minted = redactDeep({ node_id: real }) as { node_id: string };
  assert.notEqual(minted.node_id, real);
  const calls = stubFetch(reply);
  await check.checkHandler({ branch_id: minted.node_id });
  assert.ok(calls[0].url.endsWith(`/branches/${encodeURIComponent(real)}/check`), calls[0].url);
});

test("check masks planted ids in facts and keeps outside_world readable", async () => {
  stubFetch(reply);
  const out = text(await check.checkHandler({ branch_id: "b1" }));
  for (const planted of [SG, BUCKET, ROLE]) assert.equal(out.includes(planted), false, planted);
  const parsed = JSON.parse(out);
  assert.deepEqual(parsed.answers.map((a: { damage: string }) => a.damage), DAMAGES);
  const ow = parsed.answers[5].facts[0];
  assert.equal(ow.action, "ses.SendEmail");
  assert.equal(ow.service, "Amazon SES");
  assert.equal(ow.source_url, "https://docs.aws.amazon.com/ses/latest/dg/");
  assert.notEqual(ow.resource_id, ROLE);
  const data = parsed.answers[0].facts[0];
  assert.notEqual(data.resource_id, BUCKET);
  assert.notEqual(data.recovery_resource_ids[0], ROLE);
  const exp = parsed.answers[1].facts[0];
  assert.notEqual(exp.source, BUCKET);
  assert.notEqual(exp.path[0], SG);
  assert.notEqual(exp.path[1], BUCKET);
  assert.notEqual(exp.resource_ids[0], SG);
  assert.notEqual(parsed.changes[1].resource_ids[0], BUCKET);
});

test("check error message is redacted", async () => {
  stubFetch({ detail: `branch ${SG} not found` }, 404);
  await assert.rejects(check.checkHandler({ branch_id: "b1" }), (e: Error) => !e.message.includes(SG));
});

test("check masks the resource id of a changed setting and keeps the field name readable", async () => {
  const fields = ["web_acl_id", "role_arn", "instance_profile_arn", "target_role_arn", "name", "aliases", "imdsv2_required", "tags", "rules", "policy"];
  stubFetch({
    ...reply,
    changed_settings: fields.map((field) => ({
      resource_id: SG, resource_type: "security_group", field, judged: field === "rules", judged_by: field === "rules" ? ["exposure"] : [],
    })),
  });
  const out = text(await check.checkHandler({ branch_id: "b1" }));
  assert.equal(out.includes(SG), false);
  const parsed = JSON.parse(out);
  assert.deepEqual(parsed.changed_settings.map((s: { field: string }) => s.field), fields);
  for (const s of parsed.changed_settings) {
    assert.notEqual(s.resource_id, SG);
    assert.equal(s.resource_type, "security_group");
  }
  assert.deepEqual(parsed.changed_settings.find((s: { field: string }) => s.field === "rules").judged_by, ["exposure"]);
});
