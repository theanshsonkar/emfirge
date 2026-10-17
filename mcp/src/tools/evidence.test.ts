import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-evidence-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

type Call = { method: string; url: string; body?: unknown };
const evidence = await import("./evidence.js");

function stubFetch(body: unknown, status = 200): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(url), body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}

function output(result: { content: Array<{ text: string }> }): Record<string, any> {
  return JSON.parse(result.content[0].text);
}

const estimate = {
  estimate_id: "a".repeat(64), branch_revision: "b".repeat(64), window_days: 90,
  sources: ["cloudtrail_events", "cloudwatch_metrics"],
  resources: [{ resource_type: "ec2_instance", resource_id: "i-0123456789abcdef0", sources: ["cloudtrail_events"] }],
  calls: [{ source: "cloudtrail_events", api: "LookupEvents", max_requests: 1, billable: false, note: "free", pricing_url: "https://example.invalid" }],
};

test("estimate-first calls GET with sources and next step", async () => {
  const calls = stubFetch(estimate);
  const roleArn = "arn:aws:iam::123456789012:role/EstimateOnlyRole";
  const result = await evidence.inUseEvidenceHandler({ branch_id: "branch/one", sources: ["cloudtrail_events", "cloudwatch_metrics"], role_arn: roleArn });
  assert.deepEqual(calls[0], { method: "GET", url: "http://stub.invalid/api/branches/branch%2Fone/in-use-evidence/estimate?sources=cloudtrail_events%2Ccloudwatch_metrics", body: undefined });
  assert.equal(output(result).next_step, "Show this estimate to the user. Call again with accept_estimate_id only after the user agrees.");
  assert.notEqual(output(result).resources[0].resource_id, "i-0123456789abcdef0");
});

test("accepted estimate requires role ARN before backend calls", async () => {
  const calls = stubFetch({});
  await assert.rejects(
    evidence.inUseEvidenceHandler({ branch_id: "b1", sources: ["cloudwatch_metrics"], accept_estimate_id: "a".repeat(64) }),
    { message: "role_arn is required with accept_estimate_id (use the same role ARN as emfirge_scan)" },
  );
  assert.equal(calls.length, 0);
});

test("accepted estimate posts the exact body and never returns the role ARN", async () => {
  const roleArn = "arn:aws:iam::123456789012:role/EmfirgeReadOnly";
  const calls = stubFetch({ estimate_id: "a".repeat(64), observed_at: "2026-01-01T00:00:00Z", role_arn: roleArn, window_days: 90, records: [] });
  const result = await evidence.inUseEvidenceHandler({ branch_id: "b1", sources: ["cloudwatch_metrics"], role_arn: roleArn, accept_estimate_id: "a".repeat(64) });
  assert.deepEqual(calls[0], { method: "POST", url: "http://stub.invalid/api/branches/b1/in-use-evidence", body: { role_arn: roleArn, sources: ["cloudwatch_metrics"], accept_estimate_id: "a".repeat(64) } });
  assert.equal(result.content[0].text.includes(roleArn), false);
});

test("invalid sources and estimate ids are rejected before backend calls", () => {
  assert.throws(() => evidence.inUseEvidenceZodObject.parse({ branch_id: "b1", sources: ["not-a-source"] }));
  assert.throws(() => evidence.inUseEvidenceZodObject.parse({ branch_id: "b1", accept_estimate_id: "bad" }));
});

test("409 returns the replacement estimate and next step", async () => {
  const replacement = { ...estimate, estimate_id: "c".repeat(64) };
  const calls = stubFetch({ detail: "Estimate changed", estimate: replacement }, 409);
  const result = await evidence.inUseEvidenceHandler({ branch_id: "b1", sources: ["cloudtrail_events"], role_arn: "arn:aws:iam::123456789012:role/EmfirgeReadOnly", accept_estimate_id: "a".repeat(64) });
  assert.equal(calls.length, 1);
  const body = output(result);
  assert.equal(body.detail, "Estimate changed");
  assert.equal(body.next_step, "Show this estimate to the user. Call again with accept_estimate_id only after the user agrees.");
  assert.notEqual(body.estimate.resources[0].resource_id, "i-0123456789abcdef0");
});
