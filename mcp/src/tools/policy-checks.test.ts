import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-policy-checks-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

type Call = { method: string; url: string; body?: unknown };
const pc = await import("./policy-checks.js");

function stubFetch(body: unknown, status = 200): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method ?? "GET", url: String(url), body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return calls;
}

test("without approve it only calls the estimate endpoint", async () => {
  const calls = stubFetch({ estimate_id: "a".repeat(64), call_count: 1, policies: [] });
  const result = await pc.policyChecksHandler({ branch_id: "b/1" });
  assert.deepEqual(calls, [{ method: "GET", url: "http://stub.invalid/api/branches/b%2F1/policy-checks/estimate", body: undefined }]);
  assert.match(result.content[0].text, /next_step/);
});

test("approve needs role_arn and estimate id before any backend call", async () => {
  const calls = stubFetch({});
  await assert.rejects(pc.policyChecksHandler({ branch_id: "b1", approve: true }));
  assert.equal(calls.length, 0);
});

test("approve posts the exact body", async () => {
  const roleArn = "arn:aws:iam::123456789012:role/EmfirgeReadOnly";
  const calls = stubFetch({ records: [] });
  await pc.policyChecksHandler({ branch_id: "b1", approve: true, role_arn: roleArn, accept_estimate_id: "a".repeat(64) });
  assert.deepEqual(calls[0], { method: "POST", url: "http://stub.invalid/api/branches/b1/policy-checks", body: { role_arn: roleArn, approve: true, accept_estimate_id: "a".repeat(64) } });
});
