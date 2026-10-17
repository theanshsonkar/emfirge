import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-branch-handback-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";

const handback = await import("./branch-handback.js");

type Call = { method: string; url: string; body?: unknown; headers?: Headers };

function stubFetch(responses: Array<{ status?: number; body: unknown }>): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      method: init?.method ?? "GET",
      url: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
      headers: new Headers(init?.headers),
    });
    const response = responses.shift() ?? { body: {} };
    return new Response(JSON.stringify(response.body), {
      status: response.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return calls;
}

function textOf(result: { content: Array<{ text: string }> }): string {
  return result.content.map((part) => part.text).join("\n");
}

const calls = [{
  change_index: 0,
  service: "ec2",
  operation: "DeleteVolume",
  params: { VolumeId: "vol-0123456789abcdef0" },
}];
const binding = {
  input_sha256: "a".repeat(64),
  base_analysis_id: "analysis-1",
  branch_revision: "b".repeat(64),
  verdict_id: "c".repeat(64),
};
const response = { branch_id: "branch-1", kind: "aws-api-calls", calls, ...binding, verdict: "pass" };

test("branch handback returns calls and binding with auth and redaction", async () => {
  const fetchCalls = stubFetch([{ body: response }]);
  const result = JSON.parse(textOf(await handback.branchHandbackHandler({ branch_id: "branch-1" })));
  assert.deepEqual(result.input_sha256, binding.input_sha256);
  assert.deepEqual(result.calls[0].params.VolumeId, "VOL_001");
  assert.equal(JSON.stringify(result).includes("vol-0123456789abcdef0"), false);
  assert.deepEqual(fetchCalls.map((call) => [call.method, call.url]), [["GET", "http://stub.invalid/api/branches/branch-1/handback"]]);
  assert.equal(fetchCalls[0].headers?.get("authorization"), "Bearer synthetic-test-api-key");
});

test("branch handback verifies using the returned calls body", async () => {
  const fetchCalls = stubFetch([{ body: response }, { body: { ok: true, verdict: "pass", verdict_id: binding.verdict_id } }]);
  const result = JSON.parse(textOf(await handback.branchHandbackHandler({ branch_id: "branch-1", verify: true })));
  assert.deepEqual(result.verification, { ok: true, verdict: "pass", verdict_id: binding.verdict_id });
  assert.deepEqual(fetchCalls[1].body, response);
});

test("branch handback surfaces unmappable gaps without partial calls", async () => {
  stubFetch([{ status: 422, body: { error: "unmappable_changes", changes: [{ change_index: 2, reason: "resource_not_found", resource_id: "vol-0123456789abcdef0" }] } }]);
  await assert.rejects(
    () => handback.branchHandbackHandler({ branch_id: "branch-1" }),
    /unmappable_changes.*resource_not_found/,
  );
});

test("branch handback preserves 409 mismatch mapping without resource data", async () => {
  stubFetch([{ status: 409, body: { ok: false, reason_code: "branch_revision_changed" } }]);
  await assert.rejects(
    () => handback.branchHandbackHandler({ branch_id: "branch-1" }),
    /Backend 409 on \/branches\/branch-1\/handback/,
  );
});

test("branch handback maps 401 and never exposes the token", async () => {
  stubFetch([{ status: 401, body: { detail: "invalid token" } }]);
  await assert.rejects(
    () => handback.branchHandbackHandler({ branch_id: "branch-1" }),
    (error: unknown) => {
      assert.match(String(error), /Backend 401/);
      assert.equal(String(error).includes("synthetic-test-api-key"), false);
      assert.equal(String(error).includes("invalid token"), true);
      return true;
    },
  );
});
