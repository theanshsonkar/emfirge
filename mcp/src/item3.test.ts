import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-item3-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";

const { formatToolError } = await import("./tool-error.js");
const client = await import("./client.js");
const branches = await import("./tools/branches.js");
const plan = await import("./tools/plan-verdict.js");
const registry = await import("./tools-registry.js");

function stubFetch(responses: Array<{ status?: number; body: unknown }>) {
  const calls: Array<{ method: string; url: string; body?: unknown }> = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      method: init?.method ?? "GET",
      url: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
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

test("T1 Zod errors are readable and non-JSON", async () => {
  const error = textOf(await registry.dispatchTool("emfirge_apply_change", {}));
  const planError = textOf(await registry.dispatchTool("emfirge_plan_verdict", {
    branch_id: "b1", format: "wrong", plan: {},
  }));
  assert.match(error, /^Error: Invalid input/);
  assert.match(planError, /^Error: Invalid input/);
  assert.match(`${error} ${planError}`, /branch_id/);
  assert.match(`${error} ${planError}`, /format/);
  assert.doesNotMatch(`${error} ${planError}`, /"code"|\[\{|invalid_type/);
});

test("T2 Pydantic array detail is readable, redacted, and capped", () => {
  const detail = Array.from({ length: 7 }, (_, i) => ({
    loc: ["body", "calls", i, "service"], msg: "Field required", type: "missing",
    input: { secret: "s3cr3t-value" },
  }));
  const message = client.extractDetail(JSON.stringify({ detail }));
  assert.equal(message, "calls.0.service: Field required; calls.1.service: Field required; calls.2.service: Field required; calls.3.service: Field required; calls.4.service: Field required (+2 more)");
  assert.doesNotMatch(message!, /"loc"|type|s3cr3t-value/);
});

test("T3 target-not-found names the agent token, not the real id", async () => {
  const { redactDeep } = await import("./tokenize.js");
  const token = (redactDeep({ group_id: "sg-0abc123real" }) as { group_id: string }).group_id;
  assert.equal(token, "SG_001");
  stubFetch([{ status: 422, body: { detail: "Target not found: security_group" } }]);
  await assert.rejects(
    () => branches.applyChangeHandler({ branch_id: "b1", op: "modify", resource_type: "security_group", resource_id: token, fields: {} }),
    (error: Error) => error.message.includes("(target: SG_001)") && !error.message.includes("sg-0abc123real"),
  );
});

test("T4 compare branches is registered and posts the expected body", async () => {
  const tool = registry.tools.find((entry) => entry.name === "emfirge_compare_branches");
  assert.ok(tool);
  assert.ok(tool.description.length > 0);
  const calls = stubFetch([{ body: { comparisons: [] } }]);
  await tool.handler({ branch_ids: ["a", "b"] });
  assert.deepEqual(calls[0], {
    method: "POST", url: "http://stub.invalid/api/branches/compare", body: { branch_ids: ["a", "b"] },
  });
});

test("T5 plan verdict documents accepted input shapes", () => {
  const tool = registry.tools.find((entry) => entry.name === "emfirge_plan_verdict");
  assert.ok(tool);
  for (const phrase of ["aws-api-calls/1", "calls", "service", "operation", "parameters", "aws-cli/1", "commands", "authorize-security-group-ingress --group-id"]) {
    assert.match(tool.description, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});
