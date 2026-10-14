import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-plan-verdict-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
delete process.env.EMFIRGE_API_KEY;

const { redactDeep } = await import("../tokenize.js");
const planVerdict = await import("./plan-verdict.js");

type Call = { method: string; url: string; body?: unknown };

function stubFetch(responses: Array<{ status?: number; body: unknown }>): Call[] {
  const calls: Call[] = [];
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

const ingest = {
  plan_id: "plan-1",
  input_sha256: "a".repeat(64),
  applied: ["aws_instance.web"],
  rejected: [],
  unmodeled: [],
  unknown_fields: [],
  branch_revision: "b".repeat(64),
};
const verdict = { verdict: "warn", reasons: [{ code: "example", level: "warn" }] };
const handback = {
  plan_id: "plan-1",
  input_sha256: "a".repeat(64),
  verdict_id: "c".repeat(64),
  branch_revision: "b".repeat(64),
  plan_text: '{"example":"value"}',
};

const cases = [
  ["terraform", "/branches/b1/plans/terraform", { format_version: "1.0" }],
  ["aws-api", "/branches/b1/plans/aws-api", { format: "aws-api-calls/1", calls: [] }],
  ["aws-cli", "/branches/b1/plans/aws-cli", ["aws ec2 stop-instances --instance-ids i-0123456789abcdef0"]],
  ["cloudformation", "/branches/b1/plans/cloudformation", { Changes: [] }],
] as const;

test("plan verdict posts each format to the matching route and orders ingest, verdict, handback", async () => {
  for (const [format, path, input] of cases) {
    const calls = stubFetch([{ body: ingest }, { body: verdict }, { body: handback }]);
    await planVerdict.planVerdictHandler({ branch_id: "b1", format, plan: input });
    assert.deepEqual(calls.map((call) => [call.method, call.url]), [
      ["POST", `http://stub.invalid/api${path}`],
      ["GET", "http://stub.invalid/api/branches/b1/verdict"],
      ["GET", "http://stub.invalid/api/branches/b1/plans/plan-1/handback"],
    ]);
    assert.deepEqual(calls[0].body, format === "aws-cli"
      ? { format: "aws-cli/1", commands: input }
      : input);
  }
});

test("plan verdict accepts a complete aws-cli document unchanged", async () => {
  const document = { format: "aws-cli/1", commands: ["aws s3api list-buckets"] };
  const calls = stubFetch([{ body: ingest }, { body: verdict }, { body: handback }]);
  await planVerdict.planVerdictHandler({ branch_id: "b1", format: "aws-cli", plan: document });
  assert.deepEqual(calls[0].body, document);
});

test("plan verdict expands privacy tokens in the input", async () => {
  const realId = "i-0123456789abcdef0";
  const token = (redactDeep({ instance_id: realId }) as { instance_id: string }).instance_id;
  const calls = stubFetch([{ body: ingest }, { body: verdict }, { body: handback }]);
  await planVerdict.planVerdictHandler({
    branch_id: "b1", format: "aws-cli", plan: [`aws ec2 stop-instances --instance-ids ${token}`],
  });
  assert.equal((calls[0].body as { commands: string[] }).commands[0].includes(realId), true);
  assert.equal((calls[0].body as { commands: string[] }).commands[0].includes(token), false);
});

test("plan verdict returns the ingest, verdict, and handback result", async () => {
  stubFetch([{ body: ingest }, { body: verdict }, { body: handback }]);
  const result = JSON.parse(textOf(await planVerdict.planVerdictHandler({
    branch_id: "b1", format: "terraform", plan: { format_version: "1.0" },
  })));
  assert.deepEqual(result, {
    plan_id: ingest.plan_id,
    input_sha256: ingest.input_sha256,
    applied: ingest.applied,
    rejected: ingest.rejected,
    unmodeled: ingest.unmodeled,
    unknown_fields: ingest.unknown_fields,
    verdict: { decision: "warn", reasons: verdict.reasons },
    verdict_id: handback.verdict_id,
    branch_revision: handback.branch_revision,
    handback,
  });
});

test("plan verdict surfaces backend validation detail", async () => {
  stubFetch([{ status: 422, body: { detail: "Invalid AWS CLI commands document" } }]);
  await assert.rejects(
    () => planVerdict.planVerdictHandler({ branch_id: "b1", format: "aws-cli", plan: [] }),
    /Invalid AWS CLI commands document/,
  );
});
