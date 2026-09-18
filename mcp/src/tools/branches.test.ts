// Regression tests for the branch tools' privacy + token contract.
//
// Two bugs shipped in 0.2.2 and this suite exists so they cannot come back:
//
//   1. `applyChangeHandler` passed the caller's resource_id straight through, so
//      a tokenized id from emfirge_scan (SG_001) reached the backend verbatim
//      and came back "Target not found" — the branch tools could not act on any
//      id an agent actually had.
//   2. None of the eight handlers ran their response through redactDeep, so
//      branch_verdict returned raw instance ids, security-group ids, bucket
//      names and role ARNs regardless of EMFIRGE_PRIVACY.
//
// Both are wrapper-level, so these tests stub global fetch (which backendCall
// uses underneath) and assert on what crosses the wrapper boundary, rather than
// standing up a real branch.
//
// IMPORTANT — module instancing. branches.ts imports "../tokenize.js", and
// tokenize.ts reads EMFIRGE_PRIVACY and HOME once at import time. So the env
// must be set BEFORE the first import below, and this file must share the very
// same tokenize instance branches.ts uses — a cache-busting query here would
// give us a second instance with its own empty token map, and a token minted in
// it would be invisible to the code under test. Per-mode behaviour is covered in
// tokenize.test.ts; this file stays in strict mode throughout.
//
// Run with: npm test  (node --import tsx --test)

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// --- must happen before the two imports below ---
const home = mkdtempSync(join(tmpdir(), "emfirge-branch-"));
process.env.HOME = home;
process.env.USERPROFILE = home; // Windows homedir()
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
delete process.env.EMFIRGE_API_KEY;

const { redactDeep } = await import("../tokenize.js");
const branches = await import("./branches.js");

type Call = { method: string; url: string; body?: unknown };

// Point global fetch at a canned response and capture what was sent.
function stubFetch(backendResponse: unknown): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      method: init?.method ?? "GET",
      url: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    return new Response(JSON.stringify(backendResponse), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return calls;
}

function textOf(result: { content: Array<{ text: string }> }): string {
  return result.content.map((part) => part.text).join("\n");
}

// ---------------------------------------------------------------------------
// Bug 1 — tokenized ids must be expanded before they reach the backend.
// ---------------------------------------------------------------------------

test("apply_change expands a tokenized resource_id to the real AWS id", async () => {
  const realSg = "sg-0123456789abcdef0";

  // Mint the token the way a scan response would, then hand the token back in
  // as an agent would after reading a scan.
  const minted = redactDeep({ group_id: realSg }) as { group_id: string };
  assert.notEqual(minted.group_id, realSg, "precondition: id should tokenize");

  const calls = stubFetch({ status: "applied" });

  await branches.applyChangeHandler({
    branch_id: "b1",
    op: "modify",
    resource_type: "security_group",
    resource_id: minted.group_id,
    fields: { rules: [] },
  });

  assert.equal(calls.length, 1);
  const body = calls[0].body as { resource_id: string };
  assert.equal(
    body.resource_id,
    realSg,
    `backend received "${body.resource_id}" — the token was not expanded, so the ` +
      `branch engine would answer "Target not found"`,
  );
});

test("apply_change expands tokenized ids nested inside fields", async () => {
  const realSg = "sg-059631727117595f4";
  const minted = redactDeep({ group_id: realSg }) as { group_id: string };

  const calls = stubFetch({ status: "applied" });

  await branches.applyChangeHandler({
    branch_id: "b1",
    op: "modify",
    resource_type: "ec2_instance",
    resource_id: "i-real",
    fields: { security_groups: [minted.group_id] },
  });

  const body = calls[0].body as { fields: { security_groups: string[] } };
  assert.deepEqual(
    body.fields.security_groups,
    [realSg],
    "tokens nested in fields must expand too, not just the top-level id",
  );
});

// ---------------------------------------------------------------------------
// Bug 2 — every handler's output must go through redactDeep.
// ---------------------------------------------------------------------------

test("every branch handler redacts real identifiers out of its response", async () => {
  // Shaped like a real branch_verdict body, which is where the leak surfaced.
  const raw = {
    verdict: "pass",
    instance_id: "i-0123456789abcdef0",
    group_id: "sg-066a7e4eecc6f5e86",
    bucket_name: "example-bucket-123456789012",
    role_arn: "arn:aws:iam::123456789012:role/EmfirgeReadOnlyRole",
  };
  const leaks = Object.values(raw).filter((v) => v !== "pass");

  const handlers: Array<[string, (args: never) => Promise<unknown>]> = [
    ["createBranchHandler", branches.createBranchHandler],
    ["applyChangeHandler", branches.applyChangeHandler],
    ["branchDiffHandler", branches.branchDiffHandler],
    ["branchVerdictHandler", branches.branchVerdictHandler],
    ["rollbackBranchHandler", branches.rollbackBranchHandler],
    ["discardBranchHandler", branches.discardBranchHandler],
    ["listBranchesHandler", branches.listBranchesHandler],
    ["compareBranchesHandler", branches.compareBranchesHandler],
  ];

  // One arg bag that satisfies all eight schemas; extra keys are ignored.
  const args = {
    branch_id: "b1",
    base_analysis_id: "a1",
    name: "t",
    op: "modify",
    resource_type: "security_group",
    resource_id: "sg-deadbeef",
    fields: {},
    branch_ids: ["b1"],
  } as never;

  for (const [name, handler] of handlers) {
    stubFetch(raw);
    const text = textOf(
      (await handler(args)) as { content: Array<{ text: string }> },
    );
    for (const leak of leaks) {
      assert.ok(
        !text.includes(leak),
        `LEAK from ${name}: raw value "${leak}" survived redaction`,
      );
    }
  }
});
