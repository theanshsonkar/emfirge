// Tests for presigned-URL credential scrubbing.
//
// emfirge_scan returns a `report_url` — a SigV4 presigned S3 URL. Its query
// string carries an access-key id (X-Amz-Credential), the signature, and
// sometimes a full STS session token. Before this, none of those were touched
// by the tokenizer: the layer whose entire job is catching credential-shaped
// material passed a bearer credential straight to the host LLM.
//
// Note the mode matrix. Resource-name tokenization is correctly disabled by
// EMFIRGE_PRIVACY=off — that is the user asking to see their own ids. Credential
// scrubbing is NOT, because opting out of tokenizing your bucket names is not
// the same as asking for your access keys back.
//
// Run with: npm test  (node --import tsx --test)

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type TokenizeModule = typeof import("./tokenize.js");

let counter = 0;
async function load(mode: "strict" | "balanced" | "off"): Promise<TokenizeModule> {
  const home = mkdtempSync(join(tmpdir(), "emfirge-url-"));
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.env.EMFIRGE_PRIVACY = mode;
  return import(`./tokenize.ts?v=url-${mode}-${counter++}`);
}

// A realistic presigned report URL, shaped like the one emfirge_scan returns.
const ACCESS_KEY = "AKIAUDKRKJOBVFIPDMNC";
const SIGNATURE = "ee558f7a5352e71641f92914ad41bbb0d621e9984df038bea78624942fceb18d";
const SESSION_TOKEN = "FwoGZXIvYXdzEBYaDExAMPLESESSIONTOKEN";
const PRESIGNED =
  "https://emfirge-reports.s3.amazonaws.com/reports/2026-09-18/analysis-abc.json" +
  `?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${ACCESS_KEY}%2F20260918%2Fap-south-1%2Fs3%2Faws4_request` +
  `&X-Amz-Date=20260918T114749Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=${SIGNATURE}` +
  `&X-Amz-Security-Token=${SESSION_TOKEN}`;

for (const mode of ["strict", "balanced", "off"] as const) {
  test(`${mode}: presigned URL credentials are scrubbed`, async () => {
    const t = await load(mode);
    const out = JSON.stringify(t.redactDeep({ report_url: PRESIGNED }));

    assert.ok(!out.includes(ACCESS_KEY), `LEAK: access key id survived in ${mode}`);
    assert.ok(!out.includes(SIGNATURE), `LEAK: signature survived in ${mode}`);
    assert.ok(!out.includes(SESSION_TOKEN), `LEAK: session token survived in ${mode}`);
    assert.ok(out.includes("REDACTED"), "the credential params should be marked, not dropped");
  });
}

test("off: the URL stays diagnosable — only credentials are removed", async () => {
  const t = await load("off");
  const out = t.redactDeep({ report_url: PRESIGNED }) as { report_url: string };

  // Non-credential parts are preserved so a human can still tell what the URL
  // was and why it failed.
  assert.ok(out.report_url.includes("X-Amz-Expires=3600"), "expiry should survive");
  assert.ok(out.report_url.includes("X-Amz-Date=20260918T114749Z"), "date should survive");
  assert.ok(out.report_url.startsWith("https://emfirge-reports.s3.amazonaws.com/"), "host/path survive in off mode");
});

test("off still does NOT tokenize ordinary resource ids", async () => {
  // Guards against over-correction: credential scrubbing must not quietly turn
  // privacy=off into privacy=on for everything else.
  const t = await load("off");
  const out = t.redactDeep({ instance_id: "i-0c0ca7da0c26cc0fa" }) as {
    instance_id: string;
  };
  assert.equal(out.instance_id, "i-0c0ca7da0c26cc0fa");
});

test("a plain URL with no signature is left completely alone", async () => {
  const t = await load("strict");
  const plain = "https://docs.emfirge.cloud/guide?page=2&sort=asc";
  const out = t.redactDeep({ docs_url: plain }) as { docs_url: string };
  assert.equal(out.docs_url, plain);
});

test("credentials are scrubbed even when the URL is embedded in prose", async () => {
  const t = await load("strict");
  const prose = `Report ready, fetch it from ${PRESIGNED} within the hour.`;
  const out = JSON.stringify(t.redactDeep({ message: prose }));
  assert.ok(!out.includes(ACCESS_KEY), "LEAK: access key survived inside a narrative string");
  assert.ok(!out.includes(SIGNATURE), "LEAK: signature survived inside a narrative string");
});
