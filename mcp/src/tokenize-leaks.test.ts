// L81: privacy leaks found by an audit of MCP/CLI output. Each law goes through the real
// redaction path (redactDeep, the MCP handlers, runCli) with planted values.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-leaks-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";

const { redactDeep } = await import("./tokenize.js");
const branches = await import("./tools/branches.js");
const check = await import("./tools/check.js");
const { runCli } = await import("./cli/run.js");

function stubFetch(body: unknown, status = 200): void {
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })) as typeof fetch;
}
const textOf = (r: { content: Array<{ text: string }> }) => r.content.map((p) => p.text).join("\n");
const TOKEN = /^[A-Z0-9_]+_\d{3}$/;

const ACCOUNT = "483920174455";
const ALIAS = "shop.acme-internal.example.com";
const ORIGIN = "orders-origin.acme-internal.example.net";
const WAF = `arn:aws:wafv2:us-east-1:${ACCOUNT}:global/webacl/acme-edge-acl/6f1d2c3b-aaaa-bbbb-cccc-0123456789ab`;
const SQS = `arn:aws:sqs:eu-west-1:${ACCOUNT}:acme-billing-dlq`;
const SNS = `arn:aws:sns:eu-west-1:${ACCOUNT}:acme-alerts-topic`;
const DDB = `arn:aws:dynamodb:eu-west-1:${ACCOUNT}:table/acme-orders-table`;
const SCHED = `arn:aws:scheduler:eu-west-1:${ACCOUNT}:schedule/default/acme-nightly-close`;
const CF = `arn:aws:cloudfront::${ACCOUNT}:distribution/E2ACMESECRET01`;
const OAC = "E3OACSECRETID99";
const CACHE_POLICY = "9b8a7c6d-1111-2222-3333-acmecustom0001";
const MANAGED = "658327ea-f89d-4fab-a63d-7e88639e58f6";
const PATTERN = "/acme-internal-admin/*";

function leaked(out: string, values: string[]): string[] {
  return values.filter((v) => out.includes(v));
}

test("L81a branch diff masks the before/after values of changed fields", async () => {
  const diff = {
    resources_modified: [
      {
        id: "E2ACMESECRET01", resource_type: "cloudfront_distribution",
        changed: ["base.aliases", "base.web_acl_id", "base.origins", "base.behaviors"],
        values: {
          "base.enabled": { before: true, after: false },
          "base.aliases": { before: [ALIAS], after: [] },
          "base.web_acl_id": { before: WAF, after: null },
          "base.origins": {
            before: [{ id: "orders", domain_name: ORIGIN, origin_type: "custom", origin_access_control_id: OAC, s3_bucket: null }],
            after: [],
          },
          "base.behaviors": {
            before: [{ path_pattern: PATTERN, target_origin_id: "orders", cache_policy_id: CACHE_POLICY, origin_request_policy_id: MANAGED }],
            after: [{ path_pattern: PATTERN, target_origin_id: "orders", cache_policy_id: MANAGED, origin_request_policy_id: null }],
          },
        },
      },
      {
        id: "default/acme-nightly-close", resource_type: "scheduler_schedule",
        changed: ["base.target_arn", "base.target_role_arn"],
        values: {
          "base.state": { before: "ENABLED", after: "DISABLED" },
          "base.target_arn": { before: SQS, after: SNS },
          "base.target_role_arn": { before: `arn:aws:iam::${ACCOUNT}:role/AcmeSchedulerRole`, after: null },
        },
      },
    ],
  };
  stubFetch(diff);
  const out = textOf(await branches.branchDiffHandler({ branch_id: "b1" }));
  assert.deepEqual(leaked(out, [ALIAS, ORIGIN, WAF, SQS, SNS, OAC, CACHE_POLICY, MANAGED, PATTERN, ACCOUNT, "acme-"]), []);
  const parsed = JSON.parse(out).resources_modified;
  // non-identifier values stay readable
  assert.deepEqual(parsed[0].values["base.enabled"], { before: true, after: false });
  assert.deepEqual(parsed[1].values["base.state"], { before: "ENABLED", after: "DISABLED" });
  // masked values are tokens; the same value gets the same token
  const behaviors = parsed[0].values["base.behaviors"];
  assert.match(parsed[0].values["base.web_acl_id"].before, TOKEN);
  assert.match(behaviors.before[0].cache_policy_id, TOKEN);
  assert.equal(behaviors.after[0].cache_policy_id, behaviors.before[0].origin_request_policy_id);
  assert.equal(parsed[0].values["base.web_acl_id"].after, null);
});

test("L81b emfirge_check masks path_pattern", async () => {
  stubFetch({
    branch_id: "b1",
    answers: [{ damage: "exposure", facts: [{ resource_id: "E2ACMESECRET01", resource_ids: [], path_pattern: PATTERN, cache_policy_id: CACHE_POLICY }], checked: [], unknown: [] }],
  });
  const out = textOf(await check.checkHandler({ branch_id: "b1" }));
  assert.deepEqual(leaked(out, [PATTERN, "acme-internal-admin", CACHE_POLICY]), []);
  const fact = JSON.parse(out).answers[0].facts[0];
  assert.match(fact.path_pattern, TOKEN);
});

test("L81c ARNs of dynamodb, sqs, sns, scheduler, cloudfront, wafv2 and bare account ids are masked in prose", () => {
  for (const arn of [WAF, SQS, SNS, DDB, SCHED, CF]) {
    const out = JSON.stringify(redactDeep({ note: `Change touches ${arn}.` }));
    assert.deepEqual(leaked(out, [arn, ACCOUNT]), [], arn);
  }
  const prose = JSON.stringify(redactDeep({ note: `Owned by account ${ACCOUNT}, shared with (${ACCOUNT}).` }));
  assert.equal(prose.includes(ACCOUNT), false);
  const typed = redactDeep({ list: [SQS, WAF] }) as { list: string[] };
  assert.match(typed.list[0], /^SQS_\d{3}$/);
  assert.match(typed.list[1], /^WAFV2_\d{3}$/);
});

test("L81c the account-id rule leaves timestamps, ports, versions and longer numbers alone", () => {
  const safe = [
    "scanned at 2026-11-08T12:34:56Z on port 8443",
    "epoch 1762605296123 and 20261108123456 and 1234567890123",
    "version 3.123456789012 and sg-123456789012x and 1234567890123456",
    "build 12345678901 done",
  ];
  for (const s of safe) assert.equal((redactDeep({ note: s }) as { note: string }).note, s, s);
});

test("L81d CLI usage errors are redacted", async () => {
  const bucket = "arn:aws:s3:::zz-planted-bucket-7731";
  const sg = "sg-0abc123def4567890";
  const cases: string[][] = [[bucket], ["check", `--${sg}`], ["help", sg], ["branch", bucket]];
  for (const argv of cases) {
    for (const human of [false, true]) {
      let stderr = "";
      const code = await runCli(human ? [...argv, "--human"] : argv, {
        out: () => {}, err: (s) => { stderr += s; },
        readFile: () => { throw new Error("x"); }, readStdin: async () => "",
      });
      assert.equal(code, 1, argv.join(" "));
      assert.deepEqual(leaked(stderr, [bucket, "zz-planted-bucket-7731", sg]), [], `${argv.join(" ")} (human=${human}): ${stderr}`);
    }
  }
});
