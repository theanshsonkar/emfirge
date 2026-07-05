// Tests for the tokenization layer — the core privacy guarantee.
//
// The nightmare this suite guards against: a real AWS identifier slipping past
// redactDeep and reaching the host LLM. Every test that redacts something also
// asserts the raw value is GONE from the output.
//
// tokenize.ts reads EMFIRGE_PRIVACY and HOME at import time and persists the
// token map to $HOME/.emfirge/tokens.json. So each `load()` gets:
//   - a unique temp HOME  -> a pristine, empty token store (deterministic _001)
//   - the desired privacy mode
//   - a cache-busting query -> a genuinely fresh module instance
// Run with: npm test  (node --import tsx --test)

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

type TokenizeModule = typeof import("./tokenize.js");

let counter = 0;
async function load(mode: "strict" | "balanced" | "off"): Promise<TokenizeModule> {
  const home = mkdtempSync(join(tmpdir(), "emfirge-tok-"));
  process.env.HOME = home;
  process.env.USERPROFILE = home; // Windows homedir()
  process.env.EMFIRGE_PRIVACY = mode;
  return import(`./tokenize.ts?v=${mode}-${counter++}`);
}

// Assert a serialized blob contains none of the given raw values.
function assertNoLeak(blob: unknown, rawValues: string[]): void {
  const text = typeof blob === "string" ? blob : JSON.stringify(blob);
  for (const raw of rawValues) {
    assert.ok(!text.includes(raw), `LEAK: raw value "${raw}" survived redaction in: ${text}`);
  }
}

// ---------------------------------------------------------------------------
// STRICT MODE — the default. Every AWS identifier must be tokenized.
// ---------------------------------------------------------------------------

test("strict: whole-string IDs tokenize with the right prefix", async () => {
  const t = await load("strict");
  const cases: Array<[string, RegExp]> = [
    ["sg-0a1b2c3d4e5f", /^SG_\d{3}$/],
    ["i-0c0c1234abcd5678", /^EC2_\d{3}$/],
    ["eipalloc-0a1b2c3d", /^EIP_\d{3}$/],
    ["vol-0a1b2c3d4e5f", /^VOL_\d{3}$/],
    ["subnet-0a1b2c3d", /^SUBNET_\d{3}$/],
    ["vpc-0a1b2c3d", /^VPC_\d{3}$/],
    ["arn:aws:iam::123456789012:role/AdminRole", /^IAM_ROLE_\d{3}$/],
    ["arn:aws:iam::123456789012:user/ansh", /^IAM_USER_\d{3}$/],
    ["arn:aws:s3:::acme-customer-pii", /^S3_\d{3}$/],
    ["arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds", /^SECRET_\d{3}$/],
    ["arn:aws:lambda:us-east-1:123456789012:function:charge", /^LAMBDA_\d{3}$/],
    ["arn:aws:rds:us-east-1:123456789012:db:prod", /^RDS_\d{3}$/],
    ["arn:aws:kms:us-east-1:123456789012:key/abcd-1234", /^KMS_\d{3}$/],
    ["123456789012", /^ACCOUNT_\d{3}$/],
    ["54.12.33.9", /^IP_\d{3}$/],
  ];
  for (const [raw, tokenRe] of cases) {
    const out = t.redactDeep(raw) as string;
    assert.match(out, tokenRe, `${raw} should tokenize to ${tokenRe}`);
    assert.notEqual(out, raw);
  }
});

test("strict: round-trip through a nested finding restores every value", async () => {
  const t = await load("strict");
  const finding = {
    analysis_id: "abc-123",
    critical_risks: [
      {
        rule_id: "EMFIRGE-EC2-002",
        resource_id: "sg-0a1b2c3d4e5f",
        issue: "SSH open to the internet",
        attack_path: ["i-0c0c1234abcd5678", "sg-0a1b2c3d4e5f", "arn:aws:s3:::acme-customer-pii"],
        public_ip: "54.12.33.9",
        account_id: "123456789012",
      },
    ],
  };
  const redacted = t.redactDeep(finding);

  // Nothing real leaks.
  assertNoLeak(redacted, [
    "sg-0a1b2c3d4e5f",
    "i-0c0c1234abcd5678",
    "acme-customer-pii",
    "54.12.33.9",
    "123456789012",
  ]);

  // And it reverses exactly.
  const restored = t.expandTokens(redacted);
  assert.deepEqual(restored, finding);
});

test("strict: same real ID always maps to the same token", async () => {
  const t = await load("strict");
  const a = t.redactDeep("sg-0a1b2c3d4e5f");
  const b = t.redactDeep({ resource_id: "sg-0a1b2c3d4e5f" }) as { resource_id: string };
  assert.equal(a, b.resource_id);
});

test("strict: IDs embedded inside narrative text are replaced", async () => {
  const t = await load("strict");
  const narrative =
    "Attacker lands on i-0c0c1234abcd5678 via sg-0a1b2c3d4e5f then reaches arn:aws:s3:::acme-customer-pii";
  const out = t.redactDeep({ caption: narrative }) as { caption: string };
  assertNoLeak(out, ["i-0c0c1234abcd5678", "sg-0a1b2c3d4e5f", "acme-customer-pii"]);
  assert.match(out.caption, /EC2_\d{3}/);
  assert.match(out.caption, /SG_\d{3}/);
});

test("strict: sensitive-key names are tokenized even without an AWS prefix", async () => {
  const t = await load("strict");
  const obj = {
    bucket_name: "acme-customer-pii",
    summary: "The bucket acme-customer-pii is world-readable",
  };
  const out = t.redactDeep(obj) as { bucket_name: string; summary: string };
  // The bucket name leaks in NEITHER the field NOR the free-text summary.
  assertNoLeak(out, ["acme-customer-pii"]);
  assert.match(out.bucket_name, /^NAME_\d{3}$/);
});

test("strict: ordinary non-identifier strings pass through untouched", async () => {
  const t = await load("strict");
  const obj = { severity: "Critical", note: "rotate keys within 90 days" };
  assert.deepEqual(t.redactDeep(obj), obj);
});

// ---------------------------------------------------------------------------
// BALANCED MODE — high-sensitivity IDs tokenized, generic topology left raw.
// ---------------------------------------------------------------------------

test("balanced: sensitive IDs tokenized, generic IDs left raw", async () => {
  const t = await load("balanced");
  // Sensitive -> tokenized
  assert.match(t.redactDeep("sg-0a1b2c3d4e5f") as string, /^SG_\d{3}$/);
  assert.match(t.redactDeep("arn:aws:iam::123456789012:role/Admin") as string, /^IAM_ROLE_\d{3}$/);
  assert.match(t.redactDeep("54.12.33.9") as string, /^IP_\d{3}$/);
  assert.match(t.redactDeep("123456789012") as string, /^ACCOUNT_\d{3}$/);
  // Generic topology -> raw (accepted tradeoff in balanced)
  assert.equal(t.redactDeep("subnet-0a1b2c3d"), "subnet-0a1b2c3d");
  assert.equal(t.redactDeep("vpc-0a1b2c3d"), "vpc-0a1b2c3d");
  assert.equal(t.redactDeep("vol-0a1b2c3d4e5f"), "vol-0a1b2c3d4e5f");
});

// ---------------------------------------------------------------------------
// OFF MODE — nothing is touched.
// ---------------------------------------------------------------------------

test("off: everything passes through unchanged", async () => {
  const t = await load("off");
  const obj = {
    resource_id: "sg-0a1b2c3d4e5f",
    arn: "arn:aws:s3:::acme-customer-pii",
    ip: "54.12.33.9",
  };
  assert.deepEqual(t.redactDeep(obj), obj);
});

// ---------------------------------------------------------------------------
// expandTokens — the inbound direction (host LLM tokens -> real IDs).
// ---------------------------------------------------------------------------

test("expandTokens: bare token, embedded token, and unknown token", async () => {
  const t = await load("strict");
  const token = t.redactDeep("sg-0a1b2c3d4e5f") as string; // registers the mapping

  // bare
  assert.equal(t.expandTokens(token), "sg-0a1b2c3d4e5f");
  // embedded in a sentence (e.g. "fix SG_001 now")
  assert.equal(t.expandTokens(`please fix ${token} now`), "please fix sg-0a1b2c3d4e5f now");
  // unknown token -> passes through as-is
  assert.equal(t.expandTokens("SG_999"), "SG_999");
});
