// Arg parsing for the six verbs plus setup commands. Pure: no network, no auth.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-cli-args-"));
process.env.HOME = home;
process.env.USERPROFILE = home;

const { parseCommand, UsageError } = await import("./args.js");
const { VERB_NAMES, verbHelp } = await import("./verbs.js");
const { runCli } = await import("./run.js");

function capture() {
  let stdout = "";
  let stderr = "";
  return {
    io: { out: (s: string) => { stdout += s; }, err: (s: string) => { stderr += s; } },
    get stdout() { return stdout; },
    get stderr() { return stderr; },
  };
}

test("the verb list is the six verbs plus setup commands and guide", () => {
  for (const v of ["context", "branch", "try", "check", "request", "report", "connect", "login", "logout", "guide"]) {
    assert.ok(VERB_NAMES.includes(v), `missing verb ${v}`);
  }
});

test("context: question positional and id options", () => {
  const p = parseCommand(["context", "reachable", "--analysis", "a-1", "--resource=S3_001"]);
  assert.equal(p.verb, "context");
  assert.deepEqual(p.positionals, ["reachable"]);
  assert.equal(p.flags.analysis, "a-1");
  assert.equal(p.flags.resource, "S3_001");
  assert.equal(p.human, false);
});

test("context: mode flags are booleans, --human is global", () => {
  const p = parseCommand(["context", "--refresh", "--role-arn", "arn:aws:iam::123456789012:role/x", "--region", "us-east-1", "--human"]);
  assert.equal(p.flags.refresh, true);
  assert.equal(p.human, true);
});

test("context: two modes at once is a usage error", () => {
  assert.throws(() => parseCommand(["context", "--findings", "--refresh"]), UsageError);
});

test("branch: sub-command first, ids after", () => {
  const p = parseCommand(["branch", "compare", "b1", "b2"]);
  assert.equal(p.sub, "compare");
  assert.deepEqual(p.positionals, ["b1", "b2"]);
  assert.equal(parseCommand(["branch", "open", "--analysis", "a", "--name", "n"]).sub, "open");
  assert.throws(() => parseCommand(["branch"]), UsageError);
  assert.throws(() => parseCommand(["branch", "explode"]), UsageError);
});

test("try: repeatable --aws-cli collects a list", () => {
  const p = parseCommand(["try", "b1", "--aws-cli", "aws ec2 a", "--aws-cli", "aws ec2 b"]);
  assert.deepEqual(p.flags["aws-cli"], ["aws ec2 a", "aws ec2 b"]);
  assert.deepEqual(p.positionals, ["b1"]);
});

test("check and report options", () => {
  assert.equal(parseCommand(["check", "b1", "--verdict"]).flags.verdict, true);
  assert.equal(parseCommand(["check", "b1", "--policy", "--approve", "--accept-estimate", "x"]).flags.approve, true);
  assert.equal(parseCommand(["report", "b1", "--plan", "p1"]).flags.plan, "p1");
});

test("unknown option, missing value and unknown verb are usage errors", () => {
  assert.throws(() => parseCommand(["check", "b1", "--nope"]), UsageError);
  assert.throws(() => parseCommand(["context", "--analysis"]), UsageError);
  assert.throws(() => parseCommand(["frobnicate"]), UsageError);
  assert.throws(() => parseCommand(["check", "b1", "--verdict=yes"]), UsageError);
});

test("unknown verb: exit 1, usage on stderr, nothing on stdout", async () => {
  const c = capture();
  const code = await runCli(["frobnicate"], c.io);
  assert.equal(code, 1);
  assert.equal(c.stdout, "");
  assert.match(c.stderr, /Usage/i);
  assert.match(c.stderr, /context/);
});

test("unknown option: exit 1 with the verb usage on stderr", async () => {
  const c = capture();
  const code = await runCli(["check", "b1", "--nope"], c.io);
  assert.equal(code, 1);
  assert.equal(c.stdout, "");
  assert.match(c.stderr, /--nope/);
  assert.match(c.stderr, /emfirge check/);
});

test("no arguments prints usage and exits 1", async () => {
  const c = capture();
  assert.equal(await runCli([], c.io), 1);
  assert.match(c.stderr, /Usage/i);
});

test("--help works for every verb (exit 0, help on stdout)", async () => {
  for (const verb of VERB_NAMES) {
    for (const flag of ["--help", "-h"]) {
      const c = capture();
      const code = await runCli([verb, flag], c.io);
      assert.equal(code, 0, `${verb} ${flag}`);
      assert.match(c.stdout, new RegExp(`emfirge ${verb}`), `${verb} help names the verb`);
      assert.equal(c.stderr, "");
      assert.equal(c.stdout, verbHelp(verb));
    }
  }
});

test("top-level --help and help <verb>", async () => {
  const a = capture();
  assert.equal(await runCli(["--help"], a.io), 0);
  assert.match(a.stdout, /context/);
  const b = capture();
  assert.equal(await runCli(["help", "check"], b.io), 0);
  assert.equal(b.stdout, verbHelp("check"));
});
