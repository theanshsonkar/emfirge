// L71f: the local token map (and other ~/.emfirge state) is private to the user:
// directory 0700, files 0600, written via temp file + rename, and a too-open file is fixed on load.

import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const posix = process.platform !== "win32";
let counter = 0;

function freshHome(): string {
  const home = mkdtempSync(join(tmpdir(), "emfirge-perms-"));
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.env.EMFIRGE_PRIVACY = "strict";
  return home;
}

const mode = (path: string) => statSync(path).mode & 0o777;

test("tokens.json is written 0600 in a 0700 directory with no temp files left", { skip: !posix }, async () => {
  const home = freshHome();
  const tok = await import(`./tokenize.ts?perms=${counter++}`);
  const out = tok.redactDeep({ id: "i-0123456789abcdef0" }) as { id: string };
  assert.notEqual(out.id, "i-0123456789abcdef0");
  const dir = join(home, ".emfirge");
  assert.equal(mode(dir), 0o700);
  assert.equal(mode(join(dir, "tokens.json")), 0o600);
  assert.deepEqual(readdirSync(dir), ["tokens.json"]);
});

test("an existing 0644 tokens.json in a 0755 directory is tightened on load and stays private after save", { skip: !posix }, async () => {
  const home = freshHome();
  const dir = join(home, ".emfirge");
  const file = join(dir, "tokens.json");
  mkdirSync(dir, { recursive: true });
  const existing = { realToToken: { "i-0123456789abcdef0": "EC2_001" }, tokenToReal: { EC2_001: "i-0123456789abcdef0" }, counters: { EC2: 1 } };
  writeFileSync(file, JSON.stringify(existing), { mode: 0o644 });
  chmodSync(file, 0o644);
  chmodSync(dir, 0o755);
  const tok = await import(`./tokenize.ts?perms=${counter++}`);
  assert.equal(mode(file), 0o600, "loading must tighten the file");
  assert.equal(mode(dir), 0o700, "loading must tighten the directory");
  assert.equal(JSON.parse(readFileSync(file, "utf8")).counters.EC2, 1, "existing mapping is kept");
  tok.redactDeep({ id: "i-0aaaaaaaaaaaaaaaa" });
  assert.equal(mode(file), 0o600);
  assert.equal(mode(dir), 0o700);
});

test("writePrivateFile (used for notice-shown) makes a 0600 file in a 0700 dir and replaces a 0644 one", { skip: !posix }, async () => {
  const home = freshHome();
  const { writePrivateFile } = await import("./private-file.js");
  const dir = join(home, ".emfirge");
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o755);
  writeFileSync(join(dir, "notice-shown"), "old", { mode: 0o644 });
  chmodSync(join(dir, "notice-shown"), 0o644);
  writePrivateFile(dir, join(dir, "notice-shown"), "2026-01-01T00:00:00.000Z");
  assert.equal(mode(dir), 0o700);
  assert.equal(mode(join(dir, "notice-shown")), 0o600);
  assert.equal(readFileSync(join(dir, "notice-shown"), "utf8"), "2026-01-01T00:00:00.000Z");
  assert.deepEqual(readdirSync(dir), ["notice-shown"]);
});
