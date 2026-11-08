// The spinner is for a person at a terminal only. Agents read stdout as JSON, so the spinner
// must never write to stdout, and never write anything when stderr is not a terminal.
import { test } from "node:test";
import assert from "node:assert/strict";
import { startSpinner, spinnerEnabled } from "./spinner.js";
import { runCli } from "./run.js";

function fakeStream(isTTY: boolean) {
  const writes: string[] = [];
  return { isTTY, writes, write: (s: string) => { writes.push(s); return true; } };
}

test("no terminal: the spinner writes nothing", async () => {
  const s = fakeStream(false);
  const stop = startSpinner("Asking Emfirge", { stream: s, env: {}, intervalMs: 5 });
  await new Promise((r) => setTimeout(r, 30));
  stop();
  assert.deepEqual(s.writes, []);
});

test("a terminal: the spinner draws frames with the label, then clears its line", async () => {
  const s = fakeStream(true);
  const stop = startSpinner("Asking Emfirge", { stream: s, env: {}, intervalMs: 5 });
  await new Promise((r) => setTimeout(r, 40));
  stop();
  assert.ok(s.writes.length >= 2, "draws more than one frame");
  assert.ok(s.writes.some((w) => w.includes("Asking Emfirge")));
  assert.equal(s.writes.at(-1), "\r\x1b[K");
  const n = s.writes.length;
  stop(); // stopping twice is harmless
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(s.writes.length, n, "no frames after stop");
});

test("CI, NO_COLOR-style opt-out, or TERM=dumb turn it off even on a terminal", () => {
  for (const env of [{ CI: "true" }, { EMFIRGE_NO_SPINNER: "1" }, { TERM: "dumb" }]) {
    assert.equal(spinnerEnabled({ isTTY: true }, env), false, JSON.stringify(env));
  }
  assert.equal(spinnerEnabled({ isTTY: true }, {}), true);
  assert.equal(spinnerEnabled({ isTTY: false }, {}), false);
});

test("runCli never puts spinner output on stdout", async () => {
  const out: string[] = [];
  const spun: string[] = [];
  await runCli(["context", "inventory"], {
    out: (s) => { out.push(s); },
    err: () => {},
    spinner: (label) => { spun.push(label); return () => {}; },
    loadManifest: async () => ({ source: "bundled", manifest: (await import("./manifest.js")).bundledManifest() }) as never,
  });
  assert.deepEqual(spun, ["Asking Emfirge"]);
  assert.ok(out.every((s) => !s.includes("Asking Emfirge")));
});
