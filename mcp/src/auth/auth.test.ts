import test from "node:test";
import assert from "node:assert/strict";
import { assertPublicKey } from "./config.js";

test("auth public keys reject service credentials", () => {
  assert.throws(() => assertPublicKey("sb_secret_x"), /Sign-in is misconfigured/);
  const payload = Buffer.from(JSON.stringify({ role: "service_role" })).toString("base64url");
  assert.throws(() => assertPublicKey(`e30.${payload}.sig`), /Sign-in is misconfigured/);
});
