import assert from "node:assert/strict";
import test from "node:test";
import { _resetForTests, setSession } from "../auth/session.js";
import { linkProjectHandler, linkProjectSchema } from "./link.js";

test("link project uses Supabase bearer and link header without exposing secrets", async () => {
  const token = "SUPABASE-TOKEN-SYNTHETIC";
  const key = "API-KEY-SYNTHETIC";
  process.env.EMFIRGE_API_KEY = key;
  setSession(token, 3600, "refresh-synthetic");
  const originalFetch = globalThis.fetch;
  let request: RequestInit | undefined;
  globalThis.fetch = (async (_url, init) => {
    request = init;
    return new Response(JSON.stringify({ linked: true, project: "old" }), { status: 200 });
  }) as typeof fetch;
  try {
    const result = await linkProjectHandler({});
    assert.deepEqual(linkProjectSchema, {});
    assert.equal(new Headers(request?.headers).get("authorization"), `Bearer ${token}`);
    assert.equal(new Headers(request?.headers).get("x-emfirge-link-key"), key);
    assert.equal(result.content[0].text.includes(key), false);
    assert.equal(result.content[0].text, "Linked. Remove EMFIRGE_API_KEY from your MCP settings and restart; you'll stay signed in.");
  } finally {
    globalThis.fetch = originalFetch;
    delete process.env.EMFIRGE_API_KEY;
    _resetForTests();
  }
});
