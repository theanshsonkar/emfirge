import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "emfirge-branch-handback-guidance-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.EMFIRGE_PRIVACY = "strict";
process.env.EMFIRGE_BASE_URL = "http://stub.invalid/api";
process.env.EMFIRGE_API_KEY = "synthetic-test-api-key";

const handback = await import("./branch-handback.js");

const planNextStep = "This branch was built from a submitted plan. Hand back that original plan (terraform/aws-api/aws-cli) instead, or create a new branch from the base analysis and apply typed changes only.";
const unmappableNextStep = "These changes have no AWS API equivalent yet, so nothing was handed back. Roll the branch back to before them (or discard and recreate the branch without them) and hand back again, or apply them by hand outside Emfirge.";

function stubFetch(body: unknown, status: number): void {
  globalThis.fetch = (async () => new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })) as typeof fetch;
}

test("branch handback includes next step for plan receipts", async () => {
  stubFetch({ error: "branch_has_plan_receipts", next_step: planNextStep }, 409);
  await assert.rejects(
    () => handback.branchHandbackHandler({ branch_id: "branch-1" }),
    (error: unknown) => {
      assert.match(String(error), new RegExp(planNextStep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      return true;
    },
  );
});

test("branch handback includes next step for unmappable changes", async () => {
  stubFetch({
    error: "unmappable_changes",
    changes: [{ change_index: 0, reason: "resource_not_found", resource_id: "vol-0123456789abcdef0" }],
    next_step: unmappableNextStep,
  }, 422);
  await assert.rejects(
    () => handback.branchHandbackHandler({ branch_id: "branch-1" }),
    (error: unknown) => {
      assert.match(String(error), new RegExp(unmappableNextStep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      return true;
    },
  );
});
