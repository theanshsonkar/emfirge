import assert from "node:assert/strict";
import test from "node:test";

import { redactDeep } from "./tokenize.js";

test("strict tokenizes resource identifiers inside verdict reasons", () => {
  const result = redactDeep({ reasons: [{ resources: ["orders-bucket", "lambda-orders", "iam-role-orders"] }] }) as {
    reasons: Array<{ resources: string[] }>;
  };
  assert.notEqual(result.reasons[0].resources[0], "orders-bucket");
  assert.notEqual(result.reasons[0].resources[1], "lambda-orders");
  assert.notEqual(result.reasons[0].resources[2], "iam-role-orders");
});
