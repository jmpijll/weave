import test from "node:test";
import assert from "node:assert/strict";
import { buildIssuanceRecord } from "../src/m32/issuance.ts";
import { buildHostPossessionRecord } from "../src/m32/host-possession.ts";
import { buildConsumeRecord } from "../src/m32/consume.ts";

test("issuance record builds and contains purpose tag", () => {
  const r = buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456" });
  assert.ok(r.length>0 && r[0]===0x01);
});
test("host possession record builds", () => {
  const r = buildHostPossessionRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"b".repeat(64), issuedAt:"123457" });
  assert.ok(r.includes(0x11));
});
test("consume record includes freshness tag", () => {
  const r = buildConsumeRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"c".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123458", consumeFreshness:"123459" });
  assert.ok(r.includes(0x21));
});
