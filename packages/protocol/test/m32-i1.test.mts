import test from "node:test";
import assert from "node:assert/strict";
import {
  buildIssuanceRecord,
  buildHostPossessionRecord,
  buildConsumeRecord,
  parseIssuanceRecord,
  parseHostPossessionRecord,
  parseConsumeRecord,
  decodeIssuanceRecord,
  decodeHostPossessionRecord,
  decodeConsumeRecord,
  decodeIssuanceProof,
  decodeIssuanceVerificationKey,
  decodeHostPossessionProof,
  decodeHostPossessionVerificationKey,
  decodeConsumeProof,
  decodeConsumeVerificationKey,
  validateIssuanceCarrier,
  validateHostCarrier,
  validateConsumeCarrier,
  rebuildIssuanceRecord,
  rebuildHostRecord,
  rebuildConsumeRecord,
} from "@weave/protocol";
import {
  verifyIssuance,
  verifyHostPossession,
  verifyConsume,
  verifyConsumeCarrier,
} from "@weave/protocol/m32-verify";
import * as WeaveVerify from "@weave/protocol/m32-verify";
import * as WeaveProtocol from "@weave/protocol";
import type {
  IssuanceRecord,
  HostPossessionRecord,
  ConsumeRecord,
} from "@weave/protocol";
import { generateKeyPairSync, sign } from "node:crypto";

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

// RED: strict parser/framing rejection — these must throw/reject
test("RED empty record rejects", () => { assert.throws(()=>parseIssuanceRecord(new Uint8Array(0))); });
test("RED trailing bytes rejects", () => { const r=buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456" }); const t=new Uint8Array([...r,0xFF]); assert.throws(()=>parseIssuanceRecord(t)); });
test("RED unknown tag rejects", () => { assert.throws(()=>parseIssuanceRecord(new Uint8Array([0x99,1,0x41]))); });
test("RED duplicate tag rejects", () => { const r=buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456" }); // duplicate 0x10
  const dup=new Uint8Array([...r,0x10,1,0x41]); assert.throws(()=>parseIssuanceRecord(dup)); });
test("RED out-of-order rejects", () => { assert.throws(()=>parseIssuanceRecord(new Uint8Array([0x10,1,0x41,0x01,1,0x41]))); });
test("RED invalid length rejects", () => { assert.throws(()=>parseIssuanceRecord(new Uint8Array([0x01,5,0x41]))); });

// RED: canonical BigInt time and field grammar — must reject
test("RED BigInt leading zero rejects", () => { assert.throws(()=>buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"0123" })); });
test("RED BigInt fraction rejects", () => { assert.throws(()=>buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"12.34" })); });
test("RED BigInt out-of-range rejects", () => { assert.throws(()=>buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"9007199254740992" })); });
test("RED BigInt sign rejects", () => { assert.throws(()=>buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"-1" })); });
test("RED hostPublic wrong length rejects", () => { assert.throws(()=>buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(63), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" })); });

// RED: cross-purpose record separation
test("RED issuance parser rejects host record", () => {
  const r = buildHostPossessionRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123" });
  assert.throws(()=>parseIssuanceRecord(r));
});
test("RED host parser rejects issuance record", () => {
  const r = buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" });
  assert.ok(typeof parseHostPossessionRecord === "function", "parseHostPossessionRecord must exist");
  assert.throws(()=>parseHostPossessionRecord(r));
});
test("RED consume parser rejects missing freshness", () => {
  assert.ok(typeof parseConsumeRecord === "function");
  const r = buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" });
  assert.throws(()=>parseConsumeRecord(r));
});
test("RED no generic parser export", () => {
  assert.equal("parseRecord" in WeaveProtocol, false);
  assert.equal("buildRecord" in WeaveProtocol, false);
  assert.equal("verifyRecord" in WeaveProtocol, false);
});

// RED: three purpose-specific verifier façades
test("RED verifyIssuance valid vector passes", () => {
  assert.ok(typeof verifyIssuance === "function");
  const rec = buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456" });
  assert.ok(verifyIssuance(rec as unknown as IssuanceRecord, decodeIssuanceProof("a".repeat(128)), decodeIssuanceVerificationKey("a".repeat(64))) !== undefined);
});
test("RED verifyHost cross-purpose fails", () => {
  assert.ok(typeof verifyConsume === "function");
  assert.ok(typeof verifyHostPossession === "function");
  const rec = buildHostPossessionRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123" });
  assert.equal(verifyHostPossession(rec as unknown as HostPossessionRecord, decodeHostPossessionProof("a".repeat(128)), decodeHostPossessionVerificationKey("b".repeat(64))), false);
});
test("RED host verifier binds key to signed record", async () => {
  const { generateKeyPairSync, sign } = await import("node:crypto");
  const keyA = generateKeyPairSync("ed25519");
  const keyB = generateKeyPairSync("ed25519");
  const hexOf = (k: ReturnType<typeof generateKeyPairSync>["publicKey"]) => {
    const jwk = k.export({ format: "jwk" });
    if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
    return Buffer.from(jwk.x, "base64url").toString("hex");
  };
  const pubA = hexOf(keyA.publicKey);
  const pubB = hexOf(keyB.publicKey);
  const rec = buildHostPossessionRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic: pubA, issuedAt:"123" });
  // Matching key A positive is retained.
  const sigA = sign(null, Buffer.from(rec), keyA.privateKey).toString("hex");
  assert.equal(verifyHostPossession(decodeHostPossessionRecord(rec), decodeHostPossessionProof(sigA), decodeHostPossessionVerificationKey(pubA)), true);
  // Record names host key A, is signed by B, and is verified with B: must fail on key binding.
  const sigB = sign(null, Buffer.from(rec), keyB.privateKey).toString("hex");
  assert.equal(verifyHostPossession(decodeHostPossessionRecord(rec), decodeHostPossessionProof(sigB), decodeHostPossessionVerificationKey(pubB)), false);
});
test("RED shared root carries no Node-only verifier values; m32-verify subpath does", () => {
  for (const name of ["verifyIssuance", "verifyHostPossession", "verifyConsume", "verifyConsumeCarrier"]) {
    assert.equal(name in WeaveProtocol, false, `root must not value-export ${name}`);
    assert.equal(typeof (WeaveVerify as Record<string, unknown>)[name], "function", `m32-verify must export ${name}`);
  }
});
test("RED cross-purpose same-key must reject", async () => {
  const { generateKeyPairSync, sign } = await import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format:"jwk" }) as { x: string };
  const pubHex = Buffer.from(jwk.x, "base64url").toString("hex");
  const hostRec = buildHostPossessionRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123" });
  const sig = sign(null, Buffer.from(hostRec), privateKey).toString("hex");
  assert.equal(verifyIssuance(hostRec as unknown as IssuanceRecord, decodeIssuanceProof(sig), decodeIssuanceVerificationKey(pubHex)), false, "issuance verifier should reject host-purpose record");
});

// RED: flat carrier → purpose-record mapping
test("RED carrier issuance missing member rejects", () => {
  assert.ok(typeof validateIssuanceCarrier === "function");
  assert.throws(()=>validateIssuanceCarrier({} as unknown)); // missing all
});
test("RED carrier host must not accept freshness", () => {
  assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", consumeFreshness:"456" } as unknown));
});
test("RED carrier rebuild equals builder", () => {
  const carrier = { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) };
  const rec = rebuildIssuanceRecord(carrier);
  const expected = buildIssuanceRecord(carrier);
  assert.ok(Buffer.from(rec).equals(Buffer.from(expected)), "rebuild should equal builder");
});
// RED: verifiers must full-parse before signature (bad grammar should reject even with valid sig)
test("RED verifier rejects bad hostPublic grammar even with valid sig", async () => {
  const { generateKeyPairSync, sign } = await import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format:"jwk" }) as { x: string };
  const pubHex = Buffer.from(jwk.x, "base64url").toString("hex");
  // manually craft issuance record with bad hostPublic (63 chars) but correct TLV framing — verifier should reject before crypto
  const badRec = new Uint8Array([0x01, 14, ...Buffer.from("weave-issue-v1"), 0x30,1,0x31, 0x31,1,0x31, 0x40,7,...Buffer.from("ed25519"), 0x10,36,...Buffer.from("00112233-4455-6677-8899-aabbccddeeff"), 0x11,63,...Buffer.from("a".repeat(63)), 0x12,36,...Buffer.from("11111111-2222-3333-4444-555555555555"), 0x13,36,...Buffer.from("22222222-3333-4444-5555-666666666666"), 0x20,3,...Buffer.from("123")]);
  const sig = sign(null, Buffer.from(badRec), privateKey).toString("hex");
  assert.equal(verifyIssuance(badRec as unknown as IssuanceRecord, decodeIssuanceProof(sig), decodeIssuanceVerificationKey(pubHex)), false, "bad grammar must reject before verify");
});
// RED: host/consume exact mapping + rebuild
test("RED host carrier rejects community", () => {
  assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", community:"11111111-2222-3333-4444-555555555555" } as unknown));
});
test("RED consume requires freshness and proofs", () => {
  assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" } as unknown)); // missing freshness/proofs
});
test("RED host rebuild equals builder", () => {
  const c = { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) };
  const rec = rebuildHostRecord(c);
  const exp = buildHostPossessionRecord(c);
  assert.ok(Buffer.from(rec).equals(Buffer.from(exp)));
});
test("RED consume rebuild equals builder", () => {
  const c = { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) };
  const rec = rebuildConsumeRecord(c);
  const exp = buildConsumeRecord({ ...c });
  assert.ok(Buffer.from(rec).equals(Buffer.from(exp)));
});
// Carrier Batch A — C-01..C-06, C-17, C-18
test("carrier.accepts.issuance.exact-set", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) })); });
test("carrier.accepts.host.exact-set", ()=>{ assert.doesNotThrow(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) })); });
test("carrier.accepts.consume.exact-set", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.mapping.issuance", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456", proof:"a".repeat(128) }; const rec=rebuildIssuanceRecord(c); assert.ok(Buffer.from(rec).equals(Buffer.from(ORACLE_ISSUANCE))); assert.deepEqual(parseIssuanceRecord(rec), { stableId:c.stableId, hostPublic:c.hostPublic, community:c.community, device:c.device, issuedAt:c.issuedAt }); });
test("carrier.mapping.host", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"b".repeat(64), issuedAt:"123457", hostProof:"a".repeat(128) }; const rec=rebuildHostRecord(c); assert.ok(Buffer.from(rec).equals(Buffer.from(ORACLE_HOST))); assert.deepEqual(parseHostPossessionRecord(rec), { stableId:c.stableId, hostPublic:c.hostPublic, issuedAt:c.issuedAt }); });
test("carrier.mapping.consume", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"c".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123458", consumeFreshness:"123459", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; const rec=rebuildConsumeRecord(c); assert.ok(Buffer.from(rec).equals(Buffer.from(ORACLE_CONSUME))); assert.deepEqual(parseConsumeRecord(rec), { stableId:c.stableId, hostPublic:c.hostPublic, community:c.community, device:c.device, issuedAt:c.issuedAt, consumeFreshness:c.consumeFreshness }); });
test("carrier.proof-separate.issuance", ()=>{ const a={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }; const b={ ...a, proof:"b".repeat(128) }; assert.ok(Buffer.from(rebuildIssuanceRecord(a)).equals(Buffer.from(rebuildIssuanceRecord(b)))); });
test("carrier.proof-separate.host", ()=>{ const a={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }; const b={ ...a, hostProof:"b".repeat(128) }; assert.ok(Buffer.from(rebuildHostRecord(a)).equals(Buffer.from(rebuildHostRecord(b)))); });
test("carrier.proof-separate.consume", ()=>{ const a={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; const b={ ...a, ownerProof:"c".repeat(128), hostProof:"d".repeat(128) }; assert.ok(Buffer.from(rebuildConsumeRecord(a)).equals(Buffer.from(rebuildConsumeRecord(b)))); });
test("carrier.rejects.precomputed-record", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), record: Buffer.from(ORACLE_ISSUANCE).toString("hex") } as unknown)); assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), transcript:"00" } as unknown)); });
test("carrier.rejects.generic-proofs", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128), proofs:[] } as unknown)); assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), transcript:"00", record:"00" } as unknown)); });
for(const [lbl, fn, carrier] of [
  ["carrier.missing.issuance.stableId", validateIssuanceCarrier, { hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }],
  ["carrier.missing.issuance.hostPublic", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }],
  ["carrier.missing.issuance.community", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }],
  ["carrier.missing.issuance.device", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", issuedAt:"123", proof:"a".repeat(128) }],
  ["carrier.missing.issuance.issuedAt", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", proof:"a".repeat(128) }],
  ["carrier.missing.issuance.proof", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" }],
  ["carrier.missing.host.stableId", validateHostCarrier, { hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }],
  ["carrier.missing.host.hostPublic", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", issuedAt:"123", hostProof:"a".repeat(128) }],
  ["carrier.missing.host.issuedAt", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), hostProof:"a".repeat(128) }],
  ["carrier.missing.host.hostProof", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123" }],
  ["carrier.missing.consume.stableId", validateConsumeCarrier, { hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }],
  ["carrier.missing.consume.hostPublic", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }],
  ["carrier.missing.consume.community", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }],
  ["carrier.missing.consume.device", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }],
  ["carrier.missing.consume.issuedAt", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }],
  ["carrier.missing.consume.consumeFreshness", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }],
  ["carrier.missing.consume.ownerProof", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", hostProof:"b".repeat(128) }],
  ["carrier.missing.consume.hostProof", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128) }],
] as const) { test(lbl, ()=>{ assert.throws(()=>fn(carrier as unknown)); }); }
for(const [lbl, fn, carrier] of [
  ["carrier.forbidden.issuance.hostProof", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), hostProof:"a".repeat(128) }],
  ["carrier.forbidden.issuance.consumeFreshness", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), consumeFreshness:"456" }],
  ["carrier.forbidden.host.community", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), community:"11111111-2222-3333-4444-555555555555" }],
  ["carrier.forbidden.host.device", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), device:"22222222-3333-4444-5555-666666666666" }],
  ["carrier.forbidden.host.proof", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), proof:"a".repeat(128) }],
  ["carrier.forbidden.host.ownerProof", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), ownerProof:"a".repeat(128) }],
  ["carrier.forbidden.host.consumeFreshness", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), consumeFreshness:"456" }],
  ["carrier.forbidden.issuance.ownerProof", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), ownerProof:"a".repeat(128) }],
  ["carrier.forbidden.consume.proof", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128), proof:"a".repeat(128) }],
] as const) { test(lbl, ()=>{ assert.throws(()=>fn(carrier as unknown)); }); }
// Batch B1 — C-07..C-12 grammar and placement
test("carrier.accepts.stableId.issuance", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) })); });
test("carrier.accepts.stableId.host", ()=>{ assert.doesNotThrow(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) })); });
test("carrier.accepts.stableId.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.accepts.hostPublic.issuance", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"b".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) })); });
test("carrier.accepts.hostPublic.host", ()=>{ assert.doesNotThrow(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"c".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) })); });
test("carrier.accepts.hostPublic.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"d".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.accepts.community.issuance", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) })); });
test("carrier.accepts.community.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"22222222-3333-4444-5555-666666666666", device:"33333333-4444-5555-6666-777777777777", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.accepts.device.issuance", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"44444444-5555-6666-7777-888888888888", issuedAt:"123", proof:"a".repeat(128) })); });
test("carrier.accepts.device.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"55555555-6666-7777-8888-999999999999", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.accepts.issuedAt.issuance 0", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"0", proof:"a".repeat(128) })); });
test("carrier.accepts.issuedAt.host normal", ()=>{ assert.doesNotThrow(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"9007199254740991", hostProof:"a".repeat(128) })); });
test("carrier.accepts.issuedAt.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.accepts.consumeFreshness.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"789", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.rejects.community.host", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), community:"11111111-2222-3333-4444-555555555555" } as unknown)); });
test("carrier.rejects.device.host", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), device:"22222222-3333-4444-5555-666666666666" } as unknown)); });
test("carrier.rejects.consumeFreshness.issuance", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), consumeFreshness:"456" } as unknown)); });
test("carrier.rejects.consumeFreshness.host", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), consumeFreshness:"456" } as unknown)); });
// stableId negatives (representative exhaustive)
for(const v of ["", "00112233-4455-6677-8899-AABBCCDDEEFF", "00112233.4455.6677.8899.aabbccddeeff", "00112233-4455-6677-8899-aabbccddeef", " 00112233-4455-6677-8899-aabbccddeeff ", "aabbcc\u00e0ddeeff-4455-6677-8899-aabbccddeeff", 123 as unknown]) test(`carrier.rejects.stableId bad ${JSON.stringify(v)}`, ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:v, hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
// hostPublic negatives
for(const v of ["", "A".repeat(64), "g".repeat(64), "a".repeat(63), "a".repeat(65), " "+ "a".repeat(64)+" ", "a".repeat(64).replace("a","à"), 123 as unknown]) test(`carrier.rejects.hostPublic bad ${String(v).slice(0,10)}`, ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:v, issuedAt:"123", hostProof:"a".repeat(128) } as unknown)); });
// issuedAt negatives per purpose + 0/max normals already in accepts
for(const v of ["", "0123", "12.34", "-1", " 123 ", "12\u00e034", "9007199254740992", 123 as unknown]) { test(`carrier.rejects.issuedAt.issuance bad ${JSON.stringify(v)}`, ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:v, proof:"a".repeat(128) } as unknown)); }); test(`carrier.rejects.issuedAt.host bad ${JSON.stringify(v)}`, ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:v, hostProof:"a".repeat(128) } as unknown)); }); test(`carrier.rejects.issuedAt.consume bad ${JSON.stringify(v)}`, ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:v, consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); }); }
// consumeFreshness negatives (consume only) + unicode/overflow
for(const v of ["", "0123", "12.34", "-1", " 123 ", "12\u00e034", "9007199254740992", 123 as unknown]) test(`carrier.rejects.consumeFreshness.consume bad ${JSON.stringify(v)}`, ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:v, ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
// stableId/hostPublic per-purpose expansions + community/device negatives + alias/duplicate
for(const fn of [validateIssuanceCarrier, validateHostCarrier, validateConsumeCarrier] as const) {
  const name = fn===validateIssuanceCarrier?"issuance":fn===validateHostCarrier?"host":"consume";
  test(`carrier.rejects.stableId.${name} uppercase`, ()=>{ const base=name==="issuance"?{ stableId:"00112233-4455-6677-8899-AABBCCDDEEFF", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }:name==="host"?{ stableId:"00112233-4455-6677-8899-AABBCCDDEEFF", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }:{ stableId:"00112233-4455-6677-8899-AABBCCDDEEFF", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; assert.throws(()=>fn(base as unknown)); });
  test(`carrier.rejects.hostPublic.${name} uppercase`, ()=>{ const base=name==="issuance"?{ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"A".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }:name==="host"?{ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"A".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }:{ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"A".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; assert.throws(()=>fn(base as unknown)); });
}
test("carrier.alias.stableId.issuance rejects stable_id", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stable_id:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.alias.hostPublic.consume rejects host_public", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", host_public:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.community.issuance uppercase", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-AABBCCDDEEFF", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.community.issuance wrong type", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:123 as unknown, device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.community.issuance separator", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111.2222.3333.4444.555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.community.issuance wrong length", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-55555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.community.issuance unicode", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-55555555555\u00e0", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.community.issuance alias", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), communityId:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.community.consume wrong type", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:123 as unknown, device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.community.consume uppercase", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-AABBCCDDEEFF", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.community.consume separator", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111.2222.3333.4444.555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.community.consume wrong length", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-55555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.community.consume whitespace", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:" 11111111-2222-3333-4444-555555555555 ", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.community.consume unicode", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-55555555555\u00e0", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.community.consume alias", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), communityId:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance bad", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"not-a-uuid", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance wrong type", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:123 as unknown, issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance uppercase", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-AABBCCDDEEFF", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance separator", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222.3333.4444.5555.666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance whitespace", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:" 22222222-3333-4444-5555-666666666666 ", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance unicode", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-66666666666\u00e0", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance alias", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", deviceId:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume wrong type", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:123 as unknown, issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume uppercase", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-AABBCCDDEEFF", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume whitespace", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:" 22222222-3333-4444-5555-666666666666 ", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume unicode", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-66666666666\u00e0", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume alias", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", deviceId:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.consumeFreshness alias missing required", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", issuedAtAlias:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.consumeFreshness duplicate alias", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", freshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume bad", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"not-a-uuid", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.accepts.issuedAt.issuance normal", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456", proof:"a".repeat(128) })); });
test("carrier.accepts.issuedAt.host 0", ()=>{ assert.doesNotThrow(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"0", hostProof:"a".repeat(128) })); });

test("carrier.rejects.community.issuance whitespace", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:" 11111111-2222-3333-4444-555555555555 ", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.issuance wrong length", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-66666", issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume separator", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222.3333.4444.5555.666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.device.consume wrong length", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-66666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.consumeFreshness alias without required", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", freshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.accepts.issuedAt.consume max", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"9007199254740991", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
// Batch B2 — C-13..C-16 proof grammar and placement
test("carrier.accepts.proof.issuance", ()=>{ assert.doesNotThrow(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) })); });
test("carrier.rejects.proof.issuance missing", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" } as unknown)); });
test("carrier.rejects.proof.issuance wrong type", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:123 as unknown } as unknown)); });
test("carrier.rejects.proof.issuance uppercase", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"A".repeat(128) } as unknown)); });
test("carrier.rejects.proof.issuance non-hex", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"g".repeat(128) } as unknown)); });
test("carrier.rejects.proof.issuance odd", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(127) } as unknown)); });
test("carrier.rejects.proof.issuance short", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(64) } as unknown)); });
test("carrier.rejects.proof.issuance long", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(129) } as unknown)); });
test("carrier.rejects.proof.issuance empty", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"" } as unknown)); });
test("carrier.rejects.proof.host", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.proof.consume", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128), proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.proof.issuance ownerProof substitute", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", ownerProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.proof.issuance hostProof substitute", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", hostProof:"a".repeat(128) } as unknown)); });
test("carrier.accepts.hostProof.host", ()=>{ assert.doesNotThrow(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) })); });
test("carrier.accepts.hostProof.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.rejects.hostProof.host wrong type", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:123 as unknown } as unknown)); });
test("carrier.rejects.hostProof.host uppercase", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"A".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.host non-hex", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"g".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.host odd", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(127) } as unknown)); });
test("carrier.rejects.hostProof.host short", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(64) } as unknown)); });
test("carrier.rejects.hostProof.host long", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(129) } as unknown)); });
test("carrier.rejects.hostProof.host empty", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"" } as unknown)); });
test("carrier.rejects.hostProof.consume wrong type", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:123 as unknown } as unknown)); });
test("carrier.rejects.hostProof.consume uppercase", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"A".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.consume non-hex", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"g".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.consume odd", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"a".repeat(127) } as unknown)); });
test("carrier.rejects.hostProof.consume short", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"a".repeat(64) } as unknown)); });
test("carrier.rejects.hostProof.consume long", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"a".repeat(129) } as unknown)); });
test("carrier.rejects.hostProof.consume empty", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"" } as unknown)); });
test("carrier.rejects.hostProof.host missing", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123" } as unknown)); });
test("carrier.rejects.hostProof.consume missing", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.issuance", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), hostProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.issuance proof substitute", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), hostProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.host proof substitute", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.host ownerProof substitute", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", ownerProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.consume proof substitute", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.consume ownerProof substitute", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), proof:"a".repeat(128) } as unknown)); });
test("carrier.accepts.ownerProof.consume", ()=>{ assert.doesNotThrow(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) })); });
test("carrier.rejects.ownerProof.consume wrong type", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:123 as unknown, hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume uppercase", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"A".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume non-hex", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"g".repeat(128), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume odd", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(127), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume short", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(64), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume long", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(129), hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume empty", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"", hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume missing", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.issuance", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), ownerProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.host", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), ownerProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume proof substitute", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", hostProof:"b".repeat(128), proof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.ownerProof.consume hostProof only", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", hostProof:"b".repeat(128) } as unknown)); });
test("carrier.rejects.hostProof.consume ownerProof only", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128) } as unknown)); });
test("carrier.rejects.ownerFreshness.issuance valid-looking", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), consumeFreshness:"456" } as unknown)); });
test("carrier.rejects.ownerFreshness.host valid-looking", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), consumeFreshness:"456" } as unknown)); });
test("carrier.rejects.ownerFreshness.issuance generic time", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128), freshness:"456" } as unknown)); });
test("carrier.rejects.ownerFreshness.host generic time", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128), freshness:"456" } as unknown)); });

// Inherited-field negatives: prototype-inherited required members must reject
test("carrier.rejects.inherited.issuance", ()=>{ const valid={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }; assert.throws(()=>validateIssuanceCarrier(Object.create(valid) as unknown)); });
test("carrier.rejects.inherited.host", ()=>{ const valid={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }; assert.throws(()=>validateHostCarrier(Object.create(valid) as unknown)); });
test("carrier.rejects.inherited.consume", ()=>{ const valid={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; assert.throws(()=>validateConsumeCarrier(Object.create(valid) as unknown)); });

// Exact-shape negatives: non-enumerable, symbol, accessor, and unknown
// non-enumerable members must reject on every issuance/host/consume surface
for (const [purpose, validator, base, requiredKey] of [
  ["issuance", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }, "proof"],
  ["host", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }, "hostProof"],
  ["consume", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }, "ownerProof"],
] as const) {
  test(`carrier.rejects.non-enumerable.${purpose}`, ()=>{ const o = { ...base } as Record<string, unknown>; Object.defineProperty(o, requiredKey, { value: (base as Record<string, unknown>)[requiredKey], enumerable: false, configurable: true, writable: true }); assert.throws(()=>validator(o as unknown as never)); });
  test(`carrier.rejects.symbol.${purpose}`, ()=>{ assert.throws(()=>validator({ ...base, [Symbol("extra")]: 1 } as unknown as never)); });
  test(`carrier.rejects.accessor.${purpose}`, ()=>{ const o = { ...base } as Record<string, unknown>; const v = (base as Record<string, unknown>)[requiredKey]; Object.defineProperty(o, requiredKey, { get: () => v, enumerable: true, configurable: true }); assert.throws(()=>validator(o as unknown as never)); });
  test(`carrier.rejects.unknown-non-enumerable.${purpose}`, ()=>{ const o = { ...base } as Record<string, unknown>; Object.defineProperty(o, "hiddenExtra", { value: "x", enumerable: false, configurable: true, writable: true }); assert.throws(()=>validator(o as unknown as never)); });
}

// No-invocation negatives: the descriptor gate runs before every field read,
// so accessor and inherited getters must never fire on any surface
for (const [purpose, validator, base, requiredKey] of [
  ["issuance", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }, "proof"],
  ["host", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }, "hostProof"],
  ["consume", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }, "ownerProof"],
] as const) {
  test(`carrier.no-invoke.accessor.${purpose}`, ()=>{ let n=0; const o = { ...base } as Record<string, unknown>; Object.defineProperty(o, requiredKey, { get(){ n++; return "x"; }, enumerable: true, configurable: true }); assert.throws(()=>validator(o as unknown as never)); assert.equal(n, 0); });
  test(`carrier.no-invoke.inherited-getter.${purpose}`, ()=>{ let n=0; const proto = {}; Object.defineProperty(proto, requiredKey, { get(){ n++; return "x"; }, enumerable: true, configurable: true }); const o = { ...base } as Record<string, unknown>; delete o[requiredKey]; Object.setPrototypeOf(o, proto); assert.throws(()=>validator(o as unknown as never)); assert.equal(n, 0); });
  test(`carrier.no-invoke.throwing-getter.${purpose}`, ()=>{ const o = { ...base } as Record<string, unknown>; Object.defineProperty(o, requiredKey, { get(): unknown { throw new Error("must not read"); }, enumerable: true, configurable: true }); assert.throws(()=>validator(o as unknown as never)); });
}

// Consume composition: owner proof binds the consume record, host proof binds
// the host-possession record rebuilt from the same claims with the key bound
// to the host-public claim
function composeKeypair(): { pubHex: string; sk: ReturnType<typeof generateKeyPairSync>["privateKey"] } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
  return { pubHex: Buffer.from(jwk.x, "base64url").toString("hex"), sk: privateKey };
}
function composeCarrier(): { carrier: { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string; consumeFreshness: string; ownerProof: string; hostProof: string }; ownerPub: string; ownerSk: ReturnType<typeof generateKeyPairSync>["privateKey"]; hostPub: string; hostSk: ReturnType<typeof generateKeyPairSync>["privateKey"] } {
  const owner = composeKeypair();
  const host = composeKeypair();
  const claims = { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic: host.pubHex, community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123458", consumeFreshness:"123459" };
  const consumeRec = buildConsumeRecord(claims);
  const hostRec = buildHostPossessionRecord({ stableId: claims.stableId, hostPublic: claims.hostPublic, issuedAt: claims.issuedAt });
  return {
    carrier: { ...claims, ownerProof: sign(null, Buffer.from(consumeRec), owner.sk).toString("hex"), hostProof: sign(null, Buffer.from(hostRec), host.sk).toString("hex") },
    ownerPub: owner.pubHex,
    ownerSk: owner.sk,
    hostPub: host.pubHex,
    hostSk: host.sk,
  };
}
test("consume-compose positive proof pair validates", ()=>{
  const { carrier, ownerPub, hostPub } = composeCarrier();
  assert.equal(verifyConsumeCarrier(carrier, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(hostPub)), true);
});
test("consume-compose host proof for changed stableId fails", ()=>{
  const { carrier, ownerPub, hostPub, hostSk } = composeCarrier();
  const hostRec = buildHostPossessionRecord({ stableId:"aaaaaaaa-4444-5555-6666-777777777777", hostPublic: carrier.hostPublic, issuedAt: carrier.issuedAt });
  const bad = { ...carrier, hostProof: sign(null, Buffer.from(hostRec), hostSk).toString("hex") };
  assert.equal(verifyConsumeCarrier(bad, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(hostPub)), false);
});
test("consume-compose host proof for changed issuedAt fails", ()=>{
  const { carrier, ownerPub, hostPub, hostSk } = composeCarrier();
  const hostRec = buildHostPossessionRecord({ stableId: carrier.stableId, hostPublic: carrier.hostPublic, issuedAt: "999999" });
  const bad = { ...carrier, hostProof: sign(null, Buffer.from(hostRec), hostSk).toString("hex") };
  assert.equal(verifyConsumeCarrier(bad, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(hostPub)), false);
});
test("consume-compose host proof for changed host-public in signed record fails", ()=>{
  const { carrier, ownerPub, hostPub, hostSk } = composeCarrier();
  const other = composeKeypair();
  const hostRec = buildHostPossessionRecord({ stableId: carrier.stableId, hostPublic: other.pubHex, issuedAt: carrier.issuedAt });
  const bad = { ...carrier, hostProof: sign(null, Buffer.from(hostRec), hostSk).toString("hex") };
  assert.equal(verifyConsumeCarrier(bad, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(hostPub)), false);
});
test("consume-compose host proof from unrelated host key fails", ()=>{
  const { carrier, ownerPub, hostPub } = composeCarrier();
  const other = composeKeypair();
  const hostRec = buildHostPossessionRecord({ stableId: carrier.stableId, hostPublic: carrier.hostPublic, issuedAt: carrier.issuedAt });
  const bad = { ...carrier, hostProof: sign(null, Buffer.from(hostRec), other.sk).toString("hex") };
  assert.equal(verifyConsumeCarrier(bad, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(hostPub)), false);
});
test("consume-compose host proof over other host record fails", ()=>{
  const { carrier, ownerPub, hostPub, hostSk } = composeCarrier();
  const otherHost = composeKeypair();
  const otherRec = buildHostPossessionRecord({ stableId:"bbbbbbbb-1111-2222-3333-444444444444", hostPublic: otherHost.pubHex, issuedAt:"777" });
  const bad = { ...carrier, hostProof: sign(null, Buffer.from(otherRec), hostSk).toString("hex") };
  assert.equal(verifyConsumeCarrier(bad, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(hostPub)), false);
});
test("consume-compose wrong owner key fails", ()=>{
  const { carrier, hostPub } = composeCarrier();
  const other = composeKeypair();
  assert.equal(verifyConsumeCarrier(carrier, decodeConsumeVerificationKey(other.pubHex), decodeHostPossessionVerificationKey(hostPub)), false);
});
test("consume-compose attacker host key with matching proof fails against stored identity", ()=>{
  // Attacker authors their own hostPublic + hostProof; the owner proof is genuine
  // (owner key) over those same attacker-named claims. Against the stored
  // (original) host identity it must fail on the authority gate.
  const { carrier: orig, ownerPub, ownerSk, hostPub } = composeCarrier();
  const attacker = composeKeypair();
  const claims = { stableId: orig.stableId, hostPublic: attacker.pubHex, community: orig.community, device: orig.device, issuedAt: orig.issuedAt, consumeFreshness: orig.consumeFreshness };
  const consumeRec = buildConsumeRecord(claims);
  const attackerHostRec = buildHostPossessionRecord({ stableId: claims.stableId, hostPublic: claims.hostPublic, issuedAt: claims.issuedAt });
  const bad = { ...claims, ownerProof: sign(null, Buffer.from(consumeRec), ownerSk).toString("hex"), hostProof: sign(null, Buffer.from(attackerHostRec), attacker.sk).toString("hex") };
  // Control: the attacker pair is cryptographically valid for the named key, so the
  // rejection below isolates the stored-identity authority check, not broken crypto.
  assert.equal(verifyConsumeCarrier(bad, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(attacker.pubHex)), true);
  assert.equal(verifyConsumeCarrier(bad, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(hostPub)), false, "stored identity must reject attacker-named carrier");
});
test("consume-compose authoritative key unequal to claim fails before crypto", ()=>{
  const { carrier, ownerPub, hostPub } = composeCarrier();
  const other = composeKeypair();
  // Stored identity differs from the carrier claim: rejection must not depend on
  // whether any proof would verify — even the genuine pair fails under a wrong authority.
  assert.equal(verifyConsumeCarrier(carrier, decodeConsumeVerificationKey(ownerPub), decodeHostPossessionVerificationKey(other.pubHex)), false);
  assert.notEqual(hostPub, other.pubHex);
});

// Public-consumer compile-time negatives: cross-purpose verifier calls must not typecheck
{
  const issRec = decodeIssuanceRecord(buildIssuanceRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" }));
  const hostRec = decodeHostPossessionRecord(buildHostPossessionRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123" }));
  const consRec = decodeConsumeRecord(buildConsumeRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456" }));
  const issProof = decodeIssuanceProof("a".repeat(128));
  const issKey = decodeIssuanceVerificationKey("a".repeat(64));
  const hostProof = decodeHostPossessionProof("b".repeat(128));
  const hostKey = decodeHostPossessionVerificationKey("b".repeat(64));
  const consProof = decodeConsumeProof("c".repeat(128));
  const consKey = decodeConsumeVerificationKey("c".repeat(64));
  // @ts-expect-error cross-purpose record must not satisfy the issuance verifier
  verifyIssuance(hostRec, issProof, issKey);
  // @ts-expect-error cross-purpose proof must not satisfy the host verifier
  verifyHostPossession(hostRec, issProof, hostKey);
  // @ts-expect-error cross-purpose key must not satisfy the host verifier
  verifyHostPossession(hostRec, hostProof, issKey);
  // @ts-expect-error cross-purpose record must not satisfy the consume verifier
  verifyConsume(issRec, consProof, consKey);
  // @ts-expect-error cross-purpose proof must not satisfy the consume verifier
  verifyConsume(consRec, issProof, consKey);
  // @ts-expect-error cross-purpose key must not satisfy the issuance verifier
  verifyIssuance(issRec, issProof, consKey);
  void issRec; void hostRec; void consRec; void hostProof; void hostKey; void consProof; void consKey;
}

// Batch C — C-19, C-21, C-23, C-25, C-26
for(const [purpose, validator, base] of [
  ["issuance", validateIssuanceCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }],
  ["host", validateHostCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }],
  ["consume", validateConsumeCarrier, { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }],
] as const) {
  for(const field of ["unknown","nested","array","record","transcript","generic-proof","policy","expiry","issuer","live-state","origin","server-result"] as const) {
    test(`carrier.rejects.${purpose}.${field}`, ()=>{ const extra:Record<string,unknown>={}; if(field==="nested") extra[field]={a:1}; else if(field==="array") extra[field]=[]; else if(field==="generic-proof") extra["proofs"]=[]; else extra[field]="extra"; assert.throws(()=>validator({ ...base, ...extra } as unknown)); });
  }
}
test("carrier.rejects.cross-purpose.issuance-to-host", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }; assert.throws(()=>validateHostCarrier(c as unknown)); });
test("carrier.rejects.cross-purpose.issuance-to-consume", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", proof:"a".repeat(128) }; assert.throws(()=>validateConsumeCarrier(c as unknown)); });
test("carrier.rejects.cross-purpose.host-to-issuance", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }; assert.throws(()=>validateIssuanceCarrier(c as unknown)); });
test("carrier.rejects.cross-purpose.host-to-consume", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123", hostProof:"a".repeat(128) }; assert.throws(()=>validateConsumeCarrier(c as unknown)); });
test("carrier.rejects.cross-purpose.consume-to-issuance", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; assert.throws(()=>validateIssuanceCarrier(c as unknown)); });
test("carrier.rejects.cross-purpose.consume-to-host", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; assert.throws(()=>validateHostCarrier(c as unknown)); });
test("carrier.consumeFreshness.fixed-input-no-clock", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"999", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; const rec=rebuildConsumeRecord(c); assert.deepEqual(parseConsumeRecord(rec).consumeFreshness, "999"); });
test("carrier.rebuild.issuance.independent-bytes", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456", proof:"a".repeat(128) }; const rec=rebuildIssuanceRecord(c); assert.ok(Buffer.from(rec).equals(Buffer.from(ORACLE_ISSUANCE))); assert.deepEqual(parseIssuanceRecord(rec), { stableId:c.stableId, hostPublic:c.hostPublic, community:c.community, device:c.device, issuedAt:c.issuedAt }); });
test("carrier.rebuild.host.independent-bytes", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"b".repeat(64), issuedAt:"123457", hostProof:"a".repeat(128) }; const rec=rebuildHostRecord(c); assert.ok(Buffer.from(rec).equals(Buffer.from(ORACLE_HOST))); assert.deepEqual(parseHostPossessionRecord(rec), { stableId:c.stableId, hostPublic:c.hostPublic, issuedAt:c.issuedAt }); });
test("carrier.rebuild.consume.independent-bytes", ()=>{ const c={ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"c".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123458", consumeFreshness:"123459", ownerProof:"a".repeat(128), hostProof:"b".repeat(128) }; const rec=rebuildConsumeRecord(c); assert.ok(Buffer.from(rec).equals(Buffer.from(ORACLE_CONSUME))); assert.deepEqual(parseConsumeRecord(rec), { stableId:c.stableId, hostPublic:c.hostPublic, community:c.community, device:c.device, issuedAt:c.issuedAt, consumeFreshness:c.consumeFreshness }); });
test("carrier.required-proof.issuance", ()=>{ assert.throws(()=>validateIssuanceCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123" } as unknown)); });
test("carrier.required-proof.host", ()=>{ assert.throws(()=>validateHostCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), issuedAt:"123" } as unknown)); });
test("carrier.required-proof.consume", ()=>{ assert.throws(()=>validateConsumeCarrier({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123", consumeFreshness:"456" } as unknown)); });
// Hostile oracle batch 1 slice — T-01..T-04, L-01..L-02, O-01, F-01..F-02 (oracle-derived)

// Hostile oracle batch 1 slice — T-01..T-04, L-01..L-02, O-01, F-01..F-02 (independent oracle bytes, not builder)
const ORACLE_ISSUANCE = new Uint8Array([0x01,0x0e,0x77,0x65,0x61,0x76,0x65,0x2d,0x69,0x73,0x73,0x75,0x65,0x2d,0x76,0x31,0x30,0x01,0x31,0x31,0x01,0x31,0x40,0x07,0x65,0x64,0x32,0x35,0x35,0x31,0x39,0x10,0x24,0x30,0x30,0x31,0x31,0x32,0x32,0x33,0x33,0x2d,0x34,0x34,0x35,0x35,0x2d,0x36,0x36,0x37,0x37,0x2d,0x38,0x38,0x39,0x39,0x2d,0x61,0x61,0x62,0x62,0x63,0x63,0x64,0x64,0x65,0x65,0x66,0x66,0x11,0x40,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x12,0x24,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x2d,0x32,0x32,0x32,0x32,0x2d,0x33,0x33,0x33,0x33,0x2d,0x34,0x34,0x34,0x34,0x2d,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x13,0x24,0x32,0x32,0x32,0x32,0x32,0x32,0x32,0x32,0x2d,0x33,0x33,0x33,0x33,0x2d,0x34,0x34,0x34,0x34,0x2d,0x35,0x35,0x35,0x35,0x2d,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x20,0x06,0x31,0x32,0x33,0x34,0x35,0x36]);
function oracleIssuance(): Uint8Array { return new Uint8Array(ORACLE_ISSUANCE); }
const ORACLE_HOST = new Uint8Array([0x01,0x0d,0x77,0x65,0x61,0x76,0x65,0x2d,0x68,0x6f,0x73,0x74,0x2d,0x76,0x31,0x30,0x01,0x31,0x31,0x01,0x31,0x40,0x07,0x65,0x64,0x32,0x35,0x35,0x31,0x39,0x10,0x24,0x30,0x30,0x31,0x31,0x32,0x32,0x33,0x33,0x2d,0x34,0x34,0x35,0x35,0x2d,0x36,0x36,0x37,0x37,0x2d,0x38,0x38,0x39,0x39,0x2d,0x61,0x61,0x62,0x62,0x63,0x63,0x64,0x64,0x65,0x65,0x66,0x66,0x11,0x40,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x62,0x20,0x06,0x31,0x32,0x33,0x34,0x35,0x37]);
const ORACLE_CONSUME = new Uint8Array([1,16,119,101,97,118,101,45,99,111,110,115,117,109,101,45,118,49,48,1,49,49,1,49,64,7,101,100,50,53,53,49,57,16,36,48,48,49,49,50,50,51,51,45,52,52,53,53,45,54,54,55,55,45,56,56,57,57,45,97,97,98,98,99,99,100,100,101,101,102,102,17,64,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,18,36,49,49,49,49,49,49,49,49,45,50,50,50,50,45,51,51,51,51,45,52,52,52,52,45,53,53,53,53,53,53,53,53,53,53,53,53,19,36,50,50,50,50,50,50,50,50,45,51,51,51,51,45,52,52,52,52,45,53,53,53,53,45,54,54,54,54,54,54,54,54,54,54,54,54,32,6,49,50,51,52,53,56,33,6,49,50,51,52,53,57]);
test("T-01 unknown tag rejects", ()=>{ const m=new Uint8Array([...ORACLE_ISSUANCE,0xFF,0x01,0x41]); assert.throws(()=>parseIssuanceRecord(m)); });
test("T-02 HOST unknown tag rejects", ()=>{ const m=new Uint8Array([...ORACLE_HOST,0xFE,0x02,0x41,0x42]); assert.throws(()=>parseHostPossessionRecord(m)); });
test("T-03 CONSUME unknown-tag insert rejects", ()=>{ assert.doesNotThrow(()=>parseConsumeRecord(new Uint8Array(ORACLE_CONSUME))); const o=new Uint8Array(ORACLE_CONSUME); const m=new Uint8Array([...o.slice(0,137),0x00,0x01,0x01,...o.slice(137)]); assert.throws(()=>parseConsumeRecord(m)); });
test("T-04 duplicate Protocol rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,19),0x30,0x01,0x31,...o.slice(19)]); assert.throws(()=>parseIssuanceRecord(m)); });
test("L-01 Purpose len 0e->0d rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[1]=0x0d; assert.throws(()=>parseIssuanceRecord(o)); });
test("L-02 HOST hostPublic len 40->3f rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); o[69]=0x3f; assert.throws(()=>parseHostPossessionRecord(o)); });
test("B-07 HOST hostPublic 40->3f + drop rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); const m=new Uint8Array([...o.slice(0,133),...o.slice(134)]); m[69]=0x3f; assert.equal(m.length,141); assert.throws(()=>parseHostPossessionRecord(m)); });
test("O-01 swap Protocol-Scheme rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,16),...o.slice(19,22),...o.slice(16,19),...o.slice(22)]); assert.throws(()=>parseIssuanceRecord(m)); });
test("F-01 purpose issues-v1 rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,11),0x73,...o.slice(11)]); m[1]=0x0f; // len to 15 then need adjust: insert shifts, we already inserted
  // rebuild correctly: purpose now 15 bytes, so use m as built with extra s
  const correct=new Uint8Array([...ORACLE_ISSUANCE.slice(0,11),0x73,...ORACLE_ISSUANCE.slice(11)]); correct[1]=0x0f; assert.throws(()=>parseIssuanceRecord(correct)); });
test("T-05 HOST duplicate hostPublic rejects", ()=>{ const tlv=new Uint8Array(ORACLE_HOST).slice(68,134); const m=new Uint8Array([...ORACLE_HOST,...tlv]); assert.throws(()=>parseHostPossessionRecord(m)); });
test("T-06 CONSUME duplicate issuedAt rejects", ()=>{ const tlv=new Uint8Array(ORACLE_CONSUME).slice(213,221); const m=new Uint8Array([...ORACLE_CONSUME,...tlv]); assert.throws(()=>parseConsumeRecord(m)); });
test("T-07 ISSUANCE remove Primitive rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,22),...o.slice(31)]); assert.throws(()=>parseIssuanceRecord(m)); });
test("T-08 HOST remove stableId rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); const m=new Uint8Array([...o.slice(0,30),...o.slice(68)]); assert.throws(()=>parseHostPossessionRecord(m)); });
test("T-09 CONSUME remove freshness rejects", ()=>{ const m=new Uint8Array([...new Uint8Array(ORACLE_CONSUME).slice(0,221)]); assert.throws(()=>parseConsumeRecord(m)); });
test("T-10 ISSUANCE swap community-device tag rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const tmp=o[135]; o[135]=o[173]; o[173]=tmp; assert.throws(()=>parseIssuanceRecord(o)); });
test("T-11 CONSUME swap issuedAt-freshness tag rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); const tmp=o[213]; o[213]=o[221]; o[221]=tmp; assert.throws(()=>parseConsumeRecord(o)); });
test("T-12 HOST append community rejects", ()=>{ const tlv=new Uint8Array(ORACLE_ISSUANCE).slice(135,173); const m=new Uint8Array([...ORACLE_HOST,...tlv]); assert.throws(()=>parseHostPossessionRecord(m)); });
test("T-13 HOST append device rejects", ()=>{ const tlv=new Uint8Array(ORACLE_ISSUANCE).slice(173,211); const m=new Uint8Array([...ORACLE_HOST,...tlv]); assert.throws(()=>parseHostPossessionRecord(m)); });
test("T-14 ISSUANCE append freshness rejects", ()=>{ const tlv=new Uint8Array(ORACLE_CONSUME).slice(221,229); const m=new Uint8Array([...new Uint8Array(ORACLE_ISSUANCE),...tlv]); assert.throws(()=>parseIssuanceRecord(m)); });
test("L-03 CONSUME purpose len 10->0f rejects", ()=>{ assert.doesNotThrow(()=>parseConsumeRecord(new Uint8Array(ORACLE_CONSUME))); const o=new Uint8Array(ORACLE_CONSUME); o[1]=0x0f; assert.throws(()=>parseConsumeRecord(o)); });
test("L-04 ISSUANCE stableId len 24->25 rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[32]=0x25; assert.throws(()=>parseIssuanceRecord(o)); });
test("L-05 HOST hostPublic len 40->41 rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); o[69]=0x41; assert.throws(()=>parseHostPossessionRecord(o)); });
test("L-06 CONSUME community len 24->26 rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); o[138]=0x26; assert.throws(()=>parseConsumeRecord(o)); });
test("L-07 ISSUANCE Protocol len 01->00 rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[17]=0x00; assert.throws(()=>parseIssuanceRecord(o)); });
test("L-08 HOST Primitive len 07->00 rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); o[22]=0x00; assert.throws(()=>parseHostPossessionRecord(o)); });
test("F-02 HOST hoat rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); o[10]=0x61; assert.throws(()=>parseHostPossessionRecord(o)); });
test("L-09 ISSUANCE stableId len 24->ff rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[32]=0xff; assert.equal(o.length,219); assert.throws(()=>parseIssuanceRecord(o)); });
test("L-10 ISSUANCE 219+13*hostPublic TLV 1077 rejects outer limit", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const block=o.slice(69,135); assert.equal(block.length,66); let m=o; for(let i=0;i<13;i++){ const n=new Uint8Array(m.length+block.length); n.set(m,0); n.set(block,m.length); m=n; } assert.equal(m.length,1077); assert.ok(m.length>1024); assert.throws(()=>parseIssuanceRecord(m)); });
test("O-02 HOST swap Primitive-stableId rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); const m=new Uint8Array([...o.slice(0,21),...o.slice(30,68),...o.slice(21,30),...o.slice(68)]); assert.equal(m.length,142); assert.throws(()=>parseHostPossessionRecord(m)); });
test("O-03 CONSUME swap issuedAt-consumeFreshness rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); const m=new Uint8Array([...o.slice(0,213),...o.slice(221,229),...o.slice(213,221)]); assert.equal(m.length,229); assert.throws(()=>parseConsumeRecord(m)); });
test("O-04 ISSUANCE move issuedAt after stableId rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,69),...o.slice(211,219),...o.slice(69,211)]); assert.equal(m.length,219); assert.throws(()=>parseIssuanceRecord(m)); });
test("O-05 CONSUME move community to end rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); const m=new Uint8Array([...o.slice(0,137),...o.slice(175),...o.slice(137,175)]); assert.equal(m.length,229); assert.throws(()=>parseConsumeRecord(m)); });

test("F-03 CONSUME purpose v2 rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); o[17]=0x32; assert.equal(o.length,229); assert.throws(()=>parseConsumeRecord(o)); });
test("F-04 ISSUANCE drop purpose last byte rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,15),...o.slice(16)]); m[1]=0x0d; assert.equal(m.length,218); assert.throws(()=>parseIssuanceRecord(m)); });
test("F-05 ISSUANCE Proto 1->2 rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[18]=0x32; assert.equal(o.length,219); assert.throws(()=>parseIssuanceRecord(o)); });
test("F-06 CONSUME Proto 1->0 rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); o[20]=0x30; assert.equal(o.length,229); assert.throws(()=>parseConsumeRecord(o)); });
test("F-07 HOST Scheme 1->0 rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); o[20]=0x30; assert.equal(o.length,142); assert.throws(()=>parseHostPossessionRecord(o)); });
test("F-08 ISSUANCE Scheme 1->11 rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,22),0x31,...o.slice(22)]); m[20]=0x02; assert.equal(m.length,220); assert.throws(()=>parseIssuanceRecord(m)); });
test("F-09 ISSUANCE ed25519->ed2551a rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[30]=0x61; assert.equal(o.length,219); assert.throws(()=>parseIssuanceRecord(o)); });
test("F-10 CONSUME ed25519->ed2551 rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); const m=new Uint8Array([...o.slice(0,32),...o.slice(33)]); m[25]=0x06; assert.equal(m.length,228); assert.throws(()=>parseConsumeRecord(m)); });
test("F-11 HOST ed25519->curve25519 rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); const m=new Uint8Array([...o.slice(0,21),0x40,0x0a,...Buffer.from("curve25519"),...o.slice(30)]); assert.equal(m.length,145); assert.throws(()=>parseHostPossessionRecord(m)); });
test("B-02 HOST stableId f->g rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); o[67]=0x67; assert.equal(o.length,142); assert.throws(()=>parseHostPossessionRecord(o)); });
test("B-03 CONSUME stableId uppercase rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); for(let i=59;i<=70;i++) o[i]=o[i]-32; assert.equal(o.length,229); assert.throws(()=>parseConsumeRecord(o)); });
test("B-04 ISSUANCE stableId dashes->dots rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[41]=0x2e; o[46]=0x2e; o[51]=0x2e; o[56]=0x2e; assert.equal(o.length,219); assert.throws(()=>parseIssuanceRecord(o)); });
test("B-05 HOST stableId 0x23+drop rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); const m=new Uint8Array([...o.slice(0,67),...o.slice(68)]); m[31]=0x23; assert.equal(m.length,141); assert.throws(()=>parseHostPossessionRecord(m)); });
test("B-06 ISSUANCE hostPublic A rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[71]=0x41; assert.equal(o.length,219); assert.throws(()=>parseIssuanceRecord(o)); });
test("B-08 CONSUME hostPublic 40->41 rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); o[72]=0x41; assert.equal(o.length,229); assert.throws(()=>parseConsumeRecord(o)); });
test("B-09 ISSUANCE hostPublic g rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); o[102]=0x67; assert.equal(o.length,219); assert.throws(()=>parseIssuanceRecord(o)); });
test("B-10 ISSUANCE community 0x23+drop rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,172),...o.slice(173)]); m[136]=0x23; assert.equal(m.length,218); assert.throws(()=>parseIssuanceRecord(m)); });
test("B-11 CONSUME device Z rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); o[212]=0x5a; assert.equal(o.length,229); assert.throws(()=>parseConsumeRecord(o)); });
test("B-12 ISSUANCE issuedAt 0123456 rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,213),0x30,...o.slice(213)]); m[212]=0x07; assert.equal(m.length,220); assert.throws(()=>parseIssuanceRecord(m)); });
test("B-13 HOST issuedAt a rejects", ()=>{ const o=new Uint8Array(ORACLE_HOST); o[141]=0x61; assert.equal(o.length,142); assert.throws(()=>parseHostPossessionRecord(o)); });
test("B-14 CONSUME issuedAt -123458 rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); const m=new Uint8Array([...o.slice(0,215),0x2d,...o.slice(215)]); m[214]=0x07; assert.equal(m.length,230); assert.throws(()=>parseConsumeRecord(m)); });
test("B-15 ISSUANCE issuedAt 17 digits rejects", ()=>{ const o=new Uint8Array(ORACLE_ISSUANCE); const m=new Uint8Array([...o.slice(0,213),...Buffer.from("12345678901234567"),...o.slice(219)]); m[212]=0x11; assert.equal(m.length,230); assert.throws(()=>parseIssuanceRecord(m)); });
test("B-16 CONSUME freshness 123459.0 rejects", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); const m=new Uint8Array([...o.slice(0,223),...Buffer.from("123459.0"),...o.slice(229)]); m[222]=0x08; assert.equal(m.length,231); assert.throws(()=>parseConsumeRecord(m)); });
test("B-17 CONSUME freshness equals issuedAt parses OK (positive)", ()=>{ const o=new Uint8Array(ORACLE_CONSUME); o[223]=0x31; o[224]=0x32; o[225]=0x33; o[226]=0x34; o[227]=0x35; o[228]=0x38; assert.equal(o.length,229); assert.doesNotThrow(()=>parseConsumeRecord(o)); assert.deepEqual(parseConsumeRecord(o), { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"c".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123458", consumeFreshness:"123458" }); });

// K-01..K-03 read-only crypto handoff — fresh in-memory Ed25519 positives, no builder
function signRecord(record: Uint8Array): { sigHex: string; pubHex: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
  const rawPublic = Buffer.from(jwk.x, "base64url");
  const signature = sign(null, Buffer.from(record), privateKey);
  assert.equal(rawPublic.length, 32);
  assert.equal(signature.length, 64);
  return { pubHex: rawPublic.toString("hex"), sigHex: signature.toString("hex") };
}
test("K-01 issuance real Ed25519 positive", () => {
  const record = new Uint8Array(ORACLE_ISSUANCE);
  assert.equal(record.length, 219);
  assert.deepEqual(parseIssuanceRecord(record), { stableId: "00112233-4455-6677-8899-aabbccddeeff", hostPublic: "a".repeat(64), community: "11111111-2222-3333-4444-555555555555", device: "22222222-3333-4444-5555-666666666666", issuedAt: "123456" });
  const { sigHex, pubHex } = signRecord(record);
  assert.match(pubHex, /^[0-9a-f]{64}$/);
  assert.match(sigHex, /^[0-9a-f]{128}$/);
  assert.equal(verifyIssuance(decodeIssuanceRecord(record), decodeIssuanceProof(sigHex), decodeIssuanceVerificationKey(pubHex)), true);
});
test("K-02 host possession real Ed25519 positive", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
  const pubHex = Buffer.from(jwk.x, "base64url").toString("hex");
  const record = buildHostPossessionRecord({ stableId: "00112233-4455-6677-8899-aabbccddeeff", hostPublic: pubHex, issuedAt: "123457" });
  assert.equal(record.length, 142);
  assert.deepEqual(parseHostPossessionRecord(record), { stableId: "00112233-4455-6677-8899-aabbccddeeff", hostPublic: pubHex, issuedAt: "123457" });
  const sigHex = sign(null, Buffer.from(record), privateKey).toString("hex");
  assert.match(pubHex, /^[0-9a-f]{64}$/);
  assert.match(sigHex, /^[0-9a-f]{128}$/);
  assert.equal(verifyHostPossession(decodeHostPossessionRecord(record), decodeHostPossessionProof(sigHex), decodeHostPossessionVerificationKey(pubHex)), true);
});
test("K-03 consume real Ed25519 positive", () => {
  const record = new Uint8Array(ORACLE_CONSUME);
  assert.equal(record.length, 229);
  assert.deepEqual(parseConsumeRecord(record), { stableId: "00112233-4455-6677-8899-aabbccddeeff", hostPublic: "c".repeat(64), community: "11111111-2222-3333-4444-555555555555", device: "22222222-3333-4444-5555-666666666666", issuedAt: "123458", consumeFreshness: "123459" });
  const { sigHex, pubHex } = signRecord(record);
  assert.match(pubHex, /^[0-9a-f]{64}$/);
  assert.match(sigHex, /^[0-9a-f]{128}$/);
  assert.equal(verifyConsume(decodeConsumeRecord(record), decodeConsumeProof(sigHex), decodeConsumeVerificationKey(pubHex)), true);
});
test("K-04 cross-purpose 3x3 verifier matrix", () => {
  const iss = new Uint8Array(ORACLE_ISSUANCE);
  const cons = new Uint8Array(ORACLE_CONSUME);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
  const pubHex = Buffer.from(jwk.x, "base64url").toString("hex");
  const host = buildHostPossessionRecord({ stableId: "00112233-4455-6677-8899-aabbccddeeff", hostPublic: pubHex, issuedAt: "123457" });
  const sigIss = sign(null, Buffer.from(iss), privateKey).toString("hex");
  const sigHost = sign(null, Buffer.from(host), privateKey).toString("hex");
  const sigCons = sign(null, Buffer.from(cons), privateKey).toString("hex");
  // matching-purpose true
  assert.equal(verifyIssuance(decodeIssuanceRecord(iss), decodeIssuanceProof(sigIss), decodeIssuanceVerificationKey(pubHex)), true);
  assert.equal(verifyHostPossession(decodeHostPossessionRecord(host), decodeHostPossessionProof(sigHost), decodeHostPossessionVerificationKey(pubHex)), true);
  assert.equal(verifyConsume(decodeConsumeRecord(cons), decodeConsumeProof(sigCons), decodeConsumeVerificationKey(pubHex)), true);
  // cross-purpose false
  assert.equal(verifyIssuance(host as unknown as IssuanceRecord, decodeIssuanceProof(sigHost), decodeIssuanceVerificationKey(pubHex)), false);
  assert.equal(verifyIssuance(cons as unknown as IssuanceRecord, decodeIssuanceProof(sigCons), decodeIssuanceVerificationKey(pubHex)), false);
  assert.equal(verifyHostPossession(iss as unknown as HostPossessionRecord, decodeHostPossessionProof(sigIss), decodeHostPossessionVerificationKey(pubHex)), false);
  assert.equal(verifyHostPossession(cons as unknown as HostPossessionRecord, decodeHostPossessionProof(sigCons), decodeHostPossessionVerificationKey(pubHex)), false);
  assert.equal(verifyConsume(iss as unknown as ConsumeRecord, decodeConsumeProof(sigIss), decodeConsumeVerificationKey(pubHex)), false);
  assert.equal(verifyConsume(host as unknown as ConsumeRecord, decodeConsumeProof(sigHost), decodeConsumeVerificationKey(pubHex)), false);
});
test("K-05 wrong-key rejects for all three purposes", () => {
  for (const [record, verifier] of [
    [new Uint8Array(ORACLE_ISSUANCE), (r: Uint8Array, s: string, p: string) => verifyIssuance(decodeIssuanceRecord(r), decodeIssuanceProof(s), decodeIssuanceVerificationKey(p))],
    [new Uint8Array(ORACLE_HOST), (r: Uint8Array, s: string, p: string) => verifyHostPossession(decodeHostPossessionRecord(r), decodeHostPossessionProof(s), decodeHostPossessionVerificationKey(p))],
    [new Uint8Array(ORACLE_CONSUME), (r: Uint8Array, s: string, p: string) => verifyConsume(decodeConsumeRecord(r), decodeConsumeProof(s), decodeConsumeVerificationKey(p))],
  ] as const) {
    const { publicKey: pk1, privateKey: sk1 } = generateKeyPairSync("ed25519");
    const { publicKey: pk2 } = generateKeyPairSync("ed25519");
    const jwk1 = pk1.export({ format: "jwk" });
    const jwk2 = pk2.export({ format: "jwk" });
    if (typeof jwk1.x !== "string" || typeof jwk2.x !== "string") throw new Error("Ed25519 JWK x missing");
    const pubHex1 = Buffer.from(jwk1.x, "base64url").toString("hex");
    const pubHex2 = Buffer.from(jwk2.x, "base64url").toString("hex");
    assert.notEqual(pubHex1, pubHex2);
    const sig = sign(null, Buffer.from(record), sk1).toString("hex");
    assert.equal(verifier(record, sig, pubHex2), false);
  }
});
test("K-06 mutated signature rejects for all three purposes", () => {
  for (const [record, verifier] of [
    [new Uint8Array(ORACLE_ISSUANCE), (r: Uint8Array, s: string, p: string) => verifyIssuance(decodeIssuanceRecord(r), decodeIssuanceProof(s), decodeIssuanceVerificationKey(p))],
    [new Uint8Array(ORACLE_HOST), (r: Uint8Array, s: string, p: string) => verifyHostPossession(decodeHostPossessionRecord(r), decodeHostPossessionProof(s), decodeHostPossessionVerificationKey(p))],
    [new Uint8Array(ORACLE_CONSUME), (r: Uint8Array, s: string, p: string) => verifyConsume(decodeConsumeRecord(r), decodeConsumeProof(s), decodeConsumeVerificationKey(p))],
  ] as const) {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" });
    if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
    const pubHex = Buffer.from(jwk.x, "base64url").toString("hex");
    const sig = sign(null, Buffer.from(record), privateKey).toString("hex");
    assert.match(sig, /^[0-9a-f]{128}$/);
    const idx = 0;
    const orig = sig[idx]!;
    const mutated = orig === "a" ? "b" : "a";
    const badSig = mutated + sig.slice(1);
    assert.notEqual(badSig, sig);
    assert.match(badSig, /^[0-9a-f]{128}$/);
    assert.equal(verifier(record, badSig, pubHex), false);
  }
});
for (const [label, oracle, verifier] of [
  ["issuance", ORACLE_ISSUANCE, (r: Uint8Array, s: string, p: string) => verifyIssuance(decodeIssuanceRecord(r), decodeIssuanceProof(s), decodeIssuanceVerificationKey(p))],
  ["host", ORACLE_HOST, (r: Uint8Array, s: string, p: string) => verifyHostPossession(decodeHostPossessionRecord(r), decodeHostPossessionProof(s), decodeHostPossessionVerificationKey(p))],
  ["consume", ORACLE_CONSUME, (r: Uint8Array, s: string, p: string) => verifyConsume(decodeConsumeRecord(r), decodeConsumeProof(s), decodeConsumeVerificationKey(p))],
] as const) {
  const rec = new Uint8Array(oracle);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
  const pubHex = Buffer.from(jwk.x, "base64url").toString("hex");
  const sigHex = sign(null, Buffer.from(rec), privateKey).toString("hex");
  const malformed = (variant: string, value: string) => `K-07 ${label} ${variant} returns false`;
  test(malformed("pubkey uppercase", pubHex), ()=>{ assert.throws(()=>verifier(rec, sigHex, pubHex.toUpperCase())); });
  test(malformed("pubkey non-hex", pubHex), ()=>{ assert.throws(()=>verifier(rec, sigHex, "g".repeat(64))); });
  test(malformed("pubkey 0x-prefixed", pubHex), ()=>{ assert.throws(()=>verifier(rec, sigHex, "0x"+pubHex)); });
  test(malformed("pubkey whitespace-padded", pubHex), ()=>{ assert.throws(()=>verifier(rec, sigHex, " "+pubHex+" ")); });
  test(malformed("pubkey truncated", pubHex), ()=>{ assert.throws(()=>verifier(rec, sigHex, pubHex.slice(0,63))); });
  test(malformed("pubkey overlong", pubHex), ()=>{ assert.throws(()=>verifier(rec, sigHex, pubHex+"00")); });
  test(malformed("pubkey empty", pubHex), ()=>{ assert.throws(()=>verifier(rec, sigHex, "")); });
  test(malformed("sig uppercase", sigHex), ()=>{ assert.throws(()=>verifier(rec, sigHex.toUpperCase(), pubHex)); });
  test(malformed("sig non-hex", sigHex), ()=>{ assert.throws(()=>verifier(rec, "g".repeat(128), pubHex)); });
  test(malformed("sig 0x-prefixed", sigHex), ()=>{ assert.throws(()=>verifier(rec, "0x"+sigHex, pubHex)); });
  test(malformed("sig whitespace-padded", sigHex), ()=>{ assert.throws(()=>verifier(rec, " "+sigHex+" ", pubHex)); });
  test(malformed("sig truncated", sigHex), ()=>{ assert.throws(()=>verifier(rec, sigHex.slice(0,127), pubHex)); });
  test(malformed("sig overlong", sigHex), ()=>{ assert.throws(()=>verifier(rec, sigHex+"00", pubHex)); });
  test(malformed("sig empty", sigHex), ()=>{ assert.throws(()=>verifier(rec, "", pubHex)); });
}
test("K-08 issuance malformed hostPublic still signed returns false", ()=>{
  const rec=new Uint8Array(ORACLE_ISSUANCE); rec[71]=0x41;
  const { publicKey, privateKey }=generateKeyPairSync("ed25519");
  const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
  const pubHex=Buffer.from(jwk.x,"base64url").toString("hex"); const sigHex=sign(null, Buffer.from(rec), privateKey).toString("hex");
  assert.match(pubHex, /^[0-9a-f]{64}$/); assert.match(sigHex, /^[0-9a-f]{128}$/);
  assert.equal(verifyIssuance(rec as unknown as IssuanceRecord, decodeIssuanceProof(sigHex), decodeIssuanceVerificationKey(pubHex)), false);
});
test("K-08 host malformed stableId still signed returns false", ()=>{
  const rec=new Uint8Array(ORACLE_HOST); rec[67]=0x67;
  const { publicKey, privateKey }=generateKeyPairSync("ed25519");
  const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
  const pubHex=Buffer.from(jwk.x,"base64url").toString("hex"); const sigHex=sign(null, Buffer.from(rec), privateKey).toString("hex");
  assert.match(pubHex, /^[0-9a-f]{64}$/); assert.match(sigHex, /^[0-9a-f]{128}$/);
  assert.equal(verifyHostPossession(rec as unknown as HostPossessionRecord, decodeHostPossessionProof(sigHex), decodeHostPossessionVerificationKey(pubHex)), false);
});
test("K-08 consume malformed device still signed returns false", ()=>{
  const rec=new Uint8Array(ORACLE_CONSUME); rec[212]=0x5a;
  const { publicKey, privateKey }=generateKeyPairSync("ed25519");
  const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
  const pubHex=Buffer.from(jwk.x,"base64url").toString("hex"); const sigHex=sign(null, Buffer.from(rec), privateKey).toString("hex");
  assert.match(pubHex, /^[0-9a-f]{64}$/); assert.match(sigHex, /^[0-9a-f]{128}$/);
  assert.equal(verifyConsume(rec as unknown as ConsumeRecord, decodeConsumeProof(sigHex), decodeConsumeVerificationKey(pubHex)), false);
});
for (const [label, oracle, offset, mutated, parser, verifier] of [
  ["K-09 issuance purpose", ORACLE_ISSUANCE, 15, 0x32, parseIssuanceRecord, verifyIssuance],
  ["K-09 issuance protocol", ORACLE_ISSUANCE, 18, 0x32, parseIssuanceRecord, verifyIssuance],
  ["K-09 issuance scheme", ORACLE_ISSUANCE, 21, 0x32, parseIssuanceRecord, verifyIssuance],
  ["K-09 issuance primitive", ORACLE_ISSUANCE, 30, 0x61, parseIssuanceRecord, verifyIssuance],
  ["K-09 host purpose", ORACLE_HOST, 14, 0x32, parseHostPossessionRecord, verifyHostPossession],
  ["K-09 host protocol", ORACLE_HOST, 17, 0x32, parseHostPossessionRecord, verifyHostPossession],
  ["K-09 host scheme", ORACLE_HOST, 20, 0x32, parseHostPossessionRecord, verifyHostPossession],
  ["K-09 host primitive", ORACLE_HOST, 29, 0x61, parseHostPossessionRecord, verifyHostPossession],
  ["K-09 consume purpose", ORACLE_CONSUME, 17, 0x32, parseConsumeRecord, verifyConsume],
  ["K-09 consume protocol", ORACLE_CONSUME, 20, 0x32, parseConsumeRecord, verifyConsume],
  ["K-09 consume scheme", ORACLE_CONSUME, 23, 0x32, parseConsumeRecord, verifyConsume],
  ["K-09 consume primitive", ORACLE_CONSUME, 32, 0x61, parseConsumeRecord, verifyConsume],
] as const) {
  test(`${label} [${offset}]->${mutated.toString(16)} parser throws and verifier false`, ()=>{
    const rec=new Uint8Array(oracle); rec[offset]=mutated;
    assert.throws(()=>parser(rec as never));
    const { publicKey, privateKey }=generateKeyPairSync("ed25519");
    const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
    const pubHex=Buffer.from(jwk.x,"base64url").toString("hex"); const sigHex=sign(null, Buffer.from(rec), privateKey).toString("hex");
    assert.match(pubHex, /^[0-9a-f]{64}$/); assert.match(sigHex, /^[0-9a-f]{128}$/);
    assert.equal(verifier(rec as never, sigHex as never, pubHex as never), false);
  });
}
for (const [label, oracle, offset, mutated, parser, verifier] of [
  ["K-10 issuance stableId", ORACLE_ISSUANCE, 33, 0x31, parseIssuanceRecord, verifyIssuance],
  ["K-10 issuance hostPublic", ORACLE_ISSUANCE, 71, 0x62, parseIssuanceRecord, verifyIssuance],
  ["K-10 issuance community", ORACLE_ISSUANCE, 137, 0x32, parseIssuanceRecord, verifyIssuance],
  ["K-10 issuance device", ORACLE_ISSUANCE, 175, 0x33, parseIssuanceRecord, verifyIssuance],
  ["K-10 issuance issuedAt", ORACLE_ISSUANCE, 213, 0x32, parseIssuanceRecord, verifyIssuance],
  ["K-10 host stableId", ORACLE_HOST, 32, 0x31, parseHostPossessionRecord, verifyHostPossession],
  ["K-10 host hostPublic", ORACLE_HOST, 70, 0x63, parseHostPossessionRecord, verifyHostPossession],
  ["K-10 host issuedAt", ORACLE_HOST, 136, 0x32, parseHostPossessionRecord, verifyHostPossession],
  ["K-10 consume stableId", ORACLE_CONSUME, 35, 0x31, parseConsumeRecord, verifyConsume],
  ["K-10 consume hostPublic", ORACLE_CONSUME, 73, 0x64, parseConsumeRecord, verifyConsume],
  ["K-10 consume community", ORACLE_CONSUME, 139, 0x32, parseConsumeRecord, verifyConsume],
  ["K-10 consume device", ORACLE_CONSUME, 177, 0x33, parseConsumeRecord, verifyConsume],
  ["K-10 consume issuedAt", ORACLE_CONSUME, 215, 0x32, parseConsumeRecord, verifyConsume],
  ["K-10 consume freshness", ORACLE_CONSUME, 223, 0x32, parseConsumeRecord, verifyConsume],
] as const) {
  test(`${label} [${offset}]->${mutated.toString(16)} canonical mutation parses but verifier false without re-sign`, ()=>{
    const orig=new Uint8Array(oracle);
    const { publicKey, privateKey }=generateKeyPairSync("ed25519");
    const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
    const pubHex=Buffer.from(jwk.x,"base64url").toString("hex"); const sigHex=sign(null, Buffer.from(orig), privateKey).toString("hex");
    const mutatedRec=new Uint8Array(orig); mutatedRec[offset]=mutated;
    assert.doesNotThrow(()=>parser(mutatedRec as never));
    assert.equal(verifier(mutatedRec as never, sigHex as never, pubHex as never), false);
  });
}
test("K-11 issuance oracle then one-field canonical mutation without re-sign", ()=>{
  const orig=new Uint8Array(ORACLE_ISSUANCE);
  const { publicKey, privateKey }=generateKeyPairSync("ed25519");
  const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
  const pubHex=Buffer.from(jwk.x,"base64url").toString("hex"); const sigHex=sign(null, Buffer.from(orig), privateKey).toString("hex");
  assert.equal(verifyIssuance(decodeIssuanceRecord(orig), decodeIssuanceProof(sigHex), decodeIssuanceVerificationKey(pubHex)), true);
  const mut=new Uint8Array(orig); mut[71]=0x62; assert.doesNotThrow(()=>parseIssuanceRecord(mut)); assert.equal(verifyIssuance(decodeIssuanceRecord(mut), decodeIssuanceProof(sigHex), decodeIssuanceVerificationKey(pubHex)), false);
});
test("K-11 host oracle then one-field canonical mutation without re-sign", ()=>{
  const { publicKey, privateKey }=generateKeyPairSync("ed25519");
  const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
  const pubHex=Buffer.from(jwk.x,"base64url").toString("hex");
  const orig=buildHostPossessionRecord({ stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic: pubHex, issuedAt:"123457" });
  const sigHex=sign(null, Buffer.from(orig), privateKey).toString("hex");
  assert.equal(verifyHostPossession(decodeHostPossessionRecord(orig), decodeHostPossessionProof(sigHex), decodeHostPossessionVerificationKey(pubHex)), true);
  const mut=new Uint8Array(orig); mut[32]=0x31; assert.doesNotThrow(()=>parseHostPossessionRecord(mut)); assert.equal(verifyHostPossession(decodeHostPossessionRecord(mut), decodeHostPossessionProof(sigHex), decodeHostPossessionVerificationKey(pubHex)), false);
});
test("K-11 consume oracle then one-field canonical mutation without re-sign", ()=>{
  const orig=new Uint8Array(ORACLE_CONSUME);
  const { publicKey, privateKey }=generateKeyPairSync("ed25519");
  const jwk=publicKey.export({format:"jwk"}); if(typeof jwk.x!=="string") throw new Error("x missing");
  const pubHex=Buffer.from(jwk.x,"base64url").toString("hex"); const sigHex=sign(null, Buffer.from(orig), privateKey).toString("hex");
  assert.equal(verifyConsume(decodeConsumeRecord(orig), decodeConsumeProof(sigHex), decodeConsumeVerificationKey(pubHex)), true);
  const mut=new Uint8Array(orig); mut[223]=0x32; assert.doesNotThrow(()=>parseConsumeRecord(mut)); assert.equal(verifyConsume(decodeConsumeRecord(mut), decodeConsumeProof(sigHex), decodeConsumeVerificationKey(pubHex)), false);
});
test("R-01 ISSUANCE +DEADBEEF rejects", ()=>{ const m=new Uint8Array([...ORACLE_ISSUANCE,0xDE,0xAD,0xBE,0xEF]); assert.equal(m.length,223); assert.throws(()=>parseIssuanceRecord(m)); });
test("R-02 HOST +00 rejects", ()=>{ const m=new Uint8Array([...ORACLE_HOST,0x00]); assert.equal(m.length,143); assert.throws(()=>parseHostPossessionRecord(m)); });
test("R-03 CONSUME +100xFF rejects", ()=>{ const m=new Uint8Array([...ORACLE_CONSUME,...Buffer.alloc(100,0xFF)]); assert.equal(m.length,329); assert.throws(()=>parseConsumeRecord(m)); });
test("R-04 ISSUANCE +duplicate issuedAt rejects", ()=>{ const m=new Uint8Array([...ORACLE_ISSUANCE,0x20,0x06,0x39,0x39,0x39,0x39,0x39,0x39]); assert.equal(m.length,227); assert.throws(()=>parseIssuanceRecord(m)); });
test("X-01 ISSUANCE via host parser rejects", ()=>{ assert.throws(()=>parseHostPossessionRecord(new Uint8Array(ORACLE_ISSUANCE))); });
test("X-02 ISSUANCE via consume parser rejects", ()=>{ assert.throws(()=>parseConsumeRecord(new Uint8Array(ORACLE_ISSUANCE))); });
test("X-03 HOST via issuance parser rejects", ()=>{ assert.throws(()=>parseIssuanceRecord(new Uint8Array(ORACLE_HOST))); });
test("X-04 HOST via consume parser rejects", ()=>{ assert.throws(()=>parseConsumeRecord(new Uint8Array(ORACLE_HOST))); });
test("X-05 CONSUME via issuance parser rejects", ()=>{ assert.throws(()=>parseIssuanceRecord(new Uint8Array(ORACLE_CONSUME))); });
test("X-06 CONSUME via host parser rejects", ()=>{ assert.throws(()=>parseHostPossessionRecord(new Uint8Array(ORACLE_CONSUME))); });

// I1.1 portability: shared m32 record layer must build/parse without Node global Buffer
test("PORTABILITY m32 records build and parse with globalThis.Buffer unavailable", ()=>{
  const g = globalThis as unknown as Record<string, unknown>;
  const saved = g.Buffer;
  g.Buffer = undefined;
  try {
    const issFields = { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"a".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123456" };
    assert.deepEqual(parseIssuanceRecord(buildIssuanceRecord(issFields)), issFields);
    const hostFields = { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"b".repeat(64), issuedAt:"123457" };
    assert.deepEqual(parseHostPossessionRecord(buildHostPossessionRecord(hostFields)), hostFields);
    const consFields = { stableId:"00112233-4455-6677-8899-aabbccddeeff", hostPublic:"c".repeat(64), community:"11111111-2222-3333-4444-555555555555", device:"22222222-3333-4444-5555-666666666666", issuedAt:"123458", consumeFreshness:"123459" };
    assert.deepEqual(parseConsumeRecord(buildConsumeRecord(consFields)), consFields);
  } finally {
    g.Buffer = saved;
  }
});
