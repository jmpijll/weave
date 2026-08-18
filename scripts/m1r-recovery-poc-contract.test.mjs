/**
 * M1.R is deliberately test-only. This executable contract is not imported by
 * server runtime code and is not a credential enrolment implementation.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  createPrivateKey,
  createPublicKey,
  createHash,
  hkdfSync,
  sign,
  verify,
} from "node:crypto";
import test from "node:test";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_DIRECTORY = join(ROOT, "apps/server/test/recovery-poc");
const vector = JSON.parse(
  await readFile(join(FIXTURE_DIRECTORY, "public-vector-v1.json"), "utf8"),
);
const adversarial = JSON.parse(
  await readFile(join(FIXTURE_DIRECTORY, "adversarial-v1.json"), "utf8"),
);

const ENVIRONMENT_CODES = Object.freeze({
  production: 1,
  staging: 2,
  development: 3,
  test: 4,
});
const SIGNATURE_ALGORITHM_ED25519 = 1;
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function hex(value) {
  assert.match(value, /^(?:[0-9a-f]{2})+$/i, "expected non-empty even-length hexadecimal");
  return Buffer.from(value, "hex");
}

function u16(value) {
  assert.ok(Number.isInteger(value) && value >= 0 && value <= 0xffff, "u16 range");
  const output = Buffer.alloc(2);
  output.writeUInt16BE(value);
  return output;
}

function i64(value) {
  const output = Buffer.alloc(8);
  output.writeBigInt64BE(BigInt(value));
  return output;
}

function uuidBytes(value) {
  assert.match(value, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i, "RFC 4122 UUID text");
  return hex(value.replaceAll("-", ""));
}

function canonicalTlsOrigin(value) {
  const parsed = new URL(value);
  assert.equal(parsed.protocol, "wss:", "recovery origin must use TLS WebSocket");
  assert.equal(parsed.username, "", "origin has no user info");
  assert.equal(parsed.password, "", "origin has no password");
  assert.equal(parsed.pathname, "/", "origin has no path");
  assert.equal(parsed.search, "", "origin has no query");
  assert.equal(parsed.hash, "", "origin has no fragment");
  assert.ok(parsed.hostname.length > 0, "origin has hostname");
  assert.equal(value, parsed.origin, "origin must be canonical");
  const encoded = Buffer.from(value, "utf8");
  assert.ok(encoded.length >= 1 && encoded.length <= 255, "origin byte length");
  return encoded;
}

function hkdfInfo(environment, purpose) {
  assert.equal(ENVIRONMENT_CODES[environment] !== undefined, true, "known environment");
  assert.ok(["root-signing", "recovery-proof"].includes(purpose), "known role purpose");
  return Buffer.from(`weave-recovery\0v1\0${environment}\0ed25519\0${purpose}`, "utf8");
}

function deriveSeed(entropy, environment, purpose) {
  return Buffer.from(
    hkdfSync(
      "sha256",
      entropy,
      Buffer.from("weave/recovery/v1/hkdf-salt", "utf8"),
      hkdfInfo(environment, purpose),
      32,
    ),
  );
}

function privateKeyFromSeed(seed) {
  assert.equal(seed.length, 32, "Ed25519 seed length");
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyBytes(privateKey) {
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return spki.subarray(-32);
}

function transcriptBytes(challenge) {
  const origin = canonicalTlsOrigin(challenge.tlsOrigin);
  assert.equal(challenge.signatureAlgorithmCode, SIGNATURE_ALGORITHM_ED25519);
  assert.equal(ENVIRONMENT_CODES.test, challenge.environmentCode);
  assert.equal(challenge.protocolVersion, 1);
  assert.equal(challenge.schemeVersion, 1);
  assert.equal(challenge.domain, "weave/recovery/proof");
  const nonce = hex(challenge.nonceHex);
  const deviceKey = hex(challenge.intendedDevicePublicKeyHex);
  assert.equal(nonce.length, 32, "nonce length");
  assert.equal(deviceKey.length, 32, "device key length");
  assert.ok(BigInt(challenge.expiryUnixMs) > 0n, "positive expiry");
  return Buffer.concat([
    u16(Buffer.byteLength(challenge.domain)),
    Buffer.from(challenge.domain, "ascii"),
    u16(challenge.protocolVersion),
    u16(challenge.schemeVersion),
    Buffer.from([challenge.environmentCode, challenge.signatureAlgorithmCode]),
    u16(origin.length),
    origin,
    uuidBytes(challenge.personId),
    uuidBytes(challenge.recoveryVerifierId),
    uuidBytes(challenge.communityId),
    uuidBytes(challenge.challengeId),
    nonce,
    deviceKey,
    i64(challenge.expiryUnixMs),
  ]);
}

function publicKeyFromRawEd25519(raw) {
  assert.equal(raw.length, 32, "Ed25519 public key length");
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
    format: "der",
    type: "spki",
  });
}

test("M1.R public vector reproduces two domain-separated Ed25519 roles", () => {
  assert.equal(vector.classification, "non-production-test-data-only");
  assert.deepEqual(vector.notFor, ["accounts", "endpoints", "logs", "telemetry", "crash-reports", "prompts"]);
  const entropy = hex(vector.derivation.entropyHex);
  assert.equal(entropy.length, 32);
  const words = vector.derivation.bip39English24.split(" ");
  assert.equal(words.length, 24);
  assert.deepEqual(words.slice(0, 23), Array(23).fill("abandon"));
  assert.equal(words[23], "art");
  assert.equal(createHash("sha256").update(entropy).digest()[0], 0x66, "BIP-39 checksum byte");
  assert.deepEqual(vector.derivation.prohibited, ["bip39-pbkdf2-seed", "bip39-passphrase"]);
  assert.equal(vector.derivation.hkdf.environmentCode, ENVIRONMENT_CODES.test);

  const rootSeed = deriveSeed(entropy, "test", "root-signing");
  const recoverySeed = deriveSeed(entropy, "test", "recovery-proof");
  assert.equal(rootSeed.toString("hex"), vector.derivation.root.seedHex);
  assert.equal(recoverySeed.toString("hex"), vector.derivation.recoveryProof.seedHex);
  assert.notDeepEqual(rootSeed, recoverySeed);

  const rootPrivateKey = privateKeyFromSeed(rootSeed);
  const recoveryPrivateKey = privateKeyFromSeed(recoverySeed);
  assert.equal(publicKeyBytes(rootPrivateKey).toString("hex"), vector.derivation.root.publicKeyHex);
  assert.equal(publicKeyBytes(recoveryPrivateKey).toString("hex"), vector.derivation.recoveryProof.publicKeyHex);
  assert.notDeepEqual(publicKeyBytes(rootPrivateKey), publicKeyBytes(recoveryPrivateKey));
  assert.notDeepEqual(deriveSeed(entropy, "production", "root-signing"), rootSeed);
});

test("M1.R transcript is byte-canonical and both raw Ed25519 proofs verify", () => {
  const transcript = transcriptBytes(vector.challenge);
  assert.equal(transcript.toString("hex"), vector.challenge.canonicalTranscriptHex);
  const rootSignature = hex(vector.proof.rootSignatureHex);
  const recoverySignature = hex(vector.proof.recoveryProofSignatureHex);
  assert.equal(rootSignature.length, 64);
  assert.equal(recoverySignature.length, 64);
  assert.equal(
    verify(null, transcript, publicKeyFromRawEd25519(hex(vector.derivation.root.publicKeyHex)), rootSignature),
    true,
  );
  assert.equal(
    verify(null, transcript, publicKeyFromRawEd25519(hex(vector.derivation.recoveryProof.publicKeyHex)), recoverySignature),
    true,
  );
  assert.equal(
    verify(null, transcript, publicKeyFromRawEd25519(hex(vector.derivation.root.publicKeyHex)), recoverySignature),
    false,
  );

  const mutated = Buffer.from(transcript);
  mutated[mutated.length - 1] ^= 1;
  assert.equal(
    verify(null, mutated, publicKeyFromRawEd25519(hex(vector.derivation.root.publicKeyHex)), rootSignature),
    false,
  );
});

test("M1.R parser rejects non-canonical origin and invalid fixed-width fields", () => {
  assert.throws(() => canonicalTlsOrigin("wss://RECOVERY-poc.invalid:8443"));
  assert.throws(() => canonicalTlsOrigin("wss://recovery-poc.invalid:8443/path"));
  assert.throws(() => canonicalTlsOrigin("ws://recovery-poc.invalid:8443"));
  assert.equal(
    uuidBytes("00112233-4455-6677-8899-aabbccddeeff").toString("hex"),
    "00112233445566778899aabbccddeeff",
    "UUIDs use RFC 4122 text order, never a platform GUID memory layout",
  );
  assert.throws(() => transcriptBytes({ ...vector.challenge, nonceHex: "00".repeat(31) }));
  assert.throws(() => transcriptBytes({ ...vector.challenge, environmentCode: 3 }));
  assert.throws(() => transcriptBytes({ ...vector.challenge, signatureAlgorithmCode: 2 }));
});

test("M1.R secret-free adversarial bundle names the independently executable state bar", () => {
  assert.equal(adversarial.classification, "secret-free-state-and-adversarial-fixture");
  assert.equal(adversarial.serverConfiguration.environmentCode, ENVIRONMENT_CODES.test);
  assert.equal(adversarial.serverConfiguration.environment, adversarial.storedState.environment);
  assert.equal(adversarial.storedState.algorithm, "ed25519");
  assert.equal(adversarial.storedState.schemeVersion, 1);
  assert.equal(adversarial.issuedChallenge.consumedAt, null, "consumed_at is server state, not signed bytes");
  assert.equal(adversarial.issuedChallenge.challengeId, vector.challenge.challengeId);
  assert.equal(adversarial.issuedChallenge.tlsOrigin, vector.challenge.tlsOrigin);
  assert.equal(adversarial.issuedChallenge.environmentCode, ENVIRONMENT_CODES.test);
  assert.equal(adversarial.issuedChallenge.canonicalTranscriptHex, vector.challenge.canonicalTranscriptHex);
  assert.equal(adversarial.issuedChallenge.rootSignatureHex, vector.proof.rootSignatureHex);
  assert.equal(adversarial.issuedChallenge.recoveryProofSignatureHex, vector.proof.recoveryProofSignatureHex);
  assert.equal(hex(adversarial.issuedChallenge.rootSignatureHex).length, 64);
  assert.equal(hex(adversarial.issuedChallenge.recoveryProofSignatureHex).length, 64);
  assert.deepEqual(adversarial.containsNo, ["mnemonic-value", "entropy-value", "ikm-value", "private-key", "seed", "chain-code", "reversible-export"]);
  const expected = new Set([
    "valid-first-submit", "root-only-proof", "mutated-transcript", "expired-challenge",
    "origin-substitution", "community-substitution", "device-substitution", "environment-triple-mismatch",
    "unknown-or-malformed-parser-field", "replayed-consumed-challenge", "concurrent-double-consume",
    "root-only-verifier-transition", "atomic-admin-rebind", "root-authorized-device-enrollment-audit",
    "credential-revocation-audit",
  ]);
  assert.deepEqual(new Set(adversarial.cases.map((entry) => entry.id)), expected);
  assert.deepEqual(
    new Set(adversarial.cases.map((entry) => entry.auditType).filter(Boolean)),
    new Set([
      "root_authorized_device_enrollment",
      "recovery_secret_proven_enrollment",
      "identity_recovery",
      "credential_revocation",
    ]),
  );
});

test("M1.R artifacts remain test-only and production server has no recovery route", async () => {
  const serverSource = await readFile(join(ROOT, "apps/server/src/index.ts"), "utf8");
  assert.equal(serverSource.includes("recovery-poc"), false);
  assert.equal(serverSource.includes("recovery_secret"), false);
  const fixturePaths = ["public-vector-v1.json", "adversarial-v1.json"];
  for (const fixturePath of fixturePaths) {
    const fixture = await readFile(join(FIXTURE_DIRECTORY, fixturePath), "utf8");
    assert.equal(fixture.includes("/src/"), false, "fixture has no runtime import path");
  }
});

// Keep sign imported and exercised in this test-only module: an independent
// implementation can regenerate the published signatures from the public seed.
test("M1.R published signatures are deterministic for the public test vector", () => {
  const root = privateKeyFromSeed(hex(vector.derivation.root.seedHex));
  const recovery = privateKeyFromSeed(hex(vector.derivation.recoveryProof.seedHex));
  const transcript = transcriptBytes(vector.challenge);
  assert.equal(sign(null, transcript, root).toString("hex"), vector.proof.rootSignatureHex);
  assert.equal(sign(null, transcript, recovery).toString("hex"), vector.proof.recoveryProofSignatureHex);
});
