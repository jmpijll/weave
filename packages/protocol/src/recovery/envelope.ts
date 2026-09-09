/**
 * Weave M1.3.2 — frozen S8 wire envelope types and the ratified S9 transcript
 * byte layout.
 *
 * The success shape is exactly `{ "status": "verified", "requestId": "…" }` on
 * `application/json; charset=utf-8`; every refusal uses the frozen S8 envelope
 * `{ "error": { "code", "message", "requestId" } }` on the same content type.
 * A `requestId` is a server-generated diagnostic correlation id only — it is
 * never a credential, token, or capability, and it must not contain a secret or
 * a binding discriminator.
 */

import type { RecoveryErrorCode } from "./registry.ts";

export interface RecoveryVerifyOk {
  status: "verified";
  requestId: string;
}

export interface RecoveryErrorEnvelope {
  error: {
    code: RecoveryErrorCode;
    message: string;
    requestId: string;
  };
}

/**
 * The M1.3.2 `POST /v1/identity/recovery/verify` request body (ADR §M1.3.2
 * verification-only wire endpoint). The client supplies every S9 binding
 * value plus the resulting canonical transcript and both proofs; the domain,
 * algorithm text, and stored root/verifier public material are protocol or
 * persistence values, never request fields.
 */
export interface RecoveryVerifyRequest {
  challengeId: string;
  personId: string;
  recoveryVerifierId: string;
  communityId: string;
  protocolVersion: number;
  schemeVersion: number;
  algorithmCode: number;
  environmentCode: number;
  tlsOrigin: string;
  nonce: string;
  intendedDevicePublicKey: string;
  canonicalTranscript: string;
  rootSignature: string;
  recoveryProofSignature: string;
}

/** The S9 transcript values needed to rebuild the ratified byte layout. */
export interface RecoveryTranscriptMaterial {
  domain: string;
  protocolVersion: number;
  schemeVersion: number;
  environmentCode: number;
  signatureAlgorithmCode: number;
  tlsOrigin: string;
  personId: string;
  recoveryVerifierId: string;
  communityId: string;
  challengeId: string;
  nonce: Uint8Array;
  intendedDevicePublicKey: Uint8Array;
  expiryUnixMs: number;
}

function u16(value: number): Buffer {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

function i64(value: number | bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigInt64BE(BigInt(value));
  return out;
}

function uuidRaw(value: string): Buffer {
  const stripped = value.replaceAll("-", "");
  const bytes = Buffer.from(stripped, "hex");
  if (bytes.length !== 16) {
    throw new Error(`invalid UUID text: ${value}`);
  }
  return bytes;
}

/**
 * Rebuild the exact v1 S9 transcript bytes the two Ed25519 signatures cover.
 *
 * This is the fixed binary layout ratified by the accepted POC
 * (`contract.mjs:transcriptBytes` at `4acb141`):
 *
 *  1. big-endian u16 domain byte length, then ASCII domain;
 *  2. big-endian u16 protocol version 1, then big-endian u16 scheme version 1;
 *  3. one-byte environment code and one-byte Ed25519 algorithm code 1;
 *  4. big-endian u16 UTF-8 `wss://` origin byte length, then canonical TLS
 *     origin bytes (nonempty, at most 255 bytes);
 *  5. person, recovery-verifier, community, and challenge UUIDs as the 16 raw
 *     bytes represented by RFC 4122 text order, in that order;
 *  6. 32-byte nonce, 32-byte intended device public key, and signed big-endian
 *     i64 expiry Unix milliseconds.
 *
 * The caller is responsible for canonicalizing `tlsOrigin` (origin equality,
 * `wss:` protocol) before calling; this builder validates lengths and re-checks
 * byte length but does not perform full canonical origin parsing (M1.3.2 owns
 * that at the boundary).
 */
export function buildRecoveryTranscript(material: RecoveryTranscriptMaterial): Buffer {
  const originBytes = Buffer.from(material.tlsOrigin, "utf8");
  if (originBytes.length === 0 || originBytes.length > 255) {
    throw new Error(`canonical TLS origin must be 1..255 UTF-8 bytes, got ${originBytes.length}`);
  }
  if (material.nonce.length !== 32) {
    throw new Error(`nonce must be 32 bytes, got ${material.nonce.length}`);
  }
  if (material.intendedDevicePublicKey.length !== 32) {
    throw new Error(`intended device public key must be 32 bytes, got ${material.intendedDevicePublicKey.length}`);
  }
  if (material.protocolVersion !== 1 || material.schemeVersion !== 1 || material.signatureAlgorithmCode !== 1) {
    throw new Error("v1 transcript requires protocol/scheme/algorithm-code equal to 1");
  }
  // v1 permits only the four named environment codes `1..4`. The builder must
  // not create a transcript the protocol otherwise rejects, so non-integers and
  // any code outside `1..4` are refused here (M1.3.2).
  if (!Number.isInteger(material.environmentCode) || material.environmentCode < 1 || material.environmentCode > 4) {
    throw new Error("v1 transcript requires environment code to be an integer 1..4");
  }

  const domainBytes = Buffer.from(material.domain, "ascii");
  return Buffer.concat([
    u16(domainBytes.length),
    domainBytes,
    u16(material.protocolVersion),
    u16(material.schemeVersion),
    Buffer.from([material.environmentCode, material.signatureAlgorithmCode]),
    u16(originBytes.length),
    originBytes,
    uuidRaw(material.personId),
    uuidRaw(material.recoveryVerifierId),
    uuidRaw(material.communityId),
    uuidRaw(material.challengeId),
    Buffer.from(material.nonce),
    Buffer.from(material.intendedDevicePublicKey),
    i64(material.expiryUnixMs),
  ]);
}
