import { parseIssuanceRecord, type IssuanceRecord } from "./issuance.ts";
import { parseHostPossessionRecord, type HostPossessionRecord } from "./host-possession.ts";
import { parseConsumeRecord, type ConsumeRecord } from "./consume.ts";

/** Nominal 128-char lowercase-hex Ed25519 signature scoped to the issuance verifier. */
export type IssuanceProof = string & { readonly __weaveProofPurpose: "issuance" };
/** Nominal 64-char lowercase-hex Ed25519 key scoped to the issuance verifier. */
export type IssuanceVerificationKey = string & { readonly __weaveKeyPurpose: "issuance" };
/** Nominal 128-char lowercase-hex Ed25519 signature scoped to the host-possession verifier. */
export type HostPossessionProof = string & { readonly __weaveProofPurpose: "host-possession" };
/** Nominal 64-char lowercase-hex Ed25519 key scoped to the host-possession verifier. */
export type HostPossessionVerificationKey = string & { readonly __weaveKeyPurpose: "host-possession" };
/** Nominal 128-char lowercase-hex Ed25519 signature scoped to the consume verifier. */
export type ConsumeProof = string & { readonly __weaveProofPurpose: "consume" };
/** Nominal 64-char lowercase-hex Ed25519 key scoped to the consume verifier. */
export type ConsumeVerificationKey = string & { readonly __weaveKeyPurpose: "consume" };

/** Decode untrusted bytes as an issuance record: full grammar parse first, brand on success. */
export function decodeIssuanceRecord(raw: Uint8Array): IssuanceRecord {
  parseIssuanceRecord(raw);
  return raw as IssuanceRecord;
}
/** Decode untrusted bytes as a host-possession record: full grammar parse first, brand on success. */
export function decodeHostPossessionRecord(raw: Uint8Array): HostPossessionRecord {
  parseHostPossessionRecord(raw);
  return raw as HostPossessionRecord;
}
/** Decode untrusted bytes as a consume record: full grammar parse first, brand on success. */
export function decodeConsumeRecord(raw: Uint8Array): ConsumeRecord {
  parseConsumeRecord(raw);
  return raw as ConsumeRecord;
}
const PROOF_RE = /^[0-9a-f]{128}$/;
const KEY_RE = /^[0-9a-f]{64}$/;
/** Decode untrusted text as an issuance-scoped proof (canonical 128-char lowercase hex). */
export function decodeIssuanceProof(s: string): IssuanceProof {
  if(!PROOF_RE.test(s)) throw new Error("bad issuance proof");
  return s as IssuanceProof;
}
/** Decode untrusted text as an issuance-scoped verification key (canonical 64-char lowercase hex). */
export function decodeIssuanceVerificationKey(s: string): IssuanceVerificationKey {
  if(!KEY_RE.test(s)) throw new Error("bad issuance verification key");
  return s as IssuanceVerificationKey;
}
/** Decode untrusted text as a host-possession-scoped proof (canonical 128-char lowercase hex). */
export function decodeHostPossessionProof(s: string): HostPossessionProof {
  if(!PROOF_RE.test(s)) throw new Error("bad host-possession proof");
  return s as HostPossessionProof;
}
/** Decode untrusted text as a host-possession-scoped verification key (canonical 64-char lowercase hex). */
export function decodeHostPossessionVerificationKey(s: string): HostPossessionVerificationKey {
  if(!KEY_RE.test(s)) throw new Error("bad host-possession verification key");
  return s as HostPossessionVerificationKey;
}
/** Decode untrusted text as a consume-scoped proof (canonical 128-char lowercase hex). */
export function decodeConsumeProof(s: string): ConsumeProof {
  if(!PROOF_RE.test(s)) throw new Error("bad consume proof");
  return s as ConsumeProof;
}
/** Decode untrusted text as a consume-scoped verification key (canonical 64-char lowercase hex). */
export function decodeConsumeVerificationKey(s: string): ConsumeVerificationKey {
  if(!KEY_RE.test(s)) throw new Error("bad consume verification key");
  return s as ConsumeVerificationKey;
}
