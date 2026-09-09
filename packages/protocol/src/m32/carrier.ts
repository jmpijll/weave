import { buildIssuanceRecord } from "./issuance.ts";
import { buildHostPossessionRecord } from "./host-possession.ts";
import { buildConsumeRecord } from "./consume.ts";
export type IssuanceCarrier = { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string; proof: string };
export type HostCarrier = { stableId: string; hostPublic: string; issuedAt: string; hostProof: string };
export type ConsumeCarrier = { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string; consumeFreshness: string; ownerProof: string; hostProof: string };
function isRecord(v: unknown): v is Record<string, unknown> { return typeof v === "object" && v !== null && !Array.isArray(v); }
/** Exact already-parsed-object boundary: every declared carrier member must be
 * an own, enumerable data property. Rejects inherited members (no own
 * descriptor), accessor members (no `value`), non-enumerable required
 * members, unknown string own members whether enumerable or not, and all
 * symbol own members. Duplicate raw-JSON members cannot be detected here —
 * parsing has already collapsed them — so that belongs to a future HTTP
 * boundary, not to this pure validator. */
function assertExactShape(c: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.getOwnPropertySymbols(c).length > 0) throw new Error("symbol member rejected");
  const allowed = new Set(keys);
  for (const k of Object.getOwnPropertyNames(c)) if (!allowed.has(k)) throw new Error("unknown member: " + k);
  for (const k of keys) {
    const d = Object.getOwnPropertyDescriptor(c, k);
    if (!d || d.enumerable !== true || !("value" in d)) throw new Error("member must be an own enumerable data property: " + k);
  }
}
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HOST_RE = /^[0-9a-f]{64}$/;
const PROOF_RE = /^[0-9a-f]{128}$/;
/** Read already-gated descriptor values without re-triggering property reads:
 * the caller must have run `assertExactShape` first, so each key is an own
 * enumerable data property and `.value` cannot invoke user code. */
function readShape(c: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) out[k] = (Object.getOwnPropertyDescriptor(c, k) as PropertyDescriptor).value as unknown;
  return out;
}
function isBigIntMs(s: string): boolean { if(!/^(0|[1-9][0-9]{0,15})$/.test(s)) return false; try{ const bi=BigInt(s); return bi>=0n && bi<=9007199254740991n; }catch{ return false; } }
export function validateIssuanceCarrier(c: unknown): asserts c is IssuanceCarrier {
  if(!isRecord(c)) throw new Error("missing/invalid issuance carrier");
  const keys = ["stableId","hostPublic","community","device","issuedAt","proof"] as const;
  assertExactShape(c, keys);
  const v = readShape(c, keys);
  if(typeof v.stableId!=="string"||typeof v.hostPublic!=="string"||typeof v.community!=="string"||typeof v.device!=="string"||typeof v.issuedAt!=="string"||typeof v.proof!=="string") throw new Error("missing/invalid issuance carrier");
  if(!UUID_RE.test(v.stableId)) throw new Error("bad stableId");
  if(!HOST_RE.test(v.hostPublic)) throw new Error("bad hostPublic");
  if(!UUID_RE.test(v.community)) throw new Error("bad community");
  if(!UUID_RE.test(v.device)) throw new Error("bad device");
  if(!isBigIntMs(v.issuedAt)) throw new Error("bad issuedAt");
  if(!PROOF_RE.test(v.proof)) throw new Error("bad proof");
}
export function validateHostCarrier(c: unknown): asserts c is HostCarrier {
  if(!isRecord(c)) throw new Error("missing/invalid host carrier: hostProof required");
  const keys = ["stableId","hostPublic","issuedAt","hostProof"] as const;
  assertExactShape(c, keys);
  const v = readShape(c, keys);
  if(typeof v.stableId!=="string"||typeof v.hostPublic!=="string"||typeof v.issuedAt!=="string"||typeof v.hostProof!=="string") throw new Error("missing/invalid host carrier: hostProof required");
  if(!UUID_RE.test(v.stableId)) throw new Error("bad stableId");
  if(!HOST_RE.test(v.hostPublic)) throw new Error("bad hostPublic");
  if(!isBigIntMs(v.issuedAt)) throw new Error("bad issuedAt");
  if(!PROOF_RE.test(v.hostProof)) throw new Error("bad hostProof");
}
export function validateConsumeCarrier(c: unknown): asserts c is ConsumeCarrier {
  if(!isRecord(c)) throw new Error("missing/invalid consume carrier");
  const keys = ["stableId","hostPublic","community","device","issuedAt","consumeFreshness","ownerProof","hostProof"] as const;
  assertExactShape(c, keys);
  const v = readShape(c, keys);
  if(typeof v.stableId!=="string"||typeof v.hostPublic!=="string"||typeof v.community!=="string"||typeof v.device!=="string"||typeof v.issuedAt!=="string"||typeof v.consumeFreshness!=="string"||typeof v.ownerProof!=="string"||typeof v.hostProof!=="string") throw new Error("missing/invalid consume carrier");
  if(!UUID_RE.test(v.stableId)) throw new Error("bad stableId");
  if(!HOST_RE.test(v.hostPublic)) throw new Error("bad hostPublic");
  if(!UUID_RE.test(v.community)) throw new Error("bad community");
  if(!UUID_RE.test(v.device)) throw new Error("bad device");
  if(!isBigIntMs(v.issuedAt)) throw new Error("bad issuedAt");
  if(!isBigIntMs(v.consumeFreshness)) throw new Error("bad consumeFreshness");
  if(!PROOF_RE.test(v.ownerProof) || !PROOF_RE.test(v.hostProof)) throw new Error("bad proof");
}
export function rebuildIssuanceRecord(c: IssuanceCarrier): Uint8Array { validateIssuanceCarrier(c); return buildIssuanceRecord(c); }
export function rebuildHostRecord(c: HostCarrier): Uint8Array { validateHostCarrier(c); return buildHostPossessionRecord({ stableId:c.stableId, hostPublic:c.hostPublic, issuedAt:c.issuedAt }); }
export function rebuildConsumeRecord(c: ConsumeCarrier): Uint8Array { validateConsumeCarrier(c); return buildConsumeRecord({ stableId:c.stableId, hostPublic:c.hostPublic, community:c.community, device:c.device, issuedAt:c.issuedAt, consumeFreshness:c.consumeFreshness }); }
