import { createPublicKey, verify } from "node:crypto";
import { decodeLowerHexEd25519Key, decodeLowerHexEd25519Signature } from "../recovery/codec.ts";
import { parseIssuanceRecord, type IssuanceRecord } from "./issuance.ts";
import { parseHostPossessionRecord, type HostPossessionRecord } from "./host-possession.ts";
import { parseConsumeRecord, type ConsumeRecord } from "./consume.ts";
import type {
  IssuanceProof,
  IssuanceVerificationKey,
  HostPossessionProof,
  HostPossessionVerificationKey,
  ConsumeProof,
  ConsumeVerificationKey,
} from "./proofs.ts";

export type {
  IssuanceProof,
  IssuanceVerificationKey,
  HostPossessionProof,
  HostPossessionVerificationKey,
  ConsumeProof,
  ConsumeVerificationKey,
} from "./proofs.ts";

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100","hex");
function strictVerify(pubHex: string, data: Uint8Array, sigHex: string): boolean {
  const raw = decodeLowerHexEd25519Key(pubHex);
  const sig = decodeLowerHexEd25519Signature(sigHex);
  if(!raw||!sig) return false;
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]), format:"der", type:"spki" });
    return verify(null, Buffer.from(data), key, Buffer.from(sig));
  } catch { return false; }
}
export function verifyIssuance(record: IssuanceRecord, sigHex: IssuanceProof, pubHex: IssuanceVerificationKey): boolean {
  try { parseIssuanceRecord(record); } catch { return false; }
  return strictVerify(pubHex, record, sigHex);
}
export function verifyHostPossession(record: HostPossessionRecord, sigHex: HostPossessionProof, pubHex: HostPossessionVerificationKey): boolean {
  let fields;
  try { fields = parseHostPossessionRecord(record); } catch { return false; }
  if (fields.hostPublic !== pubHex) return false;
  return strictVerify(pubHex, record, sigHex);
}
export function verifyConsume(record: ConsumeRecord, sigHex: ConsumeProof, pubHex: ConsumeVerificationKey): boolean {
  try { parseConsumeRecord(record); } catch { return false; }
  return strictVerify(pubHex, record, sigHex);
}
