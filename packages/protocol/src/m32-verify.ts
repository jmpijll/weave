/** Node-only M3.2-I1 verification entry point: Ed25519 verifier façades plus
 * the purpose-scoped consume-carrier composition. Importing this subpath
 * pulls `node:crypto`; the shared `@weave/protocol` root stays portable. */
export {
  verifyIssuance,
  verifyHostPossession,
  verifyConsume,
  type IssuanceProof,
  type IssuanceVerificationKey,
  type HostPossessionProof,
  type HostPossessionVerificationKey,
  type ConsumeProof,
  type ConsumeVerificationKey,
} from "./m32/verifiers.ts";
export {
  decodeIssuanceRecord,
  decodeHostPossessionRecord,
  decodeConsumeRecord,
  decodeIssuanceProof,
  decodeIssuanceVerificationKey,
  decodeHostPossessionProof,
  decodeHostPossessionVerificationKey,
  decodeConsumeProof,
  decodeConsumeVerificationKey,
} from "./m32/proofs.ts";
import { buildConsumeRecord, type ConsumeRecord } from "./m32/consume.ts";
import { buildHostPossessionRecord } from "./m32/host-possession.ts";
import { validateConsumeCarrier, type ConsumeCarrier } from "./m32/carrier.ts";
import { verifyConsume, verifyHostPossession } from "./m32/verifiers.ts";
import {
  decodeConsumeProof,
  decodeHostPossessionProof,
  type ConsumeVerificationKey,
  type HostPossessionVerificationKey,
} from "./m32/proofs.ts";

/** Purpose-scoped consume composition: verifies the owner consume proof
 * against the consume record rebuilt from the carrier claims, then
 * reconstructs the host-possession record from the same consume claims
 * (`stableId`, `hostPublic`, `issuedAt`) and verifies `hostProof` against
 * the enclosing server boundary's stored host identity —
 * `authoritativeHostKey` — never a key decoded from the presenter-supplied
 * carrier. After structural validation and before either proof is
 * evaluated, a carrier whose `hostPublic` claim differs from the stored
 * identity is rejected. Branded purpose-specific inputs only; raw crypto
 * stays verifier-internal; no generic verifier, envelope, session, route,
 * or stored state. The host proof remains a static possession assertion,
 * not liveness. */
export function verifyConsumeCarrier(c: ConsumeCarrier, ownerKey: ConsumeVerificationKey, authoritativeHostKey: HostPossessionVerificationKey): boolean {
  try { validateConsumeCarrier(c); } catch { return false; }
  if (c.hostPublic !== authoritativeHostKey) return false;
  let consumeRecord: ConsumeRecord;
  try {
    consumeRecord = buildConsumeRecord({ stableId:c.stableId, hostPublic:c.hostPublic, community:c.community, device:c.device, issuedAt:c.issuedAt, consumeFreshness:c.consumeFreshness });
    if (!verifyConsume(consumeRecord, decodeConsumeProof(c.ownerProof), ownerKey)) return false;
  } catch { return false; }
  try {
    const hostRecord = buildHostPossessionRecord({ stableId:c.stableId, hostPublic:c.hostPublic, issuedAt:c.issuedAt });
    return verifyHostPossession(hostRecord, decodeHostPossessionProof(c.hostProof), authoritativeHostKey);
  } catch { return false; }
}
