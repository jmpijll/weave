/**
 * Weave M3.2 I4.2 — locked server consume command for `POST /v1/hosts/enroll`.
 *
 * One `withTransaction` callback on a single `PoolClient`: either the pending
 * token is conditionally consumed plus exactly one host credential, one host
 * row, and exactly one `host.enrolled` audit commits — or the transaction
 * rolls back with the token left pending and no host/host-credential/audit at
 * all. Authority always comes from the stored token row, never caller claims:
 * the stored issuer device key verifies the owner consume proof, the stored
 * host key verifies the host-possession proof, and every immutable binding
 * must equal the row.
 *
 * Lock order (deadlock-safe with I4.1 issue): inside the mutation
 * transaction, the candidate token row `FOR UPDATE` first (serializes
 * competing consumes), then policy `FOR SHARE`, then issuer and root in
 * ascending UUID order `FOR UPDATE`, then the active human member for the
 * stored community last `FOR UPDATE`.
 *
 * Stored-row-first sequencing: before the transaction begins, the candidate
 * row is read unlocked and both proofs are verified against the stored keys
 * with every immutable binding checked for equality. A structurally valid
 * but cryptographically invalid carrier therefore refuses without acquiring
 * or waiting on any lock. The transaction re-reads and revalidates the same
 * facts and live authority under its locks before consuming, so a row that
 * changed between the pre-read and the lock acquisition is still refused.
 */
import type { Pool, PoolClient } from "pg";
import { buildConsumeRecord, buildHostPossessionRecord } from "@weave/protocol";
import { verifyConsume, verifyHostPossession } from "@weave/protocol/m32-verify";
import { writeAuditEvent, AUDIT_EVENT } from "../db/audit.ts";
import { withTransaction } from "../db/transaction.ts";

export const CONSUME_FRESHNESS_MS = 300_000n;
export const CONSUME_FUTURE_SKEW_MS = 30_000n;
export const CONSUME_MAX_MS = 9_007_199_254_740_991n;
export const CONSUME_POLICY_VERSION = 1;

export interface ConsumeInput {
  stableId: string;
  hostPublic: string;
  community: string;
  device: string;
  issuedAt: string;
  consumeFreshness: string;
  ownerProof: string;
  hostProof: string;
}

export type ConsumeResult = { ok: true } | { ok: false };

/**
 * Expected post-consume refusal (e.g. globally duplicate host key): aborts
 * the transaction so the consume + any partial host writes roll back and the
 * token is left pending, while still mapping to the collapsed refusal —
 * never the redacted 503. Audit-write failures must NOT use this path: they
 * propagate and reach the 503 catch-all.
 */
class EnrollAbort extends Error {
  constructor() {
    super("enroll refused after consume; rolled back");
  }
}

function parseMsText(value: string): bigint | null {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) return null;
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    return null;
  }
  if (parsed < 0n || parsed > CONSUME_MAX_MS) return null;
  return parsed;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function consumePairingToken(
  pool: Pool,
  input: ConsumeInput,
  requestId: string,
): Promise<ConsumeResult> {
  if (
    !UUID_RE.test(input.stableId) ||
    !UUID_RE.test(input.community) ||
    !UUID_RE.test(input.device) ||
    !/^[0-9a-f]{64}$/.test(input.hostPublic) ||
    !/^[0-9a-f]{128}$/.test(input.ownerProof) ||
    !/^[0-9a-f]{128}$/.test(input.hostProof)
  ) {
    return { ok: false };
  }
  const issuedAt = parseMsText(input.issuedAt);
  const consumeFreshness = parseMsText(input.consumeFreshness);
  if (issuedAt === null || consumeFreshness === null) return { ok: false };

  // Stored-row-first pre-check, outside any transaction and without locks:
  // read the candidate row, check binding equality, and verify both proofs
  // against the stored keys. Invalid carriers refuse here and never touch
  // the token/authority locks. Live authority (revocation, membership,
  // expiry, pending state) is revalidated under lock inside the transaction.
  const precheck = await precheckConsume(pool, input);
  if (!precheck.ok) return { ok: false };

  return withTransaction(pool, (client) =>
    consumeInTransaction(client, input, consumeFreshness, requestId),
  ).catch((error) => {
    if (error instanceof EnrollAbort) return { ok: false };
    throw error;
  });
}

interface StoredCandidate {
  device: string;
  hostPublic: string;
  community: string;
  issuedAt: string;
  ownerKey: string;
}

async function readStoredCandidate(pool: Pool, input: ConsumeInput): Promise<StoredCandidate | null> {
  const token = await pool.query(
    `SELECT issued_by_credential_id, host_public_key, community_id,
            issued_at::text AS issued_at, consumed_at
     FROM pairing_token WHERE id = $1`,
    [input.stableId],
  );
  if (token.rows.length === 0) return null;
  const row = token.rows[0] as Record<string, unknown>;
  if (row.consumed_at != null) return null;
  if (
    String(row.issued_by_credential_id) !== input.device ||
    String(row.host_public_key) !== input.hostPublic ||
    String(row.community_id) !== input.community ||
    String(row.issued_at) !== input.issuedAt
  ) {
    return null;
  }
  const deviceRow = await pool.query(
    `SELECT public_key, kind, algorithm FROM credential WHERE id = $1`,
    [input.device],
  );
  if (deviceRow.rows.length === 0) return null;
  const device = deviceRow.rows[0] as Record<string, unknown>;
  if (device.kind !== "human" || device.algorithm !== "ed25519") return null;
  if (typeof device.public_key !== "string" || !/^[0-9a-f]{64}$/.test(device.public_key)) return null;
  return {
    device: input.device,
    hostPublic: String(row.host_public_key),
    community: input.community,
    issuedAt: input.issuedAt,
    ownerKey: device.public_key,
  };
}

function verifyCarrierProofs(input: ConsumeInput, stored: StoredCandidate): boolean {
  let consumeRecord: Uint8Array;
  try {
    consumeRecord = buildConsumeRecord({
      stableId: input.stableId,
      hostPublic: stored.hostPublic,
      community: stored.community,
      device: stored.device,
      issuedAt: stored.issuedAt,
      consumeFreshness: input.consumeFreshness,
    });
  } catch {
    return false;
  }
  try {
    if (
      !verifyConsume(
        consumeRecord as Parameters<typeof verifyConsume>[0],
        input.ownerProof as Parameters<typeof verifyConsume>[1],
        stored.ownerKey as Parameters<typeof verifyConsume>[2],
      )
    ) {
      return false;
    }
  } catch {
    return false;
  }
  let hostRecord: Uint8Array;
  try {
    hostRecord = buildHostPossessionRecord({
      stableId: input.stableId,
      hostPublic: stored.hostPublic,
      issuedAt: stored.issuedAt,
    });
  } catch {
    return false;
  }
  try {
    return verifyHostPossession(
      hostRecord as Parameters<typeof verifyHostPossession>[0],
      input.hostProof as Parameters<typeof verifyHostPossession>[1],
      stored.hostPublic as Parameters<typeof verifyHostPossession>[2],
    );
  } catch {
    return false;
  }
}

async function precheckConsume(pool: Pool, input: ConsumeInput): Promise<{ ok: boolean }> {
  const stored = await readStoredCandidate(pool, input);
  if (stored === null) return { ok: false };
  return { ok: verifyCarrierProofs(input, stored) };
}

async function consumeInTransaction(
  client: PoolClient,
  input: ConsumeInput,
  consumeFreshness: bigint,
  requestId: string,
): Promise<ConsumeResult> {
  const refuse = (): ConsumeResult => ({ ok: false });

  // 1. Lock the candidate token row FOR UPDATE first: competing consumes
  //    serialize here. The unlocked pre-check already passed, but the row is
  //    re-read and every fact revalidated under this lock, so a row that
  //    changed in between is refused. No disclosure — absence, consumed
  //    state, or any mismatch all refuse identically.
  const token = await client.query(
    `SELECT id, issued_by_credential_id, host_public_key, community_id,
            issued_at::text AS issued_at, expires_at::text AS expires_at,
            policy_version, consumed_at
     FROM pairing_token WHERE id = $1 FOR UPDATE`,
    [input.stableId],
  );
  if (token.rows.length === 0) return refuse();
  const row = token.rows[0] as Record<string, unknown>;
  if (row.consumed_at != null) return refuse();
  // Every immutable binding must equal the stored row; the carrier never
  // selects authority.
  if (
    String(row.issued_by_credential_id) !== input.device ||
    String(row.host_public_key) !== input.hostPublic ||
    String(row.community_id) !== input.community ||
    String(row.issued_at) !== input.issuedAt ||
    Number(row.policy_version) !== CONSUME_POLICY_VERSION
  ) {
    return refuse();
  }
  const expiresAt = parseMsText(String(row.expires_at));
  if (expiresAt === null) return refuse();

  // 2. Lock policy version 1 FOR SHARE; the stored policy version is already
  //    pinned to the sole version above.
  const policy = await client.query(
    `SELECT duration_ms::text AS duration_ms FROM pairing_policy_registry WHERE version = $1 FOR SHARE`,
    [CONSUME_POLICY_VERSION],
  );
  if (policy.rows.length === 0) return refuse();
  if (parseMsText(String(policy.rows[0].duration_ms)) === null) return refuse();

  // 3. Resolve the stored issuer device's parent, then lock issuer and root
  //    in ascending UUID order FOR UPDATE; lock the active human member for
  //    the stored community last FOR UPDATE; re-read and validate the exact
  //    direct device/root/person/member relation under lock.
  const deviceRow = await client.query(
    `SELECT id, person_id, public_key, kind, algorithm, parent_credential_id, revoked_at
     FROM credential WHERE id = $1`,
    [input.device],
  );
  if (deviceRow.rows.length === 0) return refuse();
  const device = deviceRow.rows[0] as Record<string, unknown>;
  if (device.kind !== "human" || device.algorithm !== "ed25519") return refuse();
  if (device.parent_credential_id == null) return refuse();
  const rootId = String(device.parent_credential_id);

  const [firstId, secondId] =
    String(input.device) < rootId
      ? [String(input.device), rootId]
      : [rootId, String(input.device)];
  // Deterministic ascending-UUID lock order: two separate ordered row locks,
  // mirroring the 0007 backstop. A single `WHERE id = $1 OR id = $2` query
  // must not be used — parameter order does not govern lock acquisition.
  await client.query(`SELECT 1 FROM credential WHERE id = $1 FOR UPDATE`, [firstId]);
  await client.query(`SELECT 1 FROM credential WHERE id = $1 FOR UPDATE`, [secondId]);
  const lockedCreds = await client.query(
    `SELECT id, person_id, public_key, kind, algorithm, parent_credential_id, revoked_at
     FROM credential WHERE id = $1 OR id = $2`,
    [firstId, secondId],
  );
  if (lockedCreds.rows.length !== 2) return refuse();
  const byId = new Map<string, Record<string, unknown>>();
  for (const r of lockedCreds.rows as Record<string, unknown>[]) {
    byId.set(String(r.id), r);
  }
  const lockedDevice = byId.get(String(input.device));
  const lockedRoot = byId.get(rootId);
  if (!lockedDevice || !lockedRoot) return refuse();
  if (String(lockedDevice.parent_credential_id) !== rootId) return refuse();
  if (lockedRoot.parent_credential_id != null) return refuse();
  if (lockedRoot.kind !== "human" || lockedRoot.algorithm !== "ed25519") return refuse();
  if (lockedDevice.kind !== "human" || lockedDevice.algorithm !== "ed25519") return refuse();
  if (String(lockedDevice.person_id) !== String(lockedRoot.person_id)) return refuse();
  if (lockedDevice.revoked_at != null || lockedRoot.revoked_at != null) return refuse();
  const personId = String(lockedDevice.person_id);
  if (typeof lockedDevice.public_key !== "string" || !/^[0-9a-f]{64}$/.test(lockedDevice.public_key)) {
    return refuse();
  }
  const ownerKey = lockedDevice.public_key;
  const storedHostKey = String(row.host_public_key);

  const member = await client.query(
    `SELECT id, person_id FROM member
     WHERE community_id = $1 AND subject_kind = 'human' AND person_id = $2 AND revoked_at IS NULL
     FOR UPDATE`,
    [input.community, personId],
  );
  if (member.rows.length === 0) return refuse();
  const memberRow = member.rows[0] as Record<string, unknown>;
  const memberId = String(memberRow.id);

  // 4. Revalidate both proofs under the stored keys (same check as the
  //    unlocked pre-read, now against the locked row facts and the locked
  //    device key): the owner consume proof against the consume record, the
  //    host proof against the host-possession record keyed by the stored host
  //    identity — never a caller key. A row that changed between the
  //    pre-read and these locks is refused here.
  if (
    !verifyCarrierProofs(input, {
      device: input.device,
      hostPublic: storedHostKey,
      community: input.community,
      issuedAt: input.issuedAt,
      ownerKey,
    })
  ) {
    return refuse();
  }

  // 5. Sample one post-lock DB wall clock as text decimal ms, validate its
  //    range, enforce consume freshness edges with BigInt, and consume only a
  //    token whose expiry is still after that clock.
  const clock = await client.query(
    `SELECT (floor(extract(epoch from clock_timestamp()) * 1000))::text AS now_ms`,
  );
  const nowMs = parseMsText(String(clock.rows[0].now_ms));
  if (nowMs === null) return refuse();
  if (consumeFreshness > nowMs + CONSUME_FUTURE_SKEW_MS) return refuse();
  if (nowMs > consumeFreshness + CONSUME_FRESHNESS_MS) return refuse();
  if (expiresAt <= nowMs) return refuse();

  // 6. Conditionally consume only a still-pending token. The rival that lost
  //    the token lock observes the winner's consumed value and refuses; the
  //    token stays pending only when nothing was written.
  const consumed = await client.query(
    `UPDATE pairing_token SET consumed_at = $1 WHERE id = $2 AND consumed_at IS NULL`,
    [nowMs.toString(), input.stableId],
  );
  if (consumed.rowCount !== 1) return refuse();

  // 7. Create one host credential under the locked human root, then one host
  //    row. A globally duplicate host key aborts the whole transaction —
  //    including the consume — so the token is left pending; the abort still
  //    maps to the collapsed refusal. `ON CONFLICT DO NOTHING` is only an
  //    arbitration primitive here: no error is raised, and the throw rolls
  //    everything back.
  const hostCred = await client.query(
    `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
     VALUES ($1, $2, 'ed25519', 'host', $3)
     ON CONFLICT (algorithm, public_key) DO NOTHING
     RETURNING id`,
    [personId, storedHostKey, rootId],
  );
  if (hostCred.rows.length === 0) throw new EnrollAbort();
  const hostCredentialId = String(hostCred.rows[0].id);

  const hostRow = await client.query(
    `INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2) RETURNING id`,
    [personId, hostCredentialId],
  );
  if (hostRow.rows.length === 0) return refuse();
  const hostId = String(hostRow.rows[0].id);

  // 8. Only after consume + host credential + host row, append host.enrolled
  //    with target host/<hostId>, locked actor fields, empty metadata, and
  //    server-generated requestId correlation. Commit. An injected audit
  //    failure throws, rolls the consume back, and reaches the redacted
  //    transport-503 catch-all — never the collapsed 404.
  await writeAuditEvent(client, {
    eventType: AUDIT_EVENT.hostEnrolled,
    communityId: input.community,
    actorPersonId: personId,
    actorCredentialId: input.device,
    actorMemberId: memberId,
    targetType: "host",
    targetId: `host/${hostId}`,
    metadata: {},
    correlationId: requestId,
  });
  return { ok: true };
}
