/**
 * Weave M3.2 I4.1 — locked server issue command for `POST /v1/pairing-tokens`.
 *
 * One `withTransaction` callback on a single `PoolClient`: either a new
 * pending `pairing_token` row plus exactly one `pairing.token.issued` audit
 * commits, or an exact authorized same-ID retry is accepted with no audit, or
 * the transaction rolls back with no row/audit at all.
 *
 * Lock order (deadlock-safe with I4.2 enroll): existing token row
 * `FOR KEY SHARE` first (when present), then policy `FOR SHARE`, then device
 * and root in ascending UUID order `FOR UPDATE`, then the active human member
 * for the claimed community last `FOR UPDATE`.
 */
import type { Pool, PoolClient } from "pg";
import { buildIssuanceRecord } from "@weave/protocol";
import { verifyIssuance } from "@weave/protocol/m32-verify";
import { writeAuditEvent, AUDIT_EVENT } from "../db/audit.ts";
import { withTransaction } from "../db/transaction.ts";

export const ISSUE_FRESHNESS_MS = 120_000n;
export const ISSUE_FUTURE_SKEW_MS = 30_000n;
export const ISSUE_MAX_MS = 9_007_199_254_740_991n;
export const ISSUE_POLICY_VERSION = 1;

export interface IssueInput {
  stableId: string;
  hostPublic: string;
  community: string;
  device: string;
  issuedAt: string;
  proof: string;
}

export type IssueResult =
  | { ok: true; retry: boolean }
  | { ok: false };

function parseMsText(value: string): bigint | null {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) return null;
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    return null;
  }
  if (parsed < 0n || parsed > ISSUE_MAX_MS) return null;
  return parsed;
}

export function parsePairingMs(value: unknown): bigint | null {
  if (typeof value === "string") return parseMsText(value);
  if (typeof value === "bigint") {
    return value >= 0n && value <= ISSUE_MAX_MS ? value : null;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > Number(ISSUE_MAX_MS)) return null;
    return BigInt(value);
  }
  return null;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function issuePairingToken(
  pool: Pool,
  input: IssueInput,
  requestId: string,
): Promise<IssueResult> {
  if (
    !UUID_RE.test(input.stableId) ||
    !UUID_RE.test(input.community) ||
    !UUID_RE.test(input.device) ||
    !/^[0-9a-f]{64}$/.test(input.hostPublic) ||
    !/^[0-9a-f]{128}$/.test(input.proof)
  ) {
    return { ok: false };
  }
  const issuedAt = parseMsText(input.issuedAt);
  if (issuedAt === null) return { ok: false };

  return withTransaction(pool, (client) => issueInTransaction(client, input, issuedAt, requestId));
}

async function issueInTransaction(
  client: PoolClient,
  input: IssueInput,
  issuedAt: bigint,
  requestId: string,
): Promise<IssueResult> {
  const refuse = (): IssueResult => ({ ok: false });

  // 1. Optionally acquire an existing token row FOR KEY SHARE solely to
  //    establish a token-first lock. No branching, verification, or
  //    classification against it yet.
  await client.query(`SELECT id FROM pairing_token WHERE id = $1 FOR KEY SHARE`, [input.stableId]);

  // 2. Lock policy version 1 FOR SHARE; read duration_ms as text, parse BigInt.
  const policy = await client.query(
    `SELECT duration_ms::text AS duration_ms FROM pairing_policy_registry WHERE version = $1 FOR SHARE`,
    [ISSUE_POLICY_VERSION],
  );
  if (policy.rows.length === 0) return refuse();
  const durationMs = parseMsText(String(policy.rows[0].duration_ms));
  if (durationMs === null || durationMs <= 0n) return refuse();

  // 3. Discover the presented device's direct parent, then lock device and
  //    root in ascending UUID order FOR UPDATE; lock the active human member
  //    for the claimed community last FOR UPDATE; re-read and validate the
  //    exact direct device/root/person/member relation under lock.
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
  const lockedCreds = await client.query(
    `SELECT id, person_id, public_key, kind, algorithm, parent_credential_id, revoked_at
     FROM credential WHERE id = $1 OR id = $2 FOR UPDATE`,
    [firstId, secondId],
  );
  if (lockedCreds.rows.length !== 2) return refuse();
  const byId = new Map<string, Record<string, unknown>>();
  for (const row of lockedCreds.rows as Record<string, unknown>[]) {
    byId.set(String(row.id), row);
  }
  const lockedDevice = byId.get(String(input.device));
  const lockedRoot = byId.get(rootId);
  if (!lockedDevice || !lockedRoot) return refuse();
  // Exact direct relation: device's parent is the root; root is a top-level
  // human key; same person.
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
  const deviceKey = lockedDevice.public_key;

  const member = await client.query(
    `SELECT id, person_id FROM member
     WHERE community_id = $1 AND subject_kind = 'human' AND person_id = $2 AND revoked_at IS NULL
     FOR UPDATE`,
    [input.community, personId],
  );
  if (member.rows.length === 0) return refuse();
  const memberRow = member.rows[0] as Record<string, unknown>;
  const memberId = String(memberRow.id);

  // 4. Rebuild and verify the issuance record against the locked device's
  //    stored public key. The carrier never chooses the verification key.
  let record: Uint8Array;
  try {
    record = buildIssuanceRecord({
      stableId: input.stableId,
      hostPublic: input.hostPublic,
      community: input.community,
      device: input.device,
      issuedAt: input.issuedAt,
    });
  } catch {
    return refuse();
  }
  let verified = false;
  try {
    verified = verifyIssuance(
      record as Parameters<typeof verifyIssuance>[0],
      input.proof as Parameters<typeof verifyIssuance>[1],
      deviceKey as Parameters<typeof verifyIssuance>[2],
    );
  } catch {
    return refuse();
  }
  if (!verified) return refuse();

  // 5. Sample one post-lock DB wall clock as text decimal ms, validate its
  //    range, and enforce both issue freshness edges with BigInt. Derive and
  //    range-check expiresAt = issuedAt + durationMs before writing.
  const clock = await client.query(
    `SELECT (floor(extract(epoch from clock_timestamp()) * 1000))::text AS now_ms`,
  );
  const nowMs = parseMsText(String(clock.rows[0].now_ms));
  if (nowMs === null) return refuse();
  if (issuedAt > nowMs + ISSUE_FUTURE_SKEW_MS) return refuse();
  if (nowMs > issuedAt + ISSUE_FRESHNESS_MS) return refuse();
  const expiresAt = issuedAt + durationMs;
  if (expiresAt <= issuedAt || expiresAt > ISSUE_MAX_MS) return refuse();

  // 6. Re-read the stable token row under FOR KEY SHARE. If it exists,
  //    compare every immutable persisted fact before returning accepted.
  //    This branch writes no audit.
  const existing = await client.query(
    `SELECT id, issued_by_credential_id, host_public_key, community_id,
            issued_at::text AS issued_at, expires_at::text AS expires_at,
            policy_version, consumed_at
     FROM pairing_token WHERE id = $1 FOR KEY SHARE`,
    [input.stableId],
  );
  if (existing.rows.length > 0) {
    const row = existing.rows[0] as Record<string, unknown>;
    if (
      String(row.id) === input.stableId &&
      String(row.issued_by_credential_id) === input.device &&
      String(row.host_public_key) === input.hostPublic &&
      String(row.community_id) === input.community &&
      String(row.issued_at) === input.issuedAt &&
      String(row.expires_at) === expiresAt.toString() &&
      Number(row.policy_version) === ISSUE_POLICY_VERSION
    ) {
      return { ok: true, retry: true };
    }
    return refuse();
  }

  // 7. Insert the exact durable row as pending. A concurrent PK outcome may
  //    use ON CONFLICT DO NOTHING only as an arbitration primitive: RETURNING
  //    tells whether this transaction authored the row. When another
  //    transaction won, re-read under the token lock, compare every immutable
  //    fact, and accept only an exact authorized retry (no audit here).
  const inserted = await client.query(
    `INSERT INTO pairing_token (id, issued_by_credential_id, host_public_key, community_id, issued_at, expires_at, policy_version)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (id) DO NOTHING
     RETURNING id`,
    [
      input.stableId,
      input.device,
      input.hostPublic,
      input.community,
      issuedAt.toString(),
      expiresAt.toString(),
      ISSUE_POLICY_VERSION,
    ],
  );
  if (inserted.rows.length === 0) {
    const rival = await client.query(
      `SELECT id, issued_by_credential_id, host_public_key, community_id,
              issued_at::text AS issued_at, expires_at::text AS expires_at,
              policy_version
       FROM pairing_token WHERE id = $1 FOR KEY SHARE`,
      [input.stableId],
    );
    if (rival.rows.length === 0) return refuse();
    const rivalRow = rival.rows[0] as Record<string, unknown>;
    if (
      String(rivalRow.id) === input.stableId &&
      String(rivalRow.issued_by_credential_id) === input.device &&
      String(rivalRow.host_public_key) === input.hostPublic &&
      String(rivalRow.community_id) === input.community &&
      String(rivalRow.issued_at) === input.issuedAt &&
      String(rivalRow.expires_at) === expiresAt.toString() &&
      Number(rivalRow.policy_version) === ISSUE_POLICY_VERSION
    ) {
      return { ok: true, retry: true };
    }
    return refuse();
  }
  const after = await client.query(
    `SELECT id FROM pairing_token WHERE id = $1 FOR KEY SHARE`,
    [input.stableId],
  );
  if (after.rows.length === 0) return refuse();

  // 8. Only after a newly inserted row, append pairing.token.issued with
  //    target pairing_token/<stableId>, locked actor fields, community,
  //    empty metadata, and server-generated requestId correlation. Commit.
  await writeAuditEvent(client, {
    eventType: AUDIT_EVENT.pairingTokenIssued,
    communityId: input.community,
    actorPersonId: personId,
    actorCredentialId: input.device,
    actorMemberId: memberId,
    targetType: "pairing_token",
    targetId: `pairing_token/${input.stableId}`,
    metadata: {},
    correlationId: requestId,
  });
  return { ok: true, retry: false };
}
