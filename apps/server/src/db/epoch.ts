import type { DbClient } from "./db-client.ts";

/**
 * M2.1 — uncached epoch-read seam for the delivery authorization snapshot.
 *
 * Reads the current committed `epoch` of an authorization-bearing row. This is
 * the read side the M2.2 delivery guard compares against a captured snapshot:
 * a mismatch means the access set changed (a revoked credential/member, a
 * space access-mode change, or a freshly granted/revoked space) and the guard
 * must re-evaluate.
 *
 * The epoch is an unbounded PostgreSQL `bigint`. The seam preserves the value
 * EXACTLY as a JavaScript `bigint`: it casts the column to `text` on the wire
 * and parses with `BigInt`, never routing it through `Number`. This guarantees
 * two distinct epoch values above `Number.MAX_SAFE_INTEGER` cannot collapse to
 * the same JS number and hide a real authorization change from the M2.2 guard.
 *
 * Every read here is a live, current-committed read — no cache, no memoization
 * — so a revocation is observed by the *next* delivery. Each function returns
 * `null` when the row is absent, never throwing on a missing row. Reads perform
 * no write of any kind.
 *
 * M2.1 ships no send gate, guard, sweep, or transport; that is M2.2/M2.3.
 */

export interface CredentialEpoch {
  epoch: bigint;
}

export interface MemberEpoch {
  epoch: bigint;
}

export interface SpaceEpoch {
  epoch: bigint;
}

export interface SpaceMembershipEpoch {
  epoch: bigint;
  revokedAt: string | null;
}

function toBigint(value: string): bigint {
  return BigInt(value);
}

/** Read the current credential epoch. `null` if no such credential. */
export async function readCredentialEpoch(
  client: DbClient,
  credentialId: string,
): Promise<CredentialEpoch | null> {
  const result = await client.query<{ epoch: string }>(
    "SELECT epoch::text AS epoch FROM credential WHERE id = $1",
    [credentialId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: toBigint(result.rows[0].epoch) };
}

/** Read the current member epoch. `null` if no such member. */
export async function readMemberEpoch(
  client: DbClient,
  memberId: string,
): Promise<MemberEpoch | null> {
  const result = await client.query<{ epoch: string }>(
    "SELECT epoch::text AS epoch FROM member WHERE id = $1",
    [memberId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: toBigint(result.rows[0].epoch) };
}

/** Read the current space epoch. `null` if no such space. */
export async function readSpaceEpoch(
  client: DbClient,
  spaceId: string,
): Promise<SpaceEpoch | null> {
  const result = await client.query<{ epoch: string }>(
    "SELECT epoch::text AS epoch FROM space WHERE id = $1",
    [spaceId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: toBigint(result.rows[0].epoch) };
}

/** Read the current active space-membership epoch for a (space, member) pair.
 * `null` if there is no active grant row. The member row always exists in the
 * snapshot; this scope detail is a co-located per-(member,space) version. */
export async function readSpaceMembershipEpoch(
  client: DbClient,
  spaceId: string,
  memberId: string,
): Promise<SpaceMembershipEpoch | null> {
  const result = await client.query<{ epoch: string; revoked_at: string | null }>(
    `SELECT epoch::text AS epoch, revoked_at FROM space_membership
     WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL`,
    [spaceId, memberId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: toBigint(result.rows[0].epoch), revokedAt: result.rows[0].revoked_at };
}

export type EpochBatchRequest =
  | { kind: "credential"; id: string }
  | { kind: "member"; id: string }
  | { kind: "space"; id: string }
  | { kind: "spaceMembership"; spaceId: string; memberId: string };

export type EpochBatchResult = {
  request: EpochBatchRequest;
  epoch: bigint | null;
  revokedAt?: string | null;
};

/** Typed, uncached, one-round-trip batched epoch reader. Preserves input order
 * and null-for-absent; duplicates produce distinct ordered outputs. No writes.
 * Executes exactly one SQL statement regardless of batch size. */
export async function readEpochBatch(
  client: DbClient,
  requests: EpochBatchRequest[],
): Promise<EpochBatchResult[]> {
  if (requests.length === 0) return [];
  // Build one fixed parameterized statement: each request is one UNION ALL leg
  // with its ordinal for ORDER BY, joining to the typed source via lateral.
  const legs: string[] = [];
  const params: unknown[] = [];
  let p = 1;
  for (let i = 0; i < requests.length; i++) {
    const req = requests[i];
    if (req.kind === "credential") {
      legs.push(`SELECT ${i}::int AS ord, c.epoch::text AS epoch, NULL::timestamptz AS revoked_at FROM (SELECT $${p}::uuid AS id) q LEFT JOIN credential c ON c.id = q.id`);
      params.push(req.id); p++;
    } else if (req.kind === "member") {
      legs.push(`SELECT ${i}::int AS ord, m.epoch::text AS epoch, NULL::timestamptz AS revoked_at FROM (SELECT $${p}::uuid AS id) q LEFT JOIN member m ON m.id = q.id`);
      params.push(req.id); p++;
    } else if (req.kind === "space") {
      legs.push(`SELECT ${i}::int AS ord, s.epoch::text AS epoch, NULL::timestamptz AS revoked_at FROM (SELECT $${p}::uuid AS id) q LEFT JOIN space s ON s.id = q.id`);
      params.push(req.id); p++;
    } else {
      legs.push(`SELECT ${i}::int AS ord, sm.epoch::text AS epoch, sm.revoked_at FROM (SELECT $${p}::uuid AS sid, $${p+1}::uuid AS mid) q LEFT JOIN space_membership sm ON sm.space_id = q.sid AND sm.member_id = q.mid AND sm.revoked_at IS NULL`);
      params.push(req.spaceId, req.memberId); p+=2;
    }
  }
  const sql = legs.join(" UNION ALL ") + " ORDER BY ord";
  const result = await client.query<{ ord: number; epoch: string | null; revoked_at: string | null }>(sql, params);
  // result rows are in ord order
  return result.rows.map((row, idx) => {
    const req = requests[row.ord];
    // idx should equal ord; use ord for mapping to survive any ordering guarantee
    if (req.kind === "spaceMembership") {
      return { request: req, epoch: row.epoch !== null ? toBigint(row.epoch) : null, revokedAt: row.revoked_at ?? null };
    }
    return { request: req, epoch: row.epoch !== null ? toBigint(row.epoch) : null };
  });
}
