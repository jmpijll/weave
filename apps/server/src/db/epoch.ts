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
 * Every read here is a live, current-committed read — no cache, no memoization
 * — so a revocation is observed by the *next* delivery. Each function returns
 * `null` when the row is absent, never throwing on a missing row. Reads perform
 * no write of any kind.
 *
 * M2.1 ships no send gate, guard, sweep, or transport; that is M2.2/M2.3.
 */

export interface CredentialEpoch {
  epoch: number;
}

export interface MemberEpoch {
  epoch: number;
}

export interface SpaceEpoch {
  epoch: number;
}

export interface SpaceMembershipEpoch {
  epoch: number;
  revokedAt: string | null;
}

/** Read the current credential epoch. `null` if no such credential. */
export async function readCredentialEpoch(
  client: DbClient,
  credentialId: string,
): Promise<CredentialEpoch | null> {
  const result = await client.query<{ epoch: number }>(
    "SELECT epoch FROM credential WHERE id = $1",
    [credentialId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: Number(result.rows[0].epoch) };
}

/** Read the current member epoch. `null` if no such member. */
export async function readMemberEpoch(
  client: DbClient,
  memberId: string,
): Promise<MemberEpoch | null> {
  const result = await client.query<{ epoch: number }>(
    "SELECT epoch FROM member WHERE id = $1",
    [memberId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: Number(result.rows[0].epoch) };
}

/** Read the current space epoch. `null` if no such space. */
export async function readSpaceEpoch(
  client: DbClient,
  spaceId: string,
): Promise<SpaceEpoch | null> {
  const result = await client.query<{ epoch: number }>(
    "SELECT epoch FROM space WHERE id = $1",
    [spaceId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: Number(result.rows[0].epoch) };
}

/** Read the current active space-membership epoch for a (space, member) pair.
 * `null` if there is no active grant row. The member row always exists in the
 * snapshot; this scope detail is a co-located per-(member,space) version. */
export async function readSpaceMembershipEpoch(
  client: DbClient,
  spaceId: string,
  memberId: string,
): Promise<SpaceMembershipEpoch | null> {
  const result = await client.query<{ epoch: number; revoked_at: string | null }>(
    `SELECT epoch, revoked_at FROM space_membership
     WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL`,
    [spaceId, memberId],
  );
  if (result.rows.length === 0) return null;
  return { epoch: Number(result.rows[0].epoch), revokedAt: result.rows[0].revoked_at };
}
