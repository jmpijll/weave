import type { DbClient } from "../db/db-client.ts";

export type SpaceKind = "project" | "section" | "channel" | "thread";
export type Visibility = "public" | "private";

export interface SpaceInput {
  communityId: string;
  kind: SpaceKind;
  parentSpaceId?: string | null;
  ownerMemberId?: string | null;
  visibility: Visibility;
  description?: string | null;
}

export interface SpaceRecord {
  id: string;
  kind: SpaceKind;
  visibility: Visibility;
}

/**
 * Create a space node. The DB triggers enforce project-root-only and the
 * project > section > channel > thread parent kind/depth and same-community
 * rules. Optionally records the creator's explicit project-root access grant
 * when `withRootGrantFor` is supplied (project creation), atomically.
 */
export async function createSpace(
  client: DbClient,
  input: SpaceInput,
  withRootGrantFor?: { memberId: string; grantedByMemberId: string },
): Promise<SpaceRecord> {
  const result = await client.query<{ id: string; kind: string; visibility: string }>(
    `INSERT INTO space (community_id, kind, parent_space_id, owner_member_id, visibility, description)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, kind, visibility`,
    [
      input.communityId,
      input.kind,
      input.parentSpaceId ?? null,
      input.ownerMemberId ?? null,
      input.visibility,
      input.description ?? null,
    ],
  );
  const id = result.rows[0].id;
  if (withRootGrantFor) {
    await grantSpaceMembership(client, {
      spaceId: id,
      memberId: withRootGrantFor.memberId,
      grantedByMemberId: withRootGrantFor.grantedByMemberId,
      source: "explicit",
    });
  }
  return { id, kind: result.rows[0].kind as SpaceKind, visibility: result.rows[0].visibility as Visibility };
}

export interface GrantSpaceMembershipInput {
  spaceId: string;
  memberId: string;
  grantedByMemberId: string;
  source: "explicit" | "invite";
}

/** Grant active access to a space (never a role/authority). */
export async function grantSpaceMembership(
  client: DbClient,
  input: GrantSpaceMembershipInput,
): Promise<string> {
  const result = await client.query<{ id: string }>(
    `INSERT INTO space_membership (space_id, member_id, grant_source, granted_by_member_id)
     VALUES ($1, $2, $3, $4)
     RETURNING id`,
    [input.spaceId, input.memberId, input.source, input.grantedByMemberId],
  );
  return result.rows[0].id;
}

/** Revoke an active grant, retaining the row for audit. */
export async function revokeSpaceMembership(
  client: DbClient,
  spaceId: string,
  memberId: string,
  reason: string,
): Promise<void> {
  await client.query(
    `UPDATE space_membership
     SET revoked_at = now(), revoked_reason = $3
     WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL`,
    [spaceId, memberId, reason],
  );
}
