import { randomUUID } from "node:crypto";
import type { DbClient } from "../db/db-client.ts";
import { inTransaction } from "../db/transaction.ts";
import { AUDIT_EVENT, writeAuditEvent } from "../db/audit.ts";

export type SpaceKind = "project" | "section" | "channel" | "thread";
export type Visibility = "public" | "private";

export interface SpaceInput {
  communityId: string;
  /** The authenticated actor performing the space mutation (audit actor). */
  createdByMemberId: string;
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
 * rules. Every successful mutation records a typed `space.create` audit with the
 * acting creator; when `withRootGrantFor` is supplied (project creation) the
 * space insert, the creator's explicit project-root access grant, and all audit
 * records are applied in one transaction, so a failing grant can never leave a
 * project behind.
 */
export async function createSpace(
  client: DbClient,
  input: SpaceInput,
  withRootGrantFor: { memberId: string; grantedByMemberId: string } | undefined,
  correlationId: string,
): Promise<SpaceRecord> {
  return inTransaction(client, async (tx) => {
    const result = await tx.query<{ id: string; kind: string; visibility: string }>(
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
      await grantSpaceMembership(tx, {
        spaceId: id,
        memberId: withRootGrantFor.memberId,
        grantedByMemberId: withRootGrantFor.grantedByMemberId,
        source: "explicit",
        correlationId,
      });
    }
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.spaceCreated,
      communityId: input.communityId,
      actorMemberId: input.createdByMemberId,
      targetType: "space",
      targetId: id,
      metadata: { kind: input.kind, visibility: input.visibility },
      correlationId,
    });
    return { id, kind: result.rows[0].kind as SpaceKind, visibility: result.rows[0].visibility as Visibility };
  });
}

export interface GrantSpaceMembershipInput {
  spaceId: string;
  memberId: string;
  grantedByMemberId: string;
  source: "explicit" | "invite";
  correlationId?: string;
}

/** Grant active access to a space (never a role/authority), with typed audit. */
export async function grantSpaceMembership(
  client: DbClient,
  input: GrantSpaceMembershipInput,
): Promise<string> {
  return inTransaction(client, async (tx) => {
    const result = await tx.query<{ id: string }>(
      `INSERT INTO space_membership (space_id, member_id, grant_source, granted_by_member_id)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [input.spaceId, input.memberId, input.source, input.grantedByMemberId],
    );
    const membershipId = result.rows[0].id;
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.spaceAccessGrant,
      communityId: await spaceCommunityId(tx, input.spaceId),
      actorMemberId: input.grantedByMemberId,
      targetType: "space_membership",
      targetId: membershipId,
      metadata: { spaceId: input.spaceId, memberId: input.memberId, source: input.source },
      correlationId: input.correlationId ?? randomUUID(),
    });
    return membershipId;
  });
}

/** Revoke an active grant (retaining the row for audit), with typed audit. */
export async function revokeSpaceMembership(
  client: DbClient,
  spaceId: string,
  memberId: string,
  reason: string,
  revokedByMemberId: string,
  correlationId?: string,
): Promise<void> {
  await inTransaction(client, async (tx) => {
    const result = await tx.query(
      `UPDATE space_membership
       SET revoked_at = now(), revoked_reason = $3
       WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL
       RETURNING id`,
      [spaceId, memberId, reason],
    );
    if (result.rows.length === 0) return;
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.spaceAccessRevoke,
      communityId: await spaceCommunityId(tx, spaceId),
      actorMemberId: revokedByMemberId,
      targetType: "space_membership",
      targetId: String(result.rows[0].id),
      metadata: { spaceId, memberId, reason },
      correlationId: correlationId ?? randomUUID(),
    });
  });
}

async function spaceCommunityId(client: DbClient, spaceId: string): Promise<string> {
  const result = await client.query<{ community_id: string }>(
    "SELECT community_id FROM space WHERE id = $1",
    [spaceId],
  );
  if (result.rows.length === 0) throw new Error("space not found");
  return result.rows[0].community_id;
}
