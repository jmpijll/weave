import { randomUUID } from "node:crypto";
import type { DbClient } from "../db/db-client.ts";
import { inTransaction } from "../db/transaction.ts";
import { AUDIT_EVENT, writeAuditEvent } from "../db/audit.ts";
import { createMember } from "./membership.ts";
import { grantSpaceMembership } from "./spaces.ts";

export type InviteState = "issued" | "accepted" | "revoked" | "expired";

export interface AdmissionInviteInput {
  communityId: string;
  /** Human invites target a human root credential; agent invites an existing agent. */
  target:
    | { kind: "human"; targetCredentialId: string }
    | { kind: "agent"; targetAgentId: string };
  issuerMemberId: string;
  expiresAt: string;
  correlationId: string;
}

export interface SpaceInviteInput {
  communityId: string;
  targetMemberId: string;
  spaceId: string;
  issuerMemberId: string;
  expiresAt: string;
  correlationId: string;
}

/**
 * Issue a community-admission invite. The insert and the typed issued-audit
 * event run in one transaction; the issuer is the recorded actor.
 */
export async function issueCommunityAdmissionInvite(
  client: DbClient,
  input: AdmissionInviteInput,
): Promise<string> {
  return inTransaction(client, async (tx) => {
    const result = await tx.query<{ id: string }>(
      `INSERT INTO community_admission_invite
         (community_id, target_kind, target_credential_id, target_agent_id, issuer_member_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [
        input.communityId,
        input.target.kind,
        input.target.kind === "human" ? input.target.targetCredentialId : null,
        input.target.kind === "agent" ? input.target.targetAgentId : null,
        input.issuerMemberId,
        input.expiresAt,
      ],
    );
    const id = result.rows[0].id;
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.admissionInviteIssued,
      communityId: input.communityId,
      actorMemberId: input.issuerMemberId,
      targetType: "community_admission_invite",
      targetId: id,
      metadata: { targetKind: input.target.kind },
      correlationId: input.correlationId,
    });
    return id;
  });
}

/**
 * Issue a space invite. The insert and the typed issued-audit event run in one
 * transaction; the issuer is the recorded actor.
 */
export async function issueSpaceInvite(
  client: DbClient,
  input: SpaceInviteInput,
): Promise<string> {
  return inTransaction(client, async (tx) => {
    const result = await tx.query<{ id: string }>(
      `INSERT INTO space_invite
         (community_id, target_member_id, space_id, issuer_member_id, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [input.communityId, input.targetMemberId, input.spaceId, input.issuerMemberId, input.expiresAt],
    );
    const id = result.rows[0].id;
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.spaceInviteIssued,
      communityId: input.communityId,
      actorMemberId: input.issuerMemberId,
      targetType: "space_invite",
      targetId: id,
      metadata: { spaceId: input.spaceId, targetMemberId: input.targetMemberId },
      correlationId: input.correlationId,
    });
    return id;
  });
}

/**
 * Transition an invite (admission or space) to a terminal state. Returns the
 * number of rows actually transitioned (0 when the invite is no longer
 * `issued`, e.g. already consumed or terminal). Private: every externally
 * reachable transition must go through an audited command (accept/revoke),
 * never through this raw helper.
 */
async function transitionInvite(
  client: DbClient,
  table: "community_admission_invite" | "space_invite",
  inviteId: string,
  to: Exclude<InviteState, "issued">,
): Promise<number> {
  const allowedTo = ["accepted", "revoked", "expired"];
  if (!allowedTo.includes(to)) throw new Error(`invalid invite target state: ${to}`);
  const column = to === "accepted" ? "accepted_at" : "revoked_at";
  const result = await client.query(
    `UPDATE ${table} SET state = $2, ${column} = now() WHERE id = $1 AND state = 'issued'`,
    [inviteId, to],
  );
  return result.rowCount ?? 0;
}

/**
 * Revoke a community-admission invite. Returns false when the invite was
 * already terminal (no transition, no audit); otherwise the revocation and its
 * typed audit commit together.
 */
export async function revokeCommunityAdmissionInvite(
  client: DbClient,
  inviteId: string,
  actorMemberId: string,
  reason: string,
  correlationId: string,
): Promise<boolean> {
  return inTransaction(client, async (tx) => {
    const info = await tx.query<{ community_id: string }>(
      "SELECT community_id FROM community_admission_invite WHERE id = $1",
      [inviteId],
    );
    if (info.rows.length === 0) return false;
    const transitioned = await transitionInvite(tx, "community_admission_invite", inviteId, "revoked");
    if (transitioned !== 1) return false;
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.admissionInviteRevoked,
      communityId: info.rows[0].community_id,
      actorMemberId,
      targetType: "community_admission_invite",
      targetId: inviteId,
      metadata: { reason },
      correlationId,
    });
    return true;
  });
}

/**
 * Revoke a space invite. Returns false when the invite was already terminal (no
 * transition, no audit); otherwise the revocation and its typed audit commit
 * together.
 */
export async function revokeSpaceInvite(
  client: DbClient,
  inviteId: string,
  actorMemberId: string,
  reason: string,
  correlationId: string,
): Promise<boolean> {
  return inTransaction(client, async (tx) => {
    const info = await tx.query<{ community_id: string }>(
      "SELECT community_id FROM space_invite WHERE id = $1",
      [inviteId],
    );
    if (info.rows.length === 0) return false;
    const transitioned = await transitionInvite(tx, "space_invite", inviteId, "revoked");
    if (transitioned !== 1) return false;
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.spaceInviteRevoked,
      communityId: info.rows[0].community_id,
      actorMemberId,
      targetType: "space_invite",
      targetId: inviteId,
      metadata: { reason },
      correlationId,
    });
    return true;
  });
}

/**
 * Accept a community admission invite, creating the identified member in the
 * same transaction. The consume is conditional and row-locked: only an invite
 * still `issued` and unexpired is accepted, and the terminal transition is
 * asserted to affect exactly one row, so a revoked or expired invite can never
 * admit a fresh member.
 */
export async function acceptCommunityAdmissionInvite(
  client: DbClient,
  inviteId: string,
  correlationId?: string,
): Promise<{ memberId: string } | null> {
  return inTransaction(client, async (tx) => {
    const invite = await tx.query<{
      community_id: string;
      issuer_member_id: string;
      target_kind: "human" | "agent";
      target_credential_id: string | null;
      target_agent_id: string | null;
    }>(
      `SELECT community_id, issuer_member_id, target_kind, target_credential_id, target_agent_id
       FROM community_admission_invite
       WHERE id = $1 AND state = 'issued' AND expires_at > now()
       FOR UPDATE`,
      [inviteId],
    );
    if (invite.rows.length === 0) return null;
    const row = invite.rows[0];
    const member =
      row.target_kind === "human"
        ? await createMember(tx, {
            communityId: row.community_id,
            subject: { kind: "human", personId: await credentialPersonId(tx, row.target_credential_id!) },
          })
        : await createMember(tx, {
            communityId: row.community_id,
            subject: { kind: "agent", agentId: row.target_agent_id! },
          });
    const transitioned = await transitionInvite(tx, "community_admission_invite", inviteId, "accepted");
    if (transitioned !== 1) {
      throw new Error("admission invite was consumed concurrently");
    }
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.memberAdmitted,
      communityId: row.community_id,
      actorMemberId: row.issuer_member_id,
      targetType: "member",
      targetId: member.id,
      metadata: { inviteId, targetKind: row.target_kind },
      correlationId: correlationId ?? randomUUID(),
    });
    return { memberId: member.id };
  });
}

/**
 * Accept a space invite: grants project/private-descendant access only, never
 * admission. The consume is conditional and row-locked, the acceptance is
 * attributed to the actual issuer, and the grant+audit+transition run in one
 * transaction.
 */
export async function acceptSpaceInvite(
  client: DbClient,
  inviteId: string,
  correlationId?: string,
): Promise<{ spaceId: string } | null> {
  return inTransaction(client, async (tx) => {
    const invite = await tx.query<{
      community_id: string;
      issuer_member_id: string;
      target_member_id: string;
      space_id: string;
    }>(
      `SELECT community_id, issuer_member_id, target_member_id, space_id
       FROM space_invite
       WHERE id = $1 AND state = 'issued' AND expires_at > now()
       FOR UPDATE`,
      [inviteId],
    );
    if (invite.rows.length === 0) return null;
    const row = invite.rows[0];
    await grantSpaceMembership(tx, {
      spaceId: row.space_id,
      memberId: row.target_member_id,
      grantedByMemberId: row.issuer_member_id,
      source: "invite",
      correlationId: correlationId ?? randomUUID(),
    });
    const transitioned = await transitionInvite(tx, "space_invite", inviteId, "accepted");
    if (transitioned !== 1) {
      throw new Error("space invite was consumed concurrently");
    }
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.spaceInviteAccepted,
      communityId: row.community_id,
      actorMemberId: row.issuer_member_id,
      targetType: "space_invite",
      targetId: inviteId,
      metadata: { spaceId: row.space_id, targetMemberId: row.target_member_id },
      correlationId: correlationId ?? randomUUID(),
    });
    return { spaceId: row.space_id };
  });
}

async function credentialPersonId(client: DbClient, credentialId: string): Promise<string> {
  const result = await client.query<{ person_id: string }>(
    "SELECT person_id FROM credential WHERE id = $1",
    [credentialId],
  );
  if (result.rows.length === 0) throw new Error("admission invite target credential not found");
  return result.rows[0].person_id;
}