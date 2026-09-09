import type { PoolClient } from "pg";

/**
 * The typed M1 audit vocabulary. Every state-changing command writes exactly one
 * of these event types in the same transaction as the mutation it evidences.
 */
export const AUDIT_EVENT = {
  memberAdmitted: "member.admission",
  spaceCreated: "space.create",
  spaceAccessGrant: "space.access.grant",
  spaceAccessRevoke: "space.access.revoke",
  roleAssigned: "role.assigned",
  roleRevoked: "role.revoked",
  admissionInviteIssued: "community.admission.invite.issued",
  admissionInviteRevoked: "community.admission.invite.revoked",
  admissionInviteExpired: "community.admission.invite.expired",
  spaceInviteIssued: "space.invite.issued",
  spaceInviteAccepted: "space.invite.accepted",
  spaceInviteRevoked: "space.invite.revoked",
  spaceInviteExpired: "space.invite.expired",
} as const;

export type AuditEventType = (typeof AUDIT_EVENT)[keyof typeof AUDIT_EVENT];

export interface AuditEventInput {
  eventType: string;
  communityId?: string | null;
  actorPersonId?: string | null;
  actorCredentialId?: string | null;
  actorMemberId?: string | null;
  targetType: string;
  targetId: string;
  metadata?: Record<string, unknown>;
  correlationId: string;
}

/**
 * Append-only audit write. Must be called inside the same transaction as any
 * mutation it evidences. Returns the generated event id. Callers must never
 * place keys, signatures, secret material, or raw SQL values in `metadata`.
 */
export async function writeAuditEvent(
  client: PoolClient,
  input: AuditEventInput,
): Promise<string> {
  const result = await client.query<{ id: string }>(
    `INSERT INTO audit_event (
       event_type, community_id, actor_person_id, actor_credential_id, actor_member_id,
       target_type, target_id, metadata, correlation_id
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id`,
    [
      input.eventType,
      input.communityId ?? null,
      input.actorPersonId ?? null,
      input.actorCredentialId ?? null,
      input.actorMemberId ?? null,
      input.targetType,
      input.targetId,
      JSON.stringify(input.metadata ?? {}),
      input.correlationId,
    ],
  );
  return String(result.rows[0].id);
}
