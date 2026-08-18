import type { PoolClient } from "pg";

export interface AuditEventInput {
  eventType: string;
  communityId?: string | null;
  actorPersonId?: string | null;
  actorCredentialId?: string | null;
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
       event_type, community_id, actor_person_id, actor_credential_id,
       target_type, target_id, metadata, correlation_id
     )
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id`,
    [
      input.eventType,
      input.communityId ?? null,
      input.actorPersonId ?? null,
      input.actorCredentialId ?? null,
      input.targetType,
      input.targetId,
      JSON.stringify(input.metadata ?? {}),
      input.correlationId,
    ],
  );
  return String(result.rows[0].id);
}
