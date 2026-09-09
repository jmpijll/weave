import type { DbClient } from "../db/db-client.ts";

export type MemberSubject =
  | { kind: "human"; personId: string }
  | { kind: "agent"; agentId: string };

export interface MemberInput {
  communityId: string;
  subject: MemberSubject;
}

export interface MemberRecord {
  id: string;
  communityId: string;
  subjectKind: "human" | "agent";
  personId: string | null;
  agentId: string | null;
  revokedAt: string | null;
}

/**
 * Create an active member. The partial unique indexes reject a second active
 * membership for the same (community, person) or (community, agent).
 * Used by community-admission acceptance; it never touches project access.
 */
export async function createMember(
  client: DbClient,
  input: MemberInput,
): Promise<MemberRecord> {
  const result = await client.query<{
    id: string;
    community_id: string;
    subject_kind: "human" | "agent";
    person_id: string | null;
    agent_id: string | null;
    revoked_at: string | null;
  }>(
    `INSERT INTO member (community_id, subject_kind, person_id, agent_id)
     VALUES ($1, $2, $3, $4)
     RETURNING id, community_id, subject_kind, person_id, agent_id, revoked_at`,
    [
      input.communityId,
      input.subject.kind,
      input.subject.kind === "human" ? input.subject.personId : null,
      input.subject.kind === "agent" ? input.subject.agentId : null,
    ],
  );
  const r = result.rows[0];
  return {
    id: r.id,
    communityId: r.community_id,
    subjectKind: r.subject_kind,
    personId: r.person_id,
    agentId: r.agent_id,
    revokedAt: r.revoked_at,
  };
}

/** Look up an active member record by id. */
export async function getActiveMember(
  client: DbClient,
  memberId: string,
): Promise<MemberRecord | null> {
  const result = await client.query<{
    id: string;
    community_id: string;
    subject_kind: "human" | "agent";
    person_id: string | null;
    agent_id: string | null;
    revoked_at: string | null;
  }>(
    `SELECT id, community_id, subject_kind, person_id, agent_id, revoked_at
     FROM member WHERE id = $1 AND revoked_at IS NULL`,
    [memberId],
  );
  if (result.rows.length === 0) return null;
  const r = result.rows[0];
  return {
    id: r.id,
    communityId: r.community_id,
    subjectKind: r.subject_kind,
    personId: r.person_id,
    agentId: r.agent_id,
    revokedAt: r.revoked_at,
  };
}
