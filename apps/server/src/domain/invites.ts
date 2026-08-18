import type { DbClient } from "../db/db-client.ts";
import type { Pool } from "pg";
import { withTransaction } from "../db/transaction.ts";
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
}

export interface SpaceInviteInput {
  communityId: string;
  targetMemberId: string;
  spaceId: string;
  issuerMemberId: string;
  expiresAt: string;
}

export async function issueCommunityAdmissionInvite(
  client: DbClient,
  input: AdmissionInviteInput,
): Promise<string> {
  const result = await client.query<{ id: string }>(
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
  return result.rows[0].id;
}

export async function issueSpaceInvite(
  client: DbClient,
  input: SpaceInviteInput,
): Promise<string> {
  const result = await client.query<{ id: string }>(
    `INSERT INTO space_invite
       (community_id, target_member_id, space_id, issuer_member_id, expires_at)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id`,
    [input.communityId, input.targetMemberId, input.spaceId, input.issuerMemberId, input.expiresAt],
  );
  return result.rows[0].id;
}

/** Transition an invite (admission or space) to a terminal state. */
export async function transitionInvite(
  client: DbClient,
  table: "community_admission_invite" | "space_invite",
  inviteId: string,
  to: Exclude<InviteState, "issued">,
): Promise<void> {
  const allowedTo = ["accepted", "revoked", "expired"];
  if (!allowedTo.includes(to)) throw new Error(`invalid invite target state: ${to}`);
  const column = to === "accepted" ? "accepted_at" : "revoked_at";
  await client.query(
    `UPDATE ${table} SET state = $2, ${column} = now() WHERE id = $1 AND state = 'issued'`,
    [inviteId, to],
  );
}

/** Accept a community admission invite, creating the identified member in the same transaction. */
export async function acceptCommunityAdmissionInvite(
  client: DbClient,
  inviteId: string,
): Promise<{ memberId: string } | null> {
  if (!("release" in client)) {
    return withTransaction(client as Pool, (tx) => acceptCommunityAdmissionInvite(tx, inviteId));
  }
  const invite = await client.query<{
    community_id: string;
    target_kind: "human" | "agent";
    target_credential_id: string | null;
    target_agent_id: string | null;
  }>(
    `SELECT community_id, target_kind, target_credential_id, target_agent_id
     FROM community_admission_invite WHERE id = $1`,
    [inviteId],
  );
  if (invite.rows.length === 0) return null;
  const row = invite.rows[0];
  const member =
    row.target_kind === "human"
      ? await createMember(client, {
          communityId: row.community_id,
          subject: { kind: "human", personId: await credentialPersonId(client, row.target_credential_id!) },
        })
      : await createMember(client, {
          communityId: row.community_id,
          subject: { kind: "agent", agentId: row.target_agent_id! },
        });
  await transitionInvite(client, "community_admission_invite", inviteId, "accepted");
  return { memberId: member.id };
}

/** Accept a space invite: grants project/private-descendant access only, never admission. */
export async function acceptSpaceInvite(
  client: DbClient,
  inviteId: string,
): Promise<{ spaceId: string } | null> {
  if (!("release" in client)) {
    return withTransaction(client as Pool, (tx) => acceptSpaceInvite(tx, inviteId));
  }
  const invite = await client.query<{
    target_member_id: string;
    space_id: string;
  }>(
    `SELECT target_member_id, space_id
     FROM space_invite WHERE id = $1 AND state = 'issued'`,
    [inviteId],
  );
  if (invite.rows.length === 0) return null;
  const row = invite.rows[0];
  await grantSpaceMembership(client, {
    spaceId: row.space_id,
    memberId: row.target_member_id,
    grantedByMemberId: row.target_member_id,
    source: "invite",
  });
  await transitionInvite(client, "space_invite", inviteId, "accepted");
  return { spaceId: row.space_id };
}

async function credentialPersonId(client: DbClient, credentialId: string): Promise<string> {
  const result = await client.query<{ person_id: string }>(
    "SELECT person_id FROM credential WHERE id = $1",
    [credentialId],
  );
  if (result.rows.length === 0) throw new Error("admission invite target credential not found");
  return result.rows[0].person_id;
}
