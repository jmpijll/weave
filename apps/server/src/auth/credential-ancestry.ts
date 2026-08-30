import type { DbClient } from "../db/db-client.ts";

/**
 * M1.3.3 — read-time credential ancestry authorization (S7).
 *
 * Resolves a server-resolved credential to the active member it authorizes, by
 * walking the whole credential chain at read time: uncached, depth-bounded, and
 * cycle-proof. The write-side tree-shape triggers are NOT a substitute for this
 * read walk (reads bypass triggers), so the walk validates the chain it reads
 * independently of any prior write-time invariant.
 *
 * This primitive is read-only. It never creates, revokes, caches, memoizes, or
 * writes a credential, verifier, member, role, grant, audit row, or any other
 * row. Every failure (absent / repeated / over-depth / revoked / cross-person /
 * malformed-kind, or a member that is absent or revoked) collapses to the one
 * opaque `null` denial; the resolver never reports which step failed.
 *
 * A valid chain resolves only two shapes to a session actor:
 *   - a human DEVICE (kind='human' with a parent) -> the active human member for
 *     its person + community; and
 *   - an existing AGENT credential -> the active agent member for its recorded
 *     agent + community.
 * A human root or a host credential is never a direct actor: it resolves through
 * (not as) a session subject, so a presented root/host denies here.
 *
 * The bounded recursive CTE fetches the start row plus at most three parent
 * hops in one read; the application validator owns the typed, cycle-safe,
 * non-leaking decision.
 */

export interface CredentialAncestryInput {
  credentialId: string;
  communityId: string;
}

export type CredentialAncestryResult = { memberId: string } | null;

/** Bounded parent-hops cap on the walk (start row plus at most 3 hops). */
const MAX_PARENT_HOPS = 3;

interface CredentialChainRow {
  id: string;
  person_id: string;
  kind: "human" | "host" | "agent";
  parent_credential_id: string | null;
  revoked_at: string | null;
  depth: number;
}

interface ActiveMemberRow {
  id: string;
}

/**
 * Resolve a credential to the active member it authorizes, denying (null) on any
 * invalid chain or absent/revoked member. Read-only, uncached, never writes.
 */
export async function resolveCredentialToActiveMember(
  client: DbClient,
  input: CredentialAncestryInput,
): Promise<CredentialAncestryResult> {
  const chain = await fetchChain(client, input.credentialId);
  if (!isValidChain(chain)) return null;
  return await resolveMember(client, input.communityId, chain);
}

/**
 * One bounded recursive read of the start credential plus at most three parent
 * hops, ordered root-last (start first). The depth cap makes a cycle or an
 * over-long chain terminate in SQL; the validator then rejects both shapes.
 */
async function fetchChain(client: DbClient, credentialId: string): Promise<CredentialChainRow[]> {
  const result = await client.query<CredentialChainRow>(
    `WITH RECURSIVE chain AS (
       SELECT id, person_id, kind, parent_credential_id, revoked_at, 0 AS depth
       FROM credential
       WHERE id = $1
       UNION ALL
       SELECT c.id, c.person_id, c.kind, c.parent_credential_id, c.revoked_at, ch.depth + 1
       FROM credential c
       JOIN chain ch ON c.id = ch.parent_credential_id
       WHERE ch.depth < ${MAX_PARENT_HOPS}
     )
     SELECT id, person_id, kind, parent_credential_id, revoked_at, depth
     FROM chain
     ORDER BY depth`,
    [credentialId],
  );
  return result.rows;
}

/**
 * Validate the fetched chain as a typed, acyclic, same-person, unrevoked path
 * terminating at a human root, and confirm the start credential is one of the
 * two actor shapes (human device / agent). Hosts, roots, human roots presented
 * directly, fabricated cycles, over-path chains, cross-person chains, and any
 * revoked node all deny.
 */
function isValidChain(rows: CredentialChainRow[]): boolean {
  if (rows.length === 0) return false;

  // Cycle / repeated-ID guard (visited set), independent of the SQL depth cap.
  const seen = new Set<string>();
  for (const row of rows) {
    if (seen.has(row.id)) return false;
    seen.add(row.id);
  }

  // No revoked node anywhere in the chain (S7 core).
  for (const row of rows) {
    if (row.revoked_at !== null) return false;
  }

  // The whole chain must belong to one person.
  const personId = rows[0].person_id;
  for (const row of rows) {
    if (row.person_id !== personId) return false;
  }

  // The chain must terminate at a human root within the hop cap. A non-null
  // parent on the deepest fetched row means the chain is longer than the cap
  // (over-depth); a terminal that is not a human root is malformed.
  const terminal = rows[rows.length - 1];
  if (terminal.parent_credential_id !== null) return false;
  if (terminal.kind !== "human") return false;

  const start = rows[0];

  if (start.kind === "human") {
    // A human device (has a parent) must parent directly to the human root; a
    // human root (no parent) is never a direct actor.
    if (start.parent_credential_id === null) return false;
    if (rows.length !== 2) return false;
    if (rows[1].kind !== "human") return false;
    return true;
  }

  if (start.kind === "agent") {
    // An agent credential must lie agent -> host -> human root.
    if (rows.length !== 3) return false;
    if (rows[1].kind !== "host") return false;
    return true;
  }

  // host (and any unrecognized kind) is never a direct actor.
  return false;
}

type ResolveTarget =
  | { kind: "human"; personId: string }
  | { kind: "agent"; agentId: string };

/**
 * Resolve the validated chain's start credential to its member lookup target.
 * For a human device this is its person; for an agent credential it must be a
 * PRESENT agent record whose recorded host credential equals the chain's parent
 * (the read path does not trust the write-side host binding trigger).
 */
async function resolveTarget(client: DbClient, chain: CredentialChainRow[]): Promise<ResolveTarget | null> {
  const start = chain[0];
  if (start.kind === "human") {
    return { kind: "human", personId: start.person_id };
  }

  const agent = await client.query<{ id: string; host_id: string }>(
    `SELECT a.id, a.host_id FROM agent a WHERE a.credential_id = $1`,
    [start.id],
  );
  if (agent.rows.length === 0) return null;

  const host = await client.query<{ credential_id: string }>(
    `SELECT h.credential_id FROM host h WHERE h.id = $1`,
    [agent.rows[0].host_id],
  );
  if (host.rows.length === 0) return null;
  if (host.rows[0].credential_id !== start.parent_credential_id) return null;

  return { kind: "agent", agentId: agent.rows[0].id };
}

async function resolveMember(client: DbClient, communityId: string, chain: CredentialChainRow[]): Promise<CredentialAncestryResult> {
  const target = await resolveTarget(client, chain);
  if (target === null) return null;

  const result =
    target.kind === "human"
      ? await client.query<ActiveMemberRow>(
          `SELECT id FROM member
           WHERE community_id = $1 AND subject_kind = 'human'
             AND person_id = $2 AND revoked_at IS NULL`,
          [communityId, target.personId],
        )
      : await client.query<ActiveMemberRow>(
          `SELECT id FROM member
           WHERE community_id = $1 AND subject_kind = 'agent'
             AND agent_id = $2 AND revoked_at IS NULL`,
          [communityId, target.agentId],
        );

  if (result.rows.length === 0) return null;
  return { memberId: result.rows[0].id };
}
