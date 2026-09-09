import type { DbClient } from "../db/db-client.ts";

export type SpaceKind = "project" | "section" | "channel" | "thread";
export type Visibility = "public" | "private";

export interface SpaceNode {
  id: string;
  kind: SpaceKind;
  parentSpaceId: string | null;
  visibility: Visibility;
  description: string | null;
  communityId: string;
}

export interface EffectiveAccessInput {
  /** The authenticated actor, resolved to a member. */
  actorMemberId: string;
  targetSpaceId: string;
}

export interface EffectiveAccessResult {
  /** Whether the actor may traverse to the target. */
  accessible: boolean;
  /**
   * The ancestor chain from project root to the target, root-first. Present
   * only when `accessible` is true. Never build response metadata from a failed
   * evaluation: a failed access check must not leak the target, its ancestors,
   * labels, or previews.
   */
  path: SpaceNode[] | null;
}

interface SpaceRow {
  id: string;
  kind: string;
  parent_space_id: string | null;
  visibility: string;
  description: string | null;
  community_id: string;
}

/**
 * Pass 35 effective access, enforced as a server authorization invariant.
 *
 * Walks the bounded ancestor chain (max depth 4) from project root to target,
 * rejects a malformed tree, requires the actor to be an active member of the
 * target's community and to traverse every ancestor, then applies the subtree
 * rule:
 *   - a direct grant at a space authorizes its ordinary (public) descendants;
 *   - a private space resets inherited authorization — only a direct grant at
 *     that boundary proceeds below it;
 *   - public never bypasses an earlier private boundary.
 *
 * Only after this check may response metadata be built; on failure the target,
 * ancestors, labels and previews are withheld entirely (`path` is null).
 */
export async function evaluateEffectiveAccess(
  client: DbClient,
  input: EffectiveAccessInput,
): Promise<EffectiveAccessResult> {
  // Fetch the bounded ancestor chain, root-first. Depth is capped at 4, but a
  // defensive limit keeps any unexpected longer chain from walking unbounded.
  const rows = await client.query<SpaceRow>(
    `WITH RECURSIVE chain AS (
       SELECT s.*, 0 AS depth
       FROM space s
       WHERE s.id = $1
       UNION ALL
       SELECT s.*, c.depth + 1
       FROM space s
       JOIN chain c ON s.id = c.parent_space_id
       WHERE c.depth < 4
     )
     SELECT id, kind, parent_space_id, visibility, description, community_id
     FROM chain`,
    [input.targetSpaceId],
  );

  if (rows.rows.length === 0) {
    return { accessible: false, path: null };
  }

  // Reject a malformed tree: every space except the project root must have a
  // parent, and the chain must terminate at a project root. If the walk came up
  // short (cycle or missing root), treat the space as inaccessible rather than
  // risking traversal of a malformed structure.
  const byId = new Map(rows.rows.map((r) => [r.id, r]));
  const root = rows.rows.find((r) => r.parent_space_id === null);
  if (!root) {
    return { accessible: false, path: null };
  }

  // Build the chain target-first by following parent pointers up to the root,
  // then reverse to root-first. Reject malformed trees: a non-root node without
  // a parent, a cycle, or a parent that is absent from the fetch.
  const targetFirst: SpaceNode[] = [];
  let current = byId.get(input.targetSpaceId)!;
  const visited = new Set<string>();
  for (;;) {
    if (visited.has(current.id)) {
      return { accessible: false, path: null };
    }
    visited.add(current.id);
    targetFirst.push({
      id: current.id,
      kind: current.kind as SpaceKind,
      parentSpaceId: current.parent_space_id,
      visibility: current.visibility as Visibility,
      description: current.description,
      communityId: current.community_id,
    });
    if (current.parent_space_id === null) break;
    const next = byId.get(current.parent_space_id);
    if (!next) {
      return { accessible: false, path: null };
    }
    current = next;
  }

  // The chain must terminate at a project root (parent null on a project).
  if (current.kind !== "project") {
    return { accessible: false, path: null };
  }
  const path = targetFirst.reverse();
  const communityId = root.community_id;

  // Require the actor to be an active member of the target's community.
  const member = await client.query<{ active: boolean }>(
    `SELECT (revoked_at IS NULL) AS active
     FROM member WHERE id = $1 AND community_id = $2`,
    [input.actorMemberId, communityId],
  );
  if (member.rows.length === 0 || !member.rows[0].active) {
    return { accessible: false, path: null };
  }

  // Evaluate the subtree rule from the root down. A grant at a space
  // authorizes ordinary descendants; a private space needs its own direct grant
  // to proceed below it; public never widens an earlier private boundary.
  let accessible = false;
  for (const node of path) {
    const granted = await hasActiveGrant(client, input.actorMemberId, node.id);
    if (node.parentSpaceId === null) {
      // Project root: the actor must hold a direct grant at the root (a public
      // project still requires membership, and a grant is the access token).
      accessible = granted;
    } else if (node.visibility === "private") {
      // Private boundary: reset — only a direct grant here proceeds.
      accessible = granted;
    }
    // public child: keep the parent's access (accessible stays as inherited).
    if (!accessible) return { accessible: false, path: null };
  }

  return { accessible: true, path };
}

async function hasActiveGrant(
  client: DbClient,
  memberId: string,
  spaceId: string,
): Promise<boolean> {
  const result = await client.query<{ granted: boolean }>(
    `SELECT EXISTS (
       SELECT 1 FROM space_membership
       WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL
     ) AS granted`,
    [spaceId, memberId],
  );
  return result.rows[0].granted;
}
