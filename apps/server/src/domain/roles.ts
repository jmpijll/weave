import { randomUUID } from "node:crypto";
import type { DbClient } from "../db/db-client.ts";
import { inTransaction } from "../db/transaction.ts";
import { AUDIT_EVENT, writeAuditEvent } from "../db/audit.ts";

export type PermissionName =
  | "community.members.manage"
  | "community.projects.create"
  | "roles.assign"
  | "project.spaces.manage"
  | "project.access.manage"
  | "project.invites.manage"
  | "identity.recover";

export type RoleName = "community_admin" | "project_owner" | "recovery_operator";

export interface RoleAssignmentInput {
  memberId: string;
  role: RoleName;
  /** Community scope for community_admin/recovery_operator; project root for project_owner. */
  scope:
    | { kind: "community"; communityId: string }
    | { kind: "project"; projectSpaceId: string };
  /** The authenticated actor performing the assignment. */
  grantedByMemberId: string;
  correlationId?: string;
}

/** Resolve the seeded role id by name. */
export async function roleIdForName(
  client: DbClient,
  name: RoleName,
): Promise<string | null> {
  const result = await client.query<{ id: string }>(
    "SELECT id FROM role WHERE name = $1",
    [name],
  );
  return result.rows.length > 0 ? result.rows[0].id : null;
}

/** The scope a permission is evaluated against. Community or a project root. */
export type PermissionScope =
  | { kind: "community"; communityId: string }
  | { kind: "project"; projectSpaceId: string };

export interface HasPermissionInput {
  /** The authenticated actor, resolved to a member. Never a caller-supplied role. */
  actorMemberId: string;
  permission: PermissionName;
  scope: PermissionScope;
}

/**
 * The one authoritative role evaluator: does `actorMemberId` hold `permission`
 * at `scope`? It joins only active membership, non-revoked assignments,
 * `role_permission`, and the requested scope. It contains no `member.kind`,
 * credential kind, or host/agent branch, so a human and an agent with the same
 * explicit scoped assignment receive the identical decision.
 */
export async function hasPermission(
  client: DbClient,
  input: HasPermissionInput,
): Promise<boolean> {
  const result = await client.query<{ granted: boolean }>(
    `SELECT EXISTS (
       SELECT 1
       FROM member_role_assignment a
       JOIN member m        ON m.id = a.member_id AND m.revoked_at IS NULL
       JOIN role r          ON r.id = a.role_id
       JOIN role_permission rp ON rp.role_id = r.id
       JOIN permission p    ON p.id = rp.permission_id
       WHERE m.id = $1
         AND a.revoked_at IS NULL
         AND p.name = $2
         AND (
           ($3 = 'community' AND a.scope_community_id = $4)
           OR
           ($3 = 'project' AND a.scope_space_id = $5)
         )
     ) AS granted`,
    [
      input.actorMemberId,
      input.permission,
      input.scope.kind,
      input.scope.kind === "community" ? input.scope.communityId : input.scope.projectSpaceId,
      input.scope.kind === "community" ? null : input.scope.projectSpaceId,
    ],
  );
  return result.rows[0].granted;
}

/**
 * Assign a bootstrap role to a member at an explicit scope, with typed audit.
 * Returns the new assignment id. The database trigger rejects cross-community,
 * wrong-scope, or non-project-root targets.
 */
export async function assignRole(
  client: DbClient,
  input: RoleAssignmentInput,
): Promise<string> {
  return inTransaction(client, async (tx) => {
    const roleId = await roleIdForName(tx, input.role);
    if (!roleId) throw new Error(`unknown role: ${input.role}`);
    const result = await tx.query<{ id: string }>(
      `INSERT INTO member_role_assignment
         (member_id, role_id, scope_community_id, scope_space_id, granted_by_member_id)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [
        input.memberId,
        roleId,
        input.scope.kind === "community" ? input.scope.communityId : null,
        input.scope.kind === "project" ? input.scope.projectSpaceId : null,
        input.grantedByMemberId,
      ],
    );
    const assignmentId = result.rows[0].id;
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.roleAssigned,
      communityId: await scopeCommunityId(tx, input.scope),
      actorMemberId: input.grantedByMemberId,
      targetType: "member_role_assignment",
      targetId: assignmentId,
      metadata: { memberId: input.memberId, role: input.role },
      correlationId: input.correlationId ?? randomUUID(),
    });
    return assignmentId;
  });
}

/** Revoke an active assignment (retaining the row for audit), with typed audit. */
export async function revokeRoleAssignment(
  client: DbClient,
  assignmentId: string,
  reason: string,
  revokedByMemberId: string,
  correlationId?: string,
): Promise<void> {
  await inTransaction(client, async (tx) => {
    const result = await tx.query<{
      community_id: string | null;
      scope_community_id: string | null;
      scope_space_id: string | null;
    }>(
      `UPDATE member_role_assignment
       SET revoked_at = now(), revoked_reason = $2
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING scope_community_id, scope_space_id`,
      [assignmentId, reason],
    );
    if (result.rows.length === 0) return;
    const row = result.rows[0];
    const communityId =
      row.scope_community_id ??
      (row.scope_space_id
        ? (await tx.query<{ community_id: string }>(
            "SELECT community_id FROM space WHERE id = $1",
            [row.scope_space_id],
          )).rows[0]?.community_id ?? null
        : null);
    await writeAuditEvent(tx, {
      eventType: AUDIT_EVENT.roleRevoked,
      communityId,
      actorMemberId: revokedByMemberId,
      targetType: "member_role_assignment",
      targetId: assignmentId,
      metadata: { reason },
      correlationId: correlationId ?? randomUUID(),
    });
  });
}

async function scopeCommunityId(
  client: DbClient,
  scope: RoleAssignmentInput["scope"],
): Promise<string> {
  if (scope.kind === "community") return scope.communityId;
  const result = await client.query<{ community_id: string }>(
    "SELECT community_id FROM space WHERE id = $1",
    [scope.projectSpaceId],
  );
  if (result.rows.length === 0) throw new Error("project scope space not found");
  return result.rows[0].community_id;
}
