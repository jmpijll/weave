import type { DbClient } from "../db/db-client.ts";

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
 * Assign a bootstrap role to a member at an explicit scope. Returns the new
 * assignment id. The database trigger rejects cross-community, wrong-scope, or
 * non-project-root targets.
 */
export async function assignRole(
  client: DbClient,
  input: RoleAssignmentInput,
): Promise<string> {
  const roleId = await roleIdForName(client, input.role);
  if (!roleId) throw new Error(`unknown role: ${input.role}`);
  const result = await client.query<{ id: string }>(
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
  return result.rows[0].id;
}

/** Revoke an active assignment, retaining the row for audit. */
export async function revokeRoleAssignment(
  client: DbClient,
  assignmentId: string,
  reason: string,
): Promise<void> {
  await client.query(
    `UPDATE member_role_assignment
     SET revoked_at = now(), revoked_reason = $2
     WHERE id = $1 AND revoked_at IS NULL`,
    [assignmentId, reason],
  );
}
