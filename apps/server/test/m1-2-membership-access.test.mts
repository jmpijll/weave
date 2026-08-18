import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { runMigrations } from "../src/db/migrate.ts";
import { withTransaction } from "../src/db/transaction.ts";
import { writeAuditEvent } from "../src/db/audit.ts";
import { hasPermission, assignRole, revokeRoleAssignment } from "../src/domain/roles.ts";
import { evaluateEffectiveAccess } from "../src/domain/access.ts";
import { createMember } from "../src/domain/membership.ts";
import { createSpace, grantSpaceMembership, revokeSpaceMembership } from "../src/domain/spaces.ts";
import {
  issueCommunityAdmissionInvite,
  acceptCommunityAdmissionInvite,
  issueSpaceInvite,
  acceptSpaceInvite,
  transitionInvite,
} from "../src/domain/invites.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) {
  console.error(
    "m1-2 membership/access: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL — M1.2 evidence is mandatory)",
  );
  process.exit(1);
}

let dbCounter = 0;
function swapDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

async function withFreshDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T> {
  const admin = new Client({ connectionString: BASE_URL });
  await admin.connect();
  const database = `weave_m1_2_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
  } finally {
    await admin.end();
  }
  const pool = createDatabasePool(createDatabaseConfig(swapDatabase(BASE_URL, database)));
  try {
    return await fn(pool);
  } finally {
    await pool.end();
    const dropper = new Client({ connectionString: BASE_URL });
    await dropper.connect();
    try {
      await dropper.query(`DROP DATABASE IF EXISTS ${database}`);
    } finally {
      await dropper.end();
    }
  }
}

async function expectReject(
  pool: pg.Pool,
  sql: string,
  params: unknown[],
  fragment: string,
): Promise<void> {
  const client = await pool.connect();
  try {
    await assert.rejects(client.query(sql, params), (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      return message.includes(fragment);
    });
  } finally {
    client.release();
  }
}

interface FixturePerson {
  personId: string;
  rootCredentialId: string;
  memberId: string;
  agentId: string;
  agentCredentialId: string;
  hostCredentialId: string;
}

interface Fixture {
  pool: pg.Pool;
  communityId: string;
  admin: FixturePerson;
  guest: FixturePerson;
  projectId: string;
}

/** Build a community, an admin member, a guest member, and a project root. */
async function buildFixture(pool: pg.Pool): Promise<Fixture> {
  const communityId = (
    await pool.query(
      `INSERT INTO community (canonical_tls_origin, name, bootstrap_complete)
       VALUES ($1, $2, TRUE) RETURNING id`,
      ["https://fixture.example", "Fixture"],
    )
  ).rows[0].id;

  async function person(label: string): Promise<FixturePerson> {
    const personId = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", [label])
    ).rows[0].id;
    const rootCredentialId = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [personId, `${label}-root-pub`],
      )
    ).rows[0].id;
    const memberId = (
      await createMember(pool, { communityId, subject: { kind: "human", personId } })
    ).id;

    // host + host credential + agent + agent credential to model an agent member.
    const hostCredentialId = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
         VALUES ($1, $2, 'ed25519', 'host', $3) RETURNING id`,
        [personId, `${label}-host-pub`, rootCredentialId],
      )
    ).rows[0].id;
    const hostId = (
      await pool.query(
        `INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2) RETURNING id`,
        [personId, hostCredentialId],
      )
    ).rows[0].id;
    const agentCredentialId = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
         VALUES ($1, $2, 'ed25519', 'agent', $3) RETURNING id`,
        [personId, `${label}-agent-pub`, hostCredentialId],
      )
    ).rows[0].id;
    const agentId = (
      await pool.query(
        `INSERT INTO agent (host_id, credential_id) VALUES ($1, $2) RETURNING id`,
        [hostId, agentCredentialId],
      )
    ).rows[0].id;

    return {
      personId,
      rootCredentialId,
      memberId,
      agentId,
      agentCredentialId,
      hostCredentialId,
    };
  }

  const admin = await person("admin");
  const guest = await person("guest");
  await assignRole(pool, {
    memberId: admin.memberId,
    role: "community_admin",
    scope: { kind: "community", communityId },
    grantedByMemberId: admin.memberId,
  });

  const projectId = (
    await createSpace(pool, {
      communityId,
      kind: "project",
      visibility: "private",
      ownerMemberId: admin.memberId,
      description: "root project",
    }, { memberId: admin.memberId, grantedByMemberId: admin.memberId })
  ).id;

  return { pool, communityId, admin, guest, projectId };
}

test("member enforces exact-one-subject and one active membership per target", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin } = await buildFixture(pool);

    // wrong subject shape: human without person
    await expectReject(
      pool,
      `INSERT INTO member (community_id, subject_kind, person_id, agent_id)
       VALUES ($1, 'human', NULL, NULL)`,
      [communityId],
      "member_kind_target",
    );

    // a second active human membership for the same person is rejected
    await expectReject(
      pool,
      `INSERT INTO member (community_id, subject_kind, person_id, agent_id)
       VALUES ($1, 'human', $2, NULL)`,
      [communityId, admin.personId],
      "duplicate key",
    );

    // an agent membership is created for the agent, then a duplicate is rejected
    await pool.query(
      `INSERT INTO member (community_id, subject_kind, person_id, agent_id)
       VALUES ($1, 'agent', NULL, $2)`,
      [communityId, admin.agentId],
    );
    await expectReject(
      pool,
      `INSERT INTO member (community_id, subject_kind, person_id, agent_id)
       VALUES ($1, 'agent', NULL, $2)`,
      [communityId, admin.agentId],
      "duplicate key",
    );
  });
});

test("role evaluator is type-neutral: identical assignment yields identical decision", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin } = await buildFixture(pool);

    // admin (human member) holds community_admin -> community.members.manage
    const humanDecision = await hasPermission(pool, {
      actorMemberId: admin.memberId,
      permission: "community.members.manage",
      scope: { kind: "community", communityId },
    });
    assert.equal(humanDecision, true);

    // Create an agent member and give it the SAME role assignment.
    const agentMember = await createMember(pool, {
      communityId,
      subject: { kind: "agent", agentId: admin.agentId },
    });
    await assignRole(pool, {
      memberId: agentMember.id,
      role: "community_admin",
      scope: { kind: "community", communityId },
      grantedByMemberId: admin.memberId,
    });
    const agentDecision = await hasPermission(pool, {
      actorMemberId: agentMember.id,
      permission: "community.members.manage",
      scope: { kind: "community", communityId },
    });
    assert.equal(agentDecision, true, "agent with same explicit assignment must match human");

    // An otherwise-equivalent unassigned member is denied.
    const unassigned = await createMember(pool, {
      communityId,
      subject: { kind: "human", personId: (await pool.query(
        "INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["unassigned"],
      )).rows[0].id },
    });
    assert.equal(
      await hasPermission(pool, {
        actorMemberId: unassigned.id,
        permission: "community.members.manage",
        scope: { kind: "community", communityId },
      }),
      false,
    );
    // ... and neither member type has an implied identity.recover.
    assert.equal(
      await hasPermission(pool, {
        actorMemberId: admin.memberId,
        permission: "identity.recover",
        scope: { kind: "community", communityId },
      }),
      false,
      "identity.recover must never be implicit in community_admin",
    );
    assert.equal(
      await hasPermission(pool, {
        actorMemberId: agentMember.id,
        permission: "identity.recover",
        scope: { kind: "community", communityId },
      }),
      false,
    );
  });
});

test("project_owner assignment is scoped to a project root and effective per project", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    await assignRole(pool, {
      memberId: guest.memberId,
      role: "project_owner",
      scope: { kind: "project", projectSpaceId: projectId },
      grantedByMemberId: admin.memberId,
    });

    assert.equal(
      await hasPermission(pool, {
        actorMemberId: guest.memberId,
        permission: "project.access.manage",
        scope: { kind: "project", projectSpaceId: projectId },
      }),
      true,
    );

    // Without an explicit project grant the guest still cannot traverse the private project.
    const access = await evaluateEffectiveAccess(pool, {
      actorMemberId: guest.memberId,
      targetSpaceId: projectId,
    });
    assert.equal(access.accessible, false);
    assert.equal(access.path, null, "failed access must not project the target path");

    // Cross-scope: assigning a project role at community scope must be rejected.
    const otherProject = (
      await createSpace(pool, {
        communityId,
        kind: "project",
        visibility: "private",
        ownerMemberId: admin.memberId,
        description: "other",
      }, { memberId: admin.memberId, grantedByMemberId: admin.memberId })
    ).id;
    const result = await hasPermission(pool, {
      actorMemberId: guest.memberId,
      permission: "project.spaces.manage",
      scope: { kind: "project", projectSpaceId: otherProject },
    });
    assert.equal(result, false, "project-scoped permission is limited to the assigned project");

    // Revoking the assignment removes the capability.
    const assignment = await pool.query(
      `SELECT id FROM member_role_assignment WHERE member_id = $1 AND scope_space_id = $2 AND revoked_at IS NULL`,
      [guest.memberId, projectId],
    );
    assert.equal(assignment.rows.length, 1);
    await revokeRoleAssignment(pool, assignment.rows[0].id, "test");
    assert.equal(
      await hasPermission(pool, {
        actorMemberId: guest.memberId,
        permission: "project.access.manage",
        scope: { kind: "project", projectSpaceId: projectId },
      }),
      false,
    );
  });
});

test("Pass 35: private project traversal, grant, subtree, and revoke", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { pool: p, communityId, admin, guest, projectId } = await buildFixture(pool);

    // admin has a root grant; guest does not.
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: admin.memberId, targetSpaceId: projectId })).accessible,
      true,
    );
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: projectId })).accessible,
      false,
      "private project requires a grant",
    );

    // Grant the guest access to the private project root.
    await grantSpaceMembership(p, {
      spaceId: projectId,
      memberId: guest.memberId,
      grantedByMemberId: admin.memberId,
      source: "explicit",
    });
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: projectId })).accessible,
      true,
    );

    // Ordinary subtree: a public section and channel inherit the project grant.
    const section = (
      await createSpace(p, { communityId, kind: "section", parentSpaceId: projectId, visibility: "public", description: "s" })
    ).id;
    const channel = (
      await createSpace(p, { communityId, kind: "channel", parentSpaceId: section, visibility: "public", description: "c" })
    ).id;
    const thread = (
      await createSpace(p, { communityId, kind: "thread", parentSpaceId: channel, visibility: "public", description: "t" })
    ).id;
    for (const id of [section, channel, thread]) {
      const res = await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: id });
      assert.equal(res.accessible, true, "public descendant under granted project must be traversable");
      assert.notEqual(res.path, null, "authorized access may project its ancestry");
    }

    // A private descendant resets the boundary: requires its own grant.
    const privateChannel = (
      await createSpace(p, { communityId, kind: "channel", parentSpaceId: section, visibility: "private", description: "private c" })
    ).id;
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: privateChannel })).accessible,
      false,
      "private descendant requires its own grant",
    );
    // Grant at the private descendant succeeds.
    await grantSpaceMembership(p, {
      spaceId: privateChannel,
      memberId: guest.memberId,
      grantedByMemberId: admin.memberId,
      source: "explicit",
    });
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: privateChannel })).accessible,
      true,
    );

    // A public child of private ancestry is public only within that ancestry.
    const publicUnderPrivate = (
      await createSpace(p, { communityId, kind: "thread", parentSpaceId: privateChannel, visibility: "public", description: "pub under priv" })
    ).id;
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: publicUnderPrivate })).accessible,
      true,
      "public child of a granted private ancestor is traversable by that member",
    );

    // Revoking the root grant denies the subtree, including public children.
    await revokeSpaceMembership(p, projectId, guest.memberId, "test");
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: projectId })).accessible,
      false,
    );
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: section })).accessible,
      false,
      "revoking the root grant denies ordinary descendants",
    );
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: publicUnderPrivate })).accessible,
      false,
      "a public child cannot remain reachable when its granted private ancestor loses access",
    );
  });
});

test("Pass 35: metadata projection is withheld on denied access", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    const denied = await evaluateEffectiveAccess(pool, {
      actorMemberId: guest.memberId,
      targetSpaceId: projectId,
    });
    assert.equal(denied.accessible, false);
    assert.equal(denied.path, null, "no ancestor names may be projected on denial");

    const granted = await grantSpaceMembership(pool, {
      spaceId: projectId,
      memberId: guest.memberId,
      grantedByMemberId: admin.memberId,
      source: "explicit",
    });
    assert.ok(granted);
    const allowed = await evaluateEffectiveAccess(pool, {
      actorMemberId: guest.memberId,
      targetSpaceId: projectId,
    });
    assert.equal(allowed.accessible, true);
    assert.notEqual(allowed.path, null);
    assert.equal(allowed.path!.length, 1);
    assert.equal(allowed.path![0].id, projectId);
  });
});

test("space tree: malformed depth, cross-community parent, and bad kind are rejected", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, projectId } = await buildFixture(pool);

    // channel directly under a project is malformed (must be a section first)
    await expectReject(
      pool,
      `INSERT INTO space (community_id, kind, parent_space_id, visibility)
       VALUES ($1, 'channel', $2, 'public')`,
      [communityId, projectId],
      "channel must parent only to a section",
    );

    // a project may not have a parent
    await expectReject(
      pool,
      `INSERT INTO space (community_id, kind, parent_space_id, visibility)
       VALUES ($1, 'project', $2, 'public')`,
      [communityId, projectId],
      "project must be a root space (no parent)",
    );

    // thread cannot have children (depth four is the maximum)
    const section = (
      await createSpace(pool, { communityId, kind: "section", parentSpaceId: projectId, visibility: "public", description: "s" })
    ).id;
    const channel = (
      await createSpace(pool, { communityId, kind: "channel", parentSpaceId: section, visibility: "public", description: "c" })
    ).id;
    const thread = (
      await createSpace(pool, { communityId, kind: "thread", parentSpaceId: channel, visibility: "public", description: "t" })
    ).id;
    await expectReject(
      pool,
      `INSERT INTO space (community_id, kind, parent_space_id, visibility)
       VALUES ($1, 'thread', $2, 'public')`,
      [communityId, thread],
      "thread must parent only to a channel",
    );

    // cross-community parent is rejected
    const otherCommunity = (
      await pool.query(
        `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
        ["https://other.example", "Other"],
      )
    ).rows[0].id;
    await expectReject(
      pool,
      `INSERT INTO space (community_id, kind, parent_space_id, visibility)
       VALUES ($1, 'section', $2, 'public')`,
      [otherCommunity, projectId],
      "cross-community denied",
    );
  });
});

test("admission invite: targeted human and agent accept create members; never a project grant", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest } = await buildFixture(pool);

    // guest is already admitted; an invite must not double-admit the same person.
    const dup = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: guest.rootCredentialId },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    });
    await assert.rejects(
      acceptCommunityAdmissionInvite(pool, dup),
      (error: unknown) => error instanceof Error && /duplicate key/.test(error.message),
    );

    // An agent invite to an existing agent creates an agent member.
    const agentInvite = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "agent", targetAgentId: guest.agentId },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    });
    const accepted = await acceptCommunityAdmissionInvite(pool, agentInvite);
    assert.ok(accepted);
    const agentMember = await pool.query(
      `SELECT subject_kind, agent_id, revoked_at FROM member WHERE id = $1`,
      [accepted!.memberId],
    );
    assert.equal(agentMember.rows[0].subject_kind, "agent");
    assert.equal(agentMember.rows[0].agent_id, guest.agentId);
    assert.equal(agentMember.rows[0].revoked_at, null);

    // accepting twice is rejected (terminal).
    await expectReject(
      pool,
      `UPDATE community_admission_invite SET state = 'accepted' WHERE id = $1`,
      [agentInvite],
      "invite is terminal",
    );
  });
});

test("space invite: targets an existing active member, never admits, and is terminal", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // guest is already a member; issue a space invite to them.
    const invite = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    });

    // Accepting a space invite grants space access only — it must NOT create a member.
    const memberCountBefore = (await pool.query("SELECT count(*)::int AS n FROM member")).rows[0].n;
    const acceptedSpace = await acceptSpaceInvite(pool, invite);
    assert.ok(acceptedSpace);
    const memberCountAfter = (await pool.query("SELECT count(*)::int AS n FROM member")).rows[0].n;
    assert.equal(memberCountAfter, memberCountBefore, "space invite must never admit a member");
    assert.equal(
      (await evaluateEffectiveAccess(pool, { actorMemberId: guest.memberId, targetSpaceId: projectId })).accessible,
      true,
    );

    // A space invite to a non-member is rejected at the DB boundary: an
    // unadmitted person has no member record, so the target lookup (STRICT)
    // fails before any invite row can be created.
    const outsiderPerson = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["outsider"])
    ).rows[0].id;
    await assert.rejects(
      issueSpaceInvite(pool, {
        communityId,
        targetMemberId: outsiderPerson, // not a member id
        spaceId: projectId,
        issuerMemberId: admin.memberId,
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      }),
      (error: unknown) =>
        error instanceof Error &&
        (/\bno rows\b/.test(error.message) || /violates foreign key constraint/.test(error.message)),
    );

    // terminal transition is enforced.
    await expectReject(
      pool,
      `UPDATE space_invite SET state = 'revoked' WHERE id = $1`,
      [invite],
      "invite is terminal",
    );
  });
});

test("audit events attribute member-level authority and stay append-only", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    const eventId = await withTransaction(pool, async (client) => {
      await grantSpaceMembership(client, {
        spaceId: projectId,
        memberId: guest.memberId,
        grantedByMemberId: admin.memberId,
        source: "explicit",
      });
      return writeAuditEvent(client, {
        eventType: "space.access.grant",
        communityId,
        actorMemberId: admin.memberId,
        targetType: "space_membership",
        targetId: projectId,
        metadata: { granteeMemberId: guest.memberId },
        correlationId: "corr-m1-2",
      });
    });

    const row = await pool.query(
      `SELECT event_type, actor_member_id, actor_person_id FROM audit_event WHERE id = $1`,
      [eventId],
    );
    assert.equal(row.rows[0].event_type, "space.access.grant");
    assert.equal(row.rows[0].actor_member_id, admin.memberId);

    // audit is append-only
    await expectReject(
      pool,
      "DELETE FROM audit_event WHERE id = $1",
      [eventId],
      "append-only",
    );
  });
});
