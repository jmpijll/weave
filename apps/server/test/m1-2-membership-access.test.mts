import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { runMigrations } from "../src/db/migrate.ts";
import { hasPermission, assignRole, revokeRoleAssignment } from "../src/domain/roles.ts";
import { evaluateEffectiveAccess } from "../src/domain/access.ts";
import { createMember } from "../src/domain/membership.ts";
import { createSpace, grantSpaceMembership, revokeSpaceMembership } from "../src/domain/spaces.ts";
import {
  issueCommunityAdmissionInvite,
  acceptCommunityAdmissionInvite,
  revokeCommunityAdmissionInvite,
  expireCommunityAdmissionInvite,
  issueSpaceInvite,
  acceptSpaceInvite,
  revokeSpaceInvite,
  expireSpaceInvite,
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

let corrCounter = 0;
function corr(label: string): string {
  corrCounter += 1;
  return `m1-2:${label}:${process.pid}:${corrCounter}`;
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
      createdByMemberId: admin.memberId,
      kind: "project",
      visibility: "private",
      ownerMemberId: admin.memberId,
      description: "root project",
    }, { memberId: admin.memberId, grantedByMemberId: admin.memberId }, corr("fixture-project"))
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
        createdByMemberId: admin.memberId,
        kind: "project",
        visibility: "private",
        ownerMemberId: admin.memberId,
        description: "other",
      }, { memberId: admin.memberId, grantedByMemberId: admin.memberId }, corr("other-project"))
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
    await revokeRoleAssignment(pool, assignment.rows[0].id, "test", admin.memberId);
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
      await createSpace(p, { communityId, createdByMemberId: admin.memberId, kind: "section", parentSpaceId: projectId, visibility: "public", description: "s" }, undefined, corr("p35-section"))
    ).id;
    const channel = (
      await createSpace(p, { communityId, createdByMemberId: admin.memberId, kind: "channel", parentSpaceId: section, visibility: "public", description: "c" }, undefined, corr("p35-channel"))
    ).id;
    const thread = (
      await createSpace(p, { communityId, createdByMemberId: admin.memberId, kind: "thread", parentSpaceId: channel, visibility: "public", description: "t" }, undefined, corr("p35-thread"))
    ).id;
    for (const id of [section, channel, thread]) {
      const res = await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: id });
      assert.equal(res.accessible, true, "public descendant under granted project must be traversable");
      assert.notEqual(res.path, null, "authorized access may project its ancestry");
    }

    // A private descendant resets the boundary: requires its own grant.
    const privateChannel = (
      await createSpace(p, { communityId, createdByMemberId: admin.memberId, kind: "channel", parentSpaceId: section, visibility: "private", description: "private c" }, undefined, corr("p35-private-channel"))
    ).id;
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: privateChannel })).accessible,
      false,
      "private descendant requires its own grant",
    );

    // Negative: a public child under an UNGRANTED private ancestor is denied —
    // public visibility never widens an earlier private boundary.
    const publicUnderPrivate = (
      await createSpace(p, { communityId, createdByMemberId: admin.memberId, kind: "thread", parentSpaceId: privateChannel, visibility: "public", description: "pub under priv" }, undefined, corr("p35-pub-under-private"))
    ).id;
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: publicUnderPrivate })).accessible,
      false,
      "a public child of an ungranted private ancestor must be denied",
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
    assert.equal(
      (await evaluateEffectiveAccess(p, { actorMemberId: guest.memberId, targetSpaceId: publicUnderPrivate })).accessible,
      true,
      "public child of a granted private ancestor is traversable by that member",
    );

    // Revoking the root grant denies the subtree, including public children.
    await revokeSpaceMembership(p, projectId, guest.memberId, "test", admin.memberId);
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
      await createSpace(pool, { communityId, createdByMemberId: admin.memberId, kind: "section", parentSpaceId: projectId, visibility: "public", description: "s" }, undefined, corr("tree-section"))
    ).id;
    const channel = (
      await createSpace(pool, { communityId, createdByMemberId: admin.memberId, kind: "channel", parentSpaceId: section, visibility: "public", description: "c" }, undefined, corr("tree-channel"))
    ).id;
    const thread = (
      await createSpace(pool, { communityId, createdByMemberId: admin.memberId, kind: "thread", parentSpaceId: channel, visibility: "public", description: "t" }, undefined, corr("tree-thread"))
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
      correlationId: corr("dup-admission"),
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
      correlationId: corr("agent-admission"),
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
      correlationId: corr("space-invite"),
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

    // A single operation correlation ID is generated once when the caller omits
    // it, and the access grant and the acceptance share it exactly.
    const grantAudit = await pool.query(
      `SELECT correlation_id FROM audit_event
       WHERE event_type = $1 AND metadata->>'memberId' = $2 AND metadata->>'spaceId' = $3`,
      ["space.access.grant", guest.memberId, projectId],
    );
    const acceptedAudit = await pool.query(
      `SELECT correlation_id FROM audit_event WHERE event_type = $1 AND target_id = $2`,
      ["space.invite.accepted", invite],
    );
    assert.equal(grantAudit.rows.length, 1);
    assert.equal(acceptedAudit.rows.length, 1);
    assert.ok(grantAudit.rows[0].correlation_id, "an omitted correlation ID must be generated");
    assert.equal(
      acceptedAudit.rows[0].correlation_id,
      grantAudit.rows[0].correlation_id,
      "grant and accepted audits must share one operation correlation ID",
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
        correlationId: corr("outsider-space-invite"),
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

test("admission acceptance is a locked, once-only consume: revoked and expired invites cannot admit", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin } = await buildFixture(pool);
    const outsider = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["outsider"])
    ).rows[0].id;
    const outsiderRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [outsider, "outsider-root"],
      )
    ).rows[0].id;

    // A revoked invite is terminal: accepting it must be a no-op and admit nobody.
    const revokedInvite = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("revoked-admission"),
    });
    await pool.query(
      `UPDATE community_admission_invite SET state = 'revoked', revoked_reason = 'test' WHERE id = $1`,
      [revokedInvite],
    );
    assert.equal(await acceptCommunityAdmissionInvite(pool, revokedInvite), null);
    assert.equal(
      (await pool.query(
        "SELECT count(*)::int AS n FROM member WHERE community_id = $1", [communityId],
      )).rows[0].n,
      2,
      "a revoked admission invite must never admit a member",
    );

    // An expired invite is terminal in the same way.
    const expiredInvite = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("expired-admission"),
    });
    assert.equal(await acceptCommunityAdmissionInvite(pool, expiredInvite), null);
    assert.equal(
      (await pool.query(
        "SELECT count(*)::int AS n FROM member WHERE community_id = $1", [communityId],
      )).rows[0].n,
      2,
      "an expired admission invite must never admit a member",
    );

    // A valid invite accepts exactly once: a second accept is a no-op.
    const valid = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("valid-admission"),
    });
    const accepted = await acceptCommunityAdmissionInvite(pool, valid);
    assert.ok(accepted);
    assert.equal(await acceptCommunityAdmissionInvite(pool, valid), null, "once-only consume");
  });
});

test("admission and space invite targets and issuers are validated at the DB boundary", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // A human admission invite must target an active human ROOT credential, not
    // any credential: a device (kind=human with a parent) is rejected.
    const deviceCredential = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
         VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
        [guest.personId, "guest-device", guest.rootCredentialId],
      )
    ).rows[0].id;
    await expectReject(
      pool,
      `INSERT INTO community_admission_invite
         (community_id, target_kind, target_credential_id, issuer_member_id, expires_at)
       VALUES ($1, 'human', $2, $3, $4)`,
      [communityId, deviceCredential, admin.memberId, new Date(Date.now() + 3600_000).toISOString()],
      "active human root credential",
    );

    // A revoked human root is also rejected (a fresh person whose root is revoked).
    const revokedPerson = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["revoked person"])
    ).rows[0].id;
    const revokedRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [revokedPerson, "revoked-root"],
      )
    ).rows[0].id;
    await pool.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [revokedRoot]);
    await expectReject(
      pool,
      `INSERT INTO community_admission_invite
         (community_id, target_kind, target_credential_id, issuer_member_id, expires_at)
       VALUES ($1, 'human', $2, $3, $4)`,
      [communityId, revokedRoot, admin.memberId, new Date(Date.now() + 3600_000).toISOString()],
      "active human root credential",
    );

    // A space invite must target a project root or private descendant: a public
    // section is rejected.
    const publicSection = (
      await createSpace(pool, { communityId, createdByMemberId: admin.memberId, kind: "section", parentSpaceId: projectId, visibility: "public", description: "s" }, undefined, corr("target-public-section"))
    ).id;
    await expectReject(
      pool,
      `INSERT INTO space_invite
         (community_id, target_member_id, space_id, issuer_member_id, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [communityId, guest.memberId, publicSection, admin.memberId, new Date(Date.now() + 3600_000).toISOString()],
      "project root or a private descendant",
    );
    // ... but a private descendant is accepted.
    const privateSection = (
      await createSpace(pool, { communityId, createdByMemberId: admin.memberId, kind: "section", parentSpaceId: projectId, visibility: "private", description: "ps" }, undefined, corr("target-private-section"))
    ).id;
    await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: privateSection,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("target-private-invite"),
    });

    // A cross-community issuer is rejected for a space invite.
    const otherCommunity = (
      await pool.query(
        `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
        ["https://other.example", "Other"],
      )
    ).rows[0].id;
    const otherMember = await createMember(pool, {
      communityId: otherCommunity,
      subject: {
        kind: "human",
        personId: (await pool.query(
          "INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["other"],
        )).rows[0].id,
      },
    });
    await expectReject(
      pool,
      `INSERT INTO space_invite
         (community_id, target_member_id, space_id, issuer_member_id, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [communityId, guest.memberId, projectId, otherMember.id, new Date(Date.now() + 3600_000).toISOString()],
      "space invite issuer must be an active member of the community",
    );

    // A space invite issued by a revoked member is rejected.
    const willBeRevoked = await createMember(pool, {
      communityId,
      subject: {
        kind: "human",
        personId: (await pool.query(
          "INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["willrevoke"],
        )).rows[0].id,
      },
    });
    await pool.query(`UPDATE member SET revoked_at = now(), revoked_reason = 't' WHERE id = $1`, [willBeRevoked.id]);
    await expectReject(
      pool,
      `INSERT INTO space_invite
         (community_id, target_member_id, space_id, issuer_member_id, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [communityId, guest.memberId, projectId, willBeRevoked.id, new Date(Date.now() + 3600_000).toISOString()],
      "space invite issuer must be an active member of the community",
    );
  });
});

test("authorization matrix: every capability is identical for assigned human and agent, denied when unassigned", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // Two dedicated role holders: one human member and one agent member.
    const humanHolder = await createMember(pool, {
      communityId,
      subject: {
        kind: "human",
        personId: (await pool.query(
          "INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["human holder"],
        )).rows[0].id,
      },
    });
    const agentOwner = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["agent owner"])
    ).rows[0].id;
    const agentRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [agentOwner, "aowner-root"],
      )
    ).rows[0].id;
    const agentHostCred = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
         VALUES ($1, $2, 'ed25519', 'host', $3) RETURNING id`,
        [agentOwner, "aowner-host", agentRoot],
      )
    ).rows[0].id;
    const agentHost = (
      await pool.query(
        `INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2) RETURNING id`,
        [agentOwner, agentHostCred],
      )
    ).rows[0].id;
    const agentCred = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
         VALUES ($1, $2, 'ed25519', 'agent', $3) RETURNING id`,
        [agentOwner, "aowner-agent", agentHostCred],
      )
    ).rows[0].id;
    const agent = (
      await pool.query(
        `INSERT INTO agent (host_id, credential_id) VALUES ($1, $2) RETURNING id`,
        [agentHost, agentCred],
      )
    ).rows[0].id;
    const agentHolder = await createMember(pool, {
      communityId,
      subject: { kind: "agent", agentId: agent },
    });

    // Give both holders every M1 bootstrap role at the matching scope.
    for (const holder of [humanHolder.id, agentHolder.id]) {
      await assignRole(pool, {
        memberId: holder,
        role: "community_admin",
        scope: { kind: "community", communityId },
        grantedByMemberId: admin.memberId,
      });
      await assignRole(pool, {
        memberId: holder,
        role: "project_owner",
        scope: { kind: "project", projectSpaceId: projectId },
        grantedByMemberId: admin.memberId,
      });
      await assignRole(pool, {
        memberId: holder,
        role: "recovery_operator",
        scope: { kind: "community", communityId },
        grantedByMemberId: admin.memberId,
      });
    }

    // Every matrix capability: assigned human, assigned agent, and the
    // equivalent unassigned member (guest) — one combined evidence row.
    const cases = [
      { capability: "community.members.manage", scope: { kind: "community", communityId } },
      { capability: "community.projects.create", scope: { kind: "community", communityId } },
      { capability: "roles.assign", scope: { kind: "community", communityId } },
      { capability: "project.spaces.manage", scope: { kind: "project", projectSpaceId: projectId } },
      { capability: "project.access.manage", scope: { kind: "project", projectSpaceId: projectId } },
      { capability: "project.invites.manage", scope: { kind: "project", projectSpaceId: projectId } },
      { capability: "identity.recover", scope: { kind: "community", communityId } },
    ] as const;

    for (const { capability, scope } of cases) {
      assert.equal(
        await hasPermission(pool, { actorMemberId: humanHolder.id, permission: capability, scope }),
        true,
        `assigned human must hold ${capability}`,
      );
      assert.equal(
        await hasPermission(pool, { actorMemberId: agentHolder.id, permission: capability, scope }),
        true,
        `assigned agent must hold ${capability}`,
      );
      assert.equal(
        await hasPermission(pool, { actorMemberId: guest.memberId, permission: capability, scope }),
        false,
        `unassigned member must be denied ${capability}`,
      );
    }
  });
});

test("invite issue and revoke commands write typed audit; a no-op revoke or failed issue writes none", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // Issuing an admission invite records its typed issued audit with the issuer.
    const admissionInvite = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: guest.rootCredentialId },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("issue-admission-audit"),
    });
    const issuedAdmission = await pool.query(
      `SELECT event_type, actor_member_id, correlation_id FROM audit_event WHERE event_type = $1`,
      ["community.admission.invite.issued"],
    );
    assert.equal(issuedAdmission.rows.length, 1);
    assert.equal(issuedAdmission.rows[0].actor_member_id, admin.memberId);
    assert.ok(
      String(issuedAdmission.rows[0].correlation_id).startsWith("m1-2:issue-admission-audit:"),
      "issued-admission audit must carry the caller correlation id",
    );

    // Issuing a space invite records its typed issued audit with the issuer.
    const spaceInvite = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("issue-space-audit"),
    });
    const issuedSpace = await pool.query(
      `SELECT event_type, actor_member_id FROM audit_event WHERE event_type = $1`,
      ["space.invite.issued"],
    );
    assert.equal(issuedSpace.rows.length, 1);
    assert.equal(issuedSpace.rows[0].actor_member_id, admin.memberId);

    // Revoking each invite records its typed revoked audit with the actor.
    assert.equal(
      await revokeCommunityAdmissionInvite(
        pool, admissionInvite, admin.memberId, "test", corr("revoke-admission"),
      ),
      true,
    );
    assert.equal(
      await revokeSpaceInvite(pool, spaceInvite, admin.memberId, "test", corr("revoke-space")),
      true,
    );
    const revoked = await pool.query(
      `SELECT event_type, actor_member_id, metadata FROM audit_event
       WHERE event_type IN ($1, $2) ORDER BY event_type`,
      ["community.admission.invite.revoked", "space.invite.revoked"],
    );
    assert.equal(revoked.rows.length, 2);
    for (const row of revoked.rows) {
      assert.equal(row.actor_member_id, admin.memberId);
      assert.equal(row.metadata.reason, "test");
    }

    // The central terminal transition persists a non-empty reason on the invite
    // row itself (not only in the audit metadata) for both invite types.
    const admissionRevokeRow = await pool.query(
      `SELECT state, accepted_at, revoked_at, revoked_reason
       FROM community_admission_invite WHERE id = $1`,
      [admissionInvite],
    );
    assert.equal(admissionRevokeRow.rows[0].state, "revoked");
    assert.equal(admissionRevokeRow.rows[0].accepted_at, null);
    assert.ok(admissionRevokeRow.rows[0].revoked_at, "revoked admission invite must carry revoked_at");
    assert.equal(admissionRevokeRow.rows[0].revoked_reason, "test");

    const spaceRevokeRow = await pool.query(
      `SELECT state, accepted_at, revoked_at, revoked_reason
       FROM space_invite WHERE id = $1`,
      [spaceInvite],
    );
    assert.equal(spaceRevokeRow.rows[0].state, "revoked");
    assert.equal(spaceRevokeRow.rows[0].accepted_at, null);
    assert.ok(spaceRevokeRow.rows[0].revoked_at, "revoked space invite must carry revoked_at");
    assert.equal(spaceRevokeRow.rows[0].revoked_reason, "test");

    // Revoking an already-terminal invite is a no-op: no transition, no audit.
    const revokeAuditBefore = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type IN ($1, $2)`,
      ["community.admission.invite.revoked", "space.invite.revoked"],
    )).rows[0].n;
    assert.equal(await revokeCommunityAdmissionInvite(
      pool, admissionInvite, admin.memberId, "again", corr("revoke-again"),
    ), false);
    assert.equal(await revokeSpaceInvite(pool, spaceInvite, admin.memberId, "again", corr("revoke-again")), false);
    const revokeAuditAfter = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type IN ($1, $2)`,
      ["community.admission.invite.revoked", "space.invite.revoked"],
    )).rows[0].n;
    assert.equal(revokeAuditAfter, revokeAuditBefore, "no audit for a no-op revoke");

    // A failed issue (revoked root target, rejected by the DB trigger) rolls
    // back the insert AND its audit: no issued event may survive.
    const revokedPerson = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["issuer-bad"])
    ).rows[0].id;
    const revokedRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [revokedPerson, "bad-root"],
      )
    ).rows[0].id;
    await pool.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [revokedRoot]);
    const issuedBefore = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["community.admission.invite.issued"],
    )).rows[0].n;
    await assert.rejects(
      issueCommunityAdmissionInvite(pool, {
        communityId,
        target: { kind: "human", targetCredentialId: revokedRoot },
        issuerMemberId: admin.memberId,
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        correlationId: corr("bad-issue"),
      }),
      (error: unknown) => error instanceof Error && /active human root credential/.test(error.message),
    );
    const issuedAfter = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["community.admission.invite.issued"],
    )).rows[0].n;
    assert.equal(issuedAfter, issuedBefore, "a rolled-back issue must write no issued audit");
  });
});

test("every createSpace writes a typed space.create audit with the acting creator", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, projectId } = await buildFixture(pool);
    const auditBefore = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.create"],
    )).rows[0].n;

    // A section (no root grant) must still be audited with the acting creator.
    const section = (
      await createSpace(pool, {
        communityId,
        createdByMemberId: admin.memberId,
        kind: "section",
        parentSpaceId: projectId,
        visibility: "public",
        description: "audited section",
      }, undefined, corr("audit-section"))
    ).id;
    const row = await pool.query(
      `SELECT actor_member_id, correlation_id, community_id,
              metadata->>'kind' AS kind, metadata->>'visibility' AS visibility
       FROM audit_event WHERE event_type = $1 AND target_id = $2`,
      ["space.create", section],
    );
    assert.equal(row.rows.length, 1);
    assert.equal(row.rows[0].actor_member_id, admin.memberId);
    assert.equal(row.rows[0].community_id, communityId);
    assert.equal(row.rows[0].kind, "section");
    assert.equal(row.rows[0].visibility, "public");
    assert.equal(
      (await pool.query(`SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`, ["space.create"])).rows[0].n,
      auditBefore + 1,
    );

    // A rolled-back space create (bad parent kind) writes no space.create audit.
    const auditAfterSection = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.create"],
    )).rows[0].n;
    await assert.rejects(
      createSpace(pool, {
        communityId,
        createdByMemberId: admin.memberId,
        kind: "channel",
        parentSpaceId: projectId,
        visibility: "public",
      }, undefined, corr("bad-channel")),
      (error: unknown) => error instanceof Error && /channel must parent only to a section/.test(error.message),
    );
    const auditAfterFailed = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.create"],
    )).rows[0].n;
    assert.equal(auditAfterFailed, auditAfterSection, "no space.create audit for a rolled-back create");
  });
});

test("accepting an already-issued space invite fails with no grant/audit when the target member is revoked after issue", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    const invite = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("revoked-target-invite"),
    });

    // Revoke the target member after the invite was issued.
    await pool.query(
      `UPDATE member SET revoked_at = now(), revoked_reason = 'test' WHERE id = $1`,
      [guest.memberId],
    );

    const grantBefore = (await pool.query(
      `SELECT count(*)::int AS n FROM space_membership`,
    )).rows[0].n;
    const grantAuditBefore = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1 OR event_type = $2`,
      ["space.access.grant", "space.invite.accepted"],
    )).rows[0].n;

    await assert.rejects(
      acceptSpaceInvite(pool, invite, corr("revoked-target-accept")),
      (error: unknown) => error instanceof Error && /requires an active member/.test(error.message),
    );

    const grantAfter = (await pool.query(
      `SELECT count(*)::int AS n FROM space_membership`,
    )).rows[0].n;
    assert.equal(grantAfter, grantBefore, "no grant may be created for a revoked member");
    const grantAuditAfter = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1 OR event_type = $2`,
      ["space.access.grant", "space.invite.accepted"],
    )).rows[0].n;
    assert.equal(grantAuditAfter, grantAuditBefore, "no grant/accepted audit for a rolled-back accept");
    const state = await pool.query(
      `SELECT state FROM space_invite WHERE id = $1`,
      [invite],
    );
    assert.equal(state.rows[0].state, "issued", "the invite must remain issued after a failed acceptance");
  });
});

test("expiry commands: past-due issued invites transition to expired exactly once with one system audit; active and terminal rows are no-ops", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // Admission invite that is past due at issue (issued but expires_at <= now).
    const admissionInvite = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: guest.rootCredentialId },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("expire-admission"),
    });
    // Acceptance refuses the past-due row even before it is explicitly expired.
    assert.equal(await acceptCommunityAdmissionInvite(pool, admissionInvite, corr("accept-expired-admission")), null);

    // Expiring transitions exactly one row and emits exactly one system audit.
    assert.equal(await expireCommunityAdmissionInvite(pool, admissionInvite, corr("expire-admission-cmd")), true);
    const admissionState = await pool.query(
      `SELECT state FROM community_admission_invite WHERE id = $1`, [admissionInvite],
    );
    assert.equal(admissionState.rows[0].state, "expired");
    const admissionExpired = await pool.query(
      `SELECT event_type, actor_member_id, correlation_id FROM audit_event WHERE event_type = $1`,
      ["community.admission.invite.expired"],
    );
    assert.equal(admissionExpired.rows.length, 1);
    assert.equal(admissionExpired.rows[0].actor_member_id, null, "expiry audit has no human/agent actor");
    assert.ok(
      String(admissionExpired.rows[0].correlation_id).startsWith("m1-2:expire-admission-cmd:"),
      "expiry audit must carry the system correlation id",
    );

    // Acceptance refuses the explicit expiry state too.
    assert.equal(await acceptCommunityAdmissionInvite(pool, admissionInvite, corr("accept-expired-again")), null);

    // Repeated expiry is a no-op: no state change and no second audit.
    assert.equal(await expireCommunityAdmissionInvite(pool, admissionInvite, corr("expire-admission-again")), false);
    assert.equal(
      (await pool.query(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
        ["community.admission.invite.expired"],
      )).rows[0].n,
      1,
    );

    // An active (not yet due) invite is a no-op: still issued, no expiry audit.
    const activeAdmission = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: guest.rootCredentialId },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("active-admission"),
    });
    assert.equal(await expireCommunityAdmissionInvite(pool, activeAdmission, corr("expire-active")), false);
    const activeAdmissionState = await pool.query(
      `SELECT state FROM community_admission_invite WHERE id = $1`, [activeAdmission],
    );
    assert.equal(activeAdmissionState.rows[0].state, "issued");
    assert.equal(
      (await pool.query(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
        ["community.admission.invite.expired"],
      )).rows[0].n,
      1,
      "an active admission invite must not emit an expiry audit",
    );

    // Space invite: same contract on its own table and audit type.
    const spaceInvite = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("expire-space"),
    });
    assert.equal(await acceptSpaceInvite(pool, spaceInvite, corr("accept-expired-space")), null);
    assert.equal(await expireSpaceInvite(pool, spaceInvite, corr("expire-space-cmd")), true);
    const spaceState = await pool.query(
      `SELECT state FROM space_invite WHERE id = $1`, [spaceInvite],
    );
    assert.equal(spaceState.rows[0].state, "expired");
    const spaceExpiredCount = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.invite.expired"],
    );
    const spaceExpiredWithActor = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1 AND actor_member_id IS NOT NULL`,
      ["space.invite.expired"],
    );
    assert.equal(spaceExpiredCount.rows[0].n, 1);
    assert.equal(spaceExpiredWithActor.rows[0].n, 0, "space expiry audit has no human/agent actor");
    assert.equal(await expireSpaceInvite(pool, spaceInvite, corr("expire-space-again")), false);
    assert.equal(
      (await pool.query(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
        ["space.invite.expired"],
      )).rows[0].n,
      1,
    );

    // An active (not yet due) space invite is also a no-op: still issued, no audit.
    const activeSpace = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("active-space"),
    });
    assert.equal(await expireSpaceInvite(pool, activeSpace, corr("expire-active-space")), false);
    const activeSpaceState = await pool.query(
      `SELECT state FROM space_invite WHERE id = $1`, [activeSpace],
    );
    assert.equal(activeSpaceState.rows[0].state, "issued", "an active space invite must remain issued");
    assert.equal(
      (await pool.query(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
        ["space.invite.expired"],
      )).rows[0].n,
      1,
      "an active space invite must not emit an expiry audit",
    );
  });
});

test("expiry racing acceptance: an accept that lands first is the sole terminal result with its own effects", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // Admission: accept-first ordering — the accepted state is the only terminal
    // result; the later expiry is a no-op and emits no expiry audit.
    const outsider = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["race-acc-outsider"])
    ).rows[0].id;
    const outsiderRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [outsider, "race-acc-root"],
      )
    ).rows[0].id;
    const accAdmission = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("race-acc-admission"),
    });
    const accepted = await acceptCommunityAdmissionInvite(pool, accAdmission, corr("race-acc-admission-accept"));
    assert.ok(accepted, "accept-first ordering: the accept must win");
    assert.equal(await expireCommunityAdmissionInvite(pool, accAdmission, corr("race-acc-admission-expire")), false);
    const admissionFinal = await pool.query(
      `SELECT state FROM community_admission_invite WHERE id = $1`, [accAdmission],
    );
    assert.equal(admissionFinal.rows[0].state, "accepted", "exactly one terminal state: accepted");
    const admitted = await pool.query(
      `SELECT count(*)::int AS n FROM member WHERE community_id = $1 AND person_id = $2`,
      [communityId, outsider],
    );
    assert.equal(admitted.rows[0].n, 1, "accepted ordering admits the member exactly once");
    const admissionAcceptAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event
       WHERE event_type = $1 AND metadata->>'inviteId' = $2`,
      ["member.admission", accAdmission],
    );
    assert.equal(admissionAcceptAudit.rows[0].n, 1, "only the admission audit accompanies the accept");
    const admissionExpireAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event
       WHERE event_type = $1 AND target_id = $2`,
      ["community.admission.invite.expired", accAdmission],
    );
    assert.equal(admissionExpireAudit.rows[0].n, 0, "no expiry audit may follow a winning accept");

    // Space: accept-first ordering — the acceptance grant is the only effect.
    const accSpace = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("race-acc-space"),
    });
    assert.ok(await acceptSpaceInvite(pool, accSpace, corr("race-acc-space-accept")));
    assert.equal(await expireSpaceInvite(pool, accSpace, corr("race-acc-space-expire")), false);
    const spaceFinal = await pool.query(
      `SELECT state FROM space_invite WHERE id = $1`, [accSpace],
    );
    assert.equal(spaceFinal.rows[0].state, "accepted", "exactly one terminal state: accepted");
    const granted = await pool.query(
      `SELECT count(*)::int AS n FROM space_membership
       WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL`,
      [projectId, guest.memberId],
    );
    assert.equal(granted.rows[0].n, 1, "accepted ordering grants access exactly once");
    const spaceAcceptAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1 AND target_id = $2`,
      ["space.invite.accepted", accSpace],
    );
    assert.equal(spaceAcceptAudit.rows[0].n, 1, "only the accepted audit accompanies the accept");
    const spaceExpireAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1 AND target_id = $2`,
      ["space.invite.expired", accSpace],
    );
    assert.equal(spaceExpireAudit.rows[0].n, 0, "no expiry audit may follow a winning accept");
  });
});

test("expiry racing acceptance: an expiry that lands first is the sole terminal result with no grant/acceptance effects", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // Admission: expire-first ordering — the expired state is the only terminal
    // result; the later accept is a no-op that admits nobody.
    const outsider = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["race-exp-outsider"])
    ).rows[0].id;
    const outsiderRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [outsider, "race-exp-root"],
      )
    ).rows[0].id;
    const expAdmission = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("race-exp-admission"),
    });
    assert.equal(await expireCommunityAdmissionInvite(pool, expAdmission, corr("race-exp-admission-expire")), true);
    assert.equal(await acceptCommunityAdmissionInvite(pool, expAdmission, corr("race-exp-admission-accept")), null);
    const admissionFinal = await pool.query(
      `SELECT state FROM community_admission_invite WHERE id = $1`, [expAdmission],
    );
    assert.equal(admissionFinal.rows[0].state, "expired", "exactly one terminal state: expired");
    const admitted = await pool.query(
      `SELECT count(*)::int AS n FROM member WHERE community_id = $1 AND person_id = $2`,
      [communityId, outsider],
    );
    assert.equal(admitted.rows[0].n, 0, "expired ordering must not admit a member");
    const admissionExpireAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event
       WHERE event_type = $1 AND target_id = $2`,
      ["community.admission.invite.expired", expAdmission],
    );
    assert.equal(admissionExpireAudit.rows[0].n, 1, "only the expiry audit accompanies the expire");
    const admissionAcceptAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event
       WHERE event_type = $1 AND metadata->>'inviteId' = $2`,
      ["member.admission", expAdmission],
    );
    assert.equal(admissionAcceptAudit.rows[0].n, 0, "no admission audit may follow a winning expire");

    // Space: expire-first ordering — no grant is created.
    const expSpace = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("race-exp-space"),
    });
    assert.equal(await expireSpaceInvite(pool, expSpace, corr("race-exp-space-expire")), true);
    assert.equal(await acceptSpaceInvite(pool, expSpace, corr("race-exp-space-accept")), null);
    const spaceFinal = await pool.query(
      `SELECT state FROM space_invite WHERE id = $1`, [expSpace],
    );
    assert.equal(spaceFinal.rows[0].state, "expired", "exactly one terminal state: expired");
    const granted = await pool.query(
      `SELECT count(*)::int AS n FROM space_membership
       WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL`,
      [projectId, guest.memberId],
    );
    assert.equal(granted.rows[0].n, 0, "expired ordering must not create a grant");
    const spaceExpireAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1 AND target_id = $2`,
      ["space.invite.expired", expSpace],
    );
    assert.equal(spaceExpireAudit.rows[0].n, 1, "only the expiry audit accompanies the expire");
    const spaceAcceptAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1 AND target_id = $2`,
      ["space.invite.accepted", expSpace],
    );
    assert.equal(spaceAcceptAudit.rows[0].n, 0, "no accepted audit may follow a winning expire");
  });
});

test("expiry racing acceptance: concurrent submit serializes on the row to exactly one terminal result and one effect set", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin } = await buildFixture(pool);

    const outsider = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["race-concurrent-outsider"])
    ).rows[0].id;
    const outsiderRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [outsider, "race-concurrent-root"],
      )
    ).rows[0].id;
    const raceInvite = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 5000).toISOString(),
      correlationId: corr("race-concurrent-invite"),
    });

    const [accepted, expired] = await Promise.all([
      acceptCommunityAdmissionInvite(pool, raceInvite, corr("race-concurrent-accept")),
      expireCommunityAdmissionInvite(pool, raceInvite, corr("race-concurrent-expire")),
    ]);

    const finalState = await pool.query(
      `SELECT state FROM community_admission_invite WHERE id = $1`, [raceInvite],
    );
    assert.ok(
      finalState.rows[0].state === "accepted" || finalState.rows[0].state === "expired",
      `concurrent race must end in exactly one terminal state, got ${finalState.rows[0].state}`,
    );
    assert.ok(
      (accepted !== null) !== (expired === true),
      "exactly one of accept/expire may take effect in a concurrent race",
    );
    const admitted = await pool.query(
      `SELECT count(*)::int AS n FROM member WHERE community_id = $1 AND person_id = $2`,
      [communityId, outsider],
    );
    const admissionAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event
       WHERE event_type = $1 AND metadata->>'inviteId' = $2`,
      ["member.admission", raceInvite],
    );
    const expiryAudit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event
       WHERE event_type = $1 AND target_id = $2`,
      ["community.admission.invite.expired", raceInvite],
    );
    if (finalState.rows[0].state === "accepted") {
      assert.equal(admitted.rows[0].n, 1, "winning accept admits exactly one member");
      assert.equal(admissionAudit.rows[0].n, 1, "winning accept writes exactly one admission audit");
      assert.equal(expiryAudit.rows[0].n, 0, "losing expire writes no expiry audit");
    } else {
      assert.equal(admitted.rows[0].n, 0, "winning expire admits nobody");
      assert.equal(admissionAudit.rows[0].n, 0, "losing accept writes no admission audit");
      assert.equal(expiryAudit.rows[0].n, 1, "winning expire writes exactly one expiry audit");
    }
  });
});

test("expiry atomicity: a failing expiry audit insert rolls the state transition back to issued", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    await pool.query(`
      CREATE OR REPLACE FUNCTION forbid_expiry_audit() RETURNS trigger AS $$
      BEGIN
        IF NEW.event_type IN ('community.admission.invite.expired', 'space.invite.expired') THEN
          RAISE EXCEPTION 'forced expiry audit failure';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `);
    await pool.query(`
      CREATE TRIGGER forbid_expiry_audit_trg
        BEFORE INSERT ON audit_event
        FOR EACH ROW EXECUTE FUNCTION forbid_expiry_audit()
    `);

    // Admission: the UPDATE rolls back, the invite stays issued, no audit persists.
    const admissionInvite = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: guest.rootCredentialId },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("rollback-admission"),
    });
    await assert.rejects(
      expireCommunityAdmissionInvite(pool, admissionInvite, corr("rollback-admission-expire")),
      (error: unknown) => error instanceof Error && /forced expiry audit failure/.test(error.message),
    );
    const admissionState = await pool.query(
      `SELECT state FROM community_admission_invite WHERE id = $1`, [admissionInvite],
    );
    assert.equal(admissionState.rows[0].state, "issued", "a failed audit must roll the admission expiry back");

    // Space: same atomicity on its own table.
    const spaceInvite = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("rollback-space"),
    });
    await assert.rejects(
      expireSpaceInvite(pool, spaceInvite, corr("rollback-space-expire")),
      (error: unknown) => error instanceof Error && /forced expiry audit failure/.test(error.message),
    );
    const spaceState = await pool.query(
      `SELECT state FROM space_invite WHERE id = $1`, [spaceInvite],
    );
    assert.equal(spaceState.rows[0].state, "issued", "a failed audit must roll the space expiry back");

    const persistedExpiredAudits = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type LIKE '%.invite.expired'`,
    );
    assert.equal(persistedExpiredAudits.rows[0].n, 0, "no expiry audit may persist after a rollback");
  });
});

test("retry: an expired invitation does not poison a fresh invitation for the same target", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // Admission: the first invitation expires; a fresh one for the same target
    // accepts and admits exactly once.
    const outsider = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["retry-outsider"])
    ).rows[0].id;
    const outsiderRoot = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind)
         VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
        [outsider, "retry-root"],
      )
    ).rows[0].id;
    const first = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("retry-first-admission"),
    });
    assert.equal(await expireCommunityAdmissionInvite(pool, first, corr("retry-first-expire")), true);
    const second = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: outsiderRoot },
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("retry-second-admission"),
    });
    assert.ok(await acceptCommunityAdmissionInvite(pool, second, corr("retry-second-accept")));
    const admitted = await pool.query(
      `SELECT count(*)::int AS n FROM member WHERE community_id = $1 AND person_id = $2`,
      [communityId, outsider],
    );
    assert.equal(admitted.rows[0].n, 1, "a fresh invitation after expiry admits the target exactly once");
    const firstState = await pool.query(`SELECT state FROM community_admission_invite WHERE id = $1`, [first]);
    assert.equal(firstState.rows[0].state, "expired", "the superseded invitation stays expired");
    const secondState = await pool.query(`SELECT state FROM community_admission_invite WHERE id = $1`, [second]);
    assert.equal(secondState.rows[0].state, "accepted", "the fresh invitation takes its own path");

    // Space: a fresh space invite after expiry grants access exactly once.
    const firstSpace = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      correlationId: corr("retry-first-space"),
    });
    assert.equal(await expireSpaceInvite(pool, firstSpace, corr("retry-first-space-expire")), true);
    const secondSpace = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      correlationId: corr("retry-second-space"),
    });
    assert.ok(await acceptSpaceInvite(pool, secondSpace, corr("retry-second-space-accept")));
    const granted = await pool.query(
      `SELECT count(*)::int AS n FROM space_membership
       WHERE space_id = $1 AND member_id = $2 AND revoked_at IS NULL`,
      [projectId, guest.memberId],
    );
    assert.equal(granted.rows[0].n, 1, "a fresh space invitation after expiry grants access exactly once");
  });
});

test("grant and revoke commands write their own typed audit in the same transaction", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);

    // GrantSpaceMembership emits space.access.grant itself.
    await grantSpaceMembership(pool, {
      spaceId: projectId,
      memberId: guest.memberId,
      grantedByMemberId: admin.memberId,
      source: "explicit",
    });
    const grants = await pool.query(
      `SELECT event_type, actor_member_id, community_id FROM audit_event
       WHERE event_type = $1 AND metadata->>'memberId' = $2 ORDER BY created_at`,
      ["space.access.grant", guest.memberId],
    );
    assert.equal(grants.rows.length, 1);
    assert.equal(grants.rows[0].actor_member_id, admin.memberId);
    assert.equal(grants.rows[0].community_id, communityId);

    // RevokeSpaceMembership emits space.access.revoke with the acting member.
    await revokeSpaceMembership(pool, projectId, guest.memberId, "test", admin.memberId);
    const revokes = await pool.query(
      `SELECT event_type, actor_member_id FROM audit_event
       WHERE event_type = $1 AND metadata->>'memberId' = $2 ORDER BY created_at`,
      ["space.access.revoke", guest.memberId],
    );
    assert.equal(revokes.rows.length, 1);
    assert.equal(revokes.rows[0].actor_member_id, admin.memberId);

    // audit is append-only
    const firstEvent = (
      await pool.query(`SELECT id FROM audit_event ORDER BY created_at LIMIT 1`)
    ).rows[0].id;
    await expectReject(pool, "DELETE FROM audit_event WHERE id = $1", [firstEvent], "append-only");
  });
});

test("createSpace with a root grant is atomic: a failing grant leaves no project behind", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin } = await buildFixture(pool);

    // A revoked member cannot receive a grant (space_membership trigger), so the
    // combined create+grant must roll back entirely and create no project.
    const revokedMember = await createMember(pool, {
      communityId,
      subject: {
        kind: "human",
        personId: (await pool.query(
          "INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["revoked"],
        )).rows[0].id,
      },
    });
    await pool.query(
      `UPDATE member SET revoked_at = now(), revoked_reason = 'test' WHERE id = $1`,
      [revokedMember.id],
    );

    const before = (await pool.query("SELECT count(*)::int AS n FROM space")).rows[0].n;
    const grantAuditBefore = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.access.grant"],
    )).rows[0].n;
    const spaceCreateAuditBefore = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.create"],
    )).rows[0].n;
    await assert.rejects(
      createSpace(pool, {
        communityId,
        createdByMemberId: admin.memberId,
        kind: "project",
        visibility: "private",
        ownerMemberId: admin.memberId,
      }, { memberId: revokedMember.id, grantedByMemberId: admin.memberId }, corr("atomic-project")),
      (error: unknown) =>
        error instanceof Error && /requires an active member/.test(error.message),
    );
    const after = (await pool.query("SELECT count(*)::int AS n FROM space")).rows[0].n;
    assert.equal(after, before, "a failed root grant must not leave a partial project");
    const grantAuditAfter = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.access.grant"],
    )).rows[0].n;
    assert.equal(grantAuditAfter, grantAuditBefore, "no grant audit may be written for a rolled-back grant");
    const spaceCreateAuditAfter = (await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = $1`,
      ["space.create"],
    )).rows[0].n;
    assert.equal(spaceCreateAuditAfter, spaceCreateAuditBefore, "no space.create audit may be written for a rolled-back project");
  });
});

test("invite state machine: malformed terminal timestamp/reason shapes are rejected at the DB boundary", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId } = await buildFixture(pool);
    const future = new Date(Date.now() + 3600_000).toISOString();

    // An issued row must not carry any terminal field on INSERT.
    await expectReject(
      pool,
      `INSERT INTO community_admission_invite
         (community_id, target_kind, target_credential_id, issuer_member_id, expires_at, state, accepted_at)
       VALUES ($1, 'human', $2, $3, $4, 'issued', now())`,
      [communityId, guest.rootCredentialId, admin.memberId, future],
      "issued invite must not carry terminal fields",
    );
    await expectReject(
      pool,
      `INSERT INTO space_invite
         (community_id, target_member_id, space_id, issuer_member_id, expires_at, state, revoked_reason)
       VALUES ($1, $2, $3, $4, $5, 'issued', 'x')`,
      [communityId, guest.memberId, projectId, admin.memberId, future],
      "issued invite must not carry terminal fields",
    );

    // An invite may only be created in the issued state.
    await expectReject(
      pool,
      `INSERT INTO community_admission_invite
         (community_id, target_kind, target_credential_id, issuer_member_id, expires_at, state)
       VALUES ($1, 'human', $2, $3, $4, 'revoked')`,
      [communityId, guest.rootCredentialId, admin.memberId, future],
      "invite must be created in the issued state",
    );

    // Valid issued rows for the direct-UPDATE shape negatives below.
    const admission = await issueCommunityAdmissionInvite(pool, {
      communityId,
      target: { kind: "human", targetCredentialId: guest.rootCredentialId },
      issuerMemberId: admin.memberId,
      expiresAt: future,
      correlationId: corr("shape-admission"),
    });
    const space = await issueSpaceInvite(pool, {
      communityId,
      targetMemberId: guest.memberId,
      spaceId: projectId,
      issuerMemberId: admin.memberId,
      expiresAt: future,
      correlationId: corr("shape-space"),
    });

    // accepted must not carry revocation fields.
    await expectReject(
      pool,
      `UPDATE community_admission_invite SET state = 'accepted', accepted_at = now(), revoked_reason = 'x' WHERE id = $1`,
      [admission],
      "accepted invite must not carry revocation fields",
    );

    // revoked requires a non-empty reason (null and whitespace both rejected).
    await expectReject(
      pool,
      `UPDATE community_admission_invite SET state = 'revoked', revoked_reason = NULL WHERE id = $1`,
      [admission],
      "revoked invite must carry a non-empty revoke reason",
    );
    await expectReject(
      pool,
      `UPDATE space_invite SET state = 'revoked', revoked_reason = '   ' WHERE id = $1`,
      [space],
      "revoked invite must carry a non-empty revoke reason",
    );

    // revoked must not carry an acceptance timestamp.
    await expectReject(
      pool,
      `UPDATE community_admission_invite SET state = 'revoked', accepted_at = now(), revoked_reason = 'x' WHERE id = $1`,
      [admission],
      "revoked invite must not carry an acceptance timestamp",
    );

    // expired must not carry any terminal field.
    await expectReject(
      pool,
      `UPDATE space_invite SET state = 'expired', revoked_at = now() WHERE id = $1`,
      [space],
      "expired invite must not carry terminal fields",
    );
    await expectReject(
      pool,
      `UPDATE community_admission_invite SET state = 'expired', revoked_reason = 'x' WHERE id = $1`,
      [admission],
      "expired invite must not carry terminal fields",
    );

    // The rows remain issued after every rejected shape.
    const admissionFinal = await pool.query(
      `SELECT state FROM community_admission_invite WHERE id = $1`, [admission],
    );
    assert.equal(admissionFinal.rows[0].state, "issued");
    const spaceFinal = await pool.query(
      `SELECT state, accepted_at, revoked_at, revoked_reason FROM space_invite WHERE id = $1`, [space],
    );
    assert.equal(spaceFinal.rows[0].state, "issued");
    assert.equal(spaceFinal.rows[0].accepted_at, null);
    assert.equal(spaceFinal.rows[0].revoked_at, null);
    assert.equal(spaceFinal.rows[0].revoked_reason, null);
  });
});
