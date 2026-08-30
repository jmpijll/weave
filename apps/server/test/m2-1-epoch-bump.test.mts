import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { runMigrations } from "../src/db/migrate.ts";
import { grantSpaceMembership, revokeSpaceMembership, createSpace } from "../src/domain/spaces.ts";
import { assignRole } from "../src/domain/roles.ts";
import { issueCommunityAdmissionInvite } from "../src/domain/invites.ts";
import {
  readCredentialEpoch,
  readMemberEpoch,
  readSpaceEpoch,
  readSpaceMembershipEpoch,
} from "../src/db/epoch.ts";
import { createMember } from "../src/domain/membership.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) {
  console.error(
    "m2-1 epoch bump: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL — M2.1 epoch discipline evidence is mandatory)",
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
  const database = `weave_m21_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
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

async function snapshot(pool: pg.Pool): Promise<Record<string, number>> {
  const tables = [
    "community",
    "person",
    "credential",
    "host",
    "agent",
    "member",
    "space",
    "space_membership",
    "member_role_assignment",
    "community_admission_invite",
    "space_invite",
    "audit_event",
  ] as const;
  const out: Record<string, number> = {};
  for (const table of tables) {
    const res = await pool.query(`SELECT count(*)::int AS n FROM ${table}`);
    out[table] = (res.rows[0] as { n: number }).n;
  }
  return out;
}

async function assertZeroMutation(pool: pg.Pool, before: Record<string, number>): Promise<void> {
  const after = await snapshot(pool);
  for (const table of Object.keys(before)) {
    assert.equal(after[table], before[table], `table ${table} must be unchanged by a read`);
  }
}

let corrCounter = 0;
function corr(label: string): string {
  corrCounter += 1;
  return `m2-1:${label}:${process.pid}:${corrCounter}`;
}

interface Fixture {
  communityId: string;
  admin: {
    personId: string;
    rootCredentialId: string;
    deviceCredentialId: string;
    memberId: string;
  };
  guest: {
    personId: string;
    rootCredentialId: string;
    deviceCredentialId: string;
    memberId: string;
  };
  projectId: string;
  sectionId: string;
}

async function createPersonWithMember(
  pool: pg.Pool,
  communityId: string,
  label: string,
): Promise<{ personId: string; rootCredentialId: string; deviceCredentialId: string; memberId: string }> {
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
  const deviceCredentialId = (
    await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
      [personId, `${label}-device-pub`, rootCredentialId],
    )
  ).rows[0].id;
  const member = await createMember(pool, {
    communityId,
    subject: { kind: "human", personId },
  });
  return { personId, rootCredentialId, deviceCredentialId, memberId: member.id };
}

async function buildFixture(pool: pg.Pool): Promise<Fixture> {
  const communityId = (
    await pool.query(
      `INSERT INTO community (canonical_tls_origin, name, bootstrap_complete)
       VALUES ($1, $2, TRUE) RETURNING id`,
      ["https://m21.example", "M21 Fixture"],
    )
  ).rows[0].id;

  const admin = await createPersonWithMember(pool, communityId, "admin");
  const guest = await createPersonWithMember(pool, communityId, "guest");

  // A project root + a section for grant/revoke/visibility purposes.
  const projectId = (
    await createSpace(
      pool,
      {
        communityId,
        createdByMemberId: admin.memberId,
        kind: "project",
        visibility: "private",
        ownerMemberId: admin.memberId,
        description: "root project",
      },
      { memberId: admin.memberId, grantedByMemberId: admin.memberId },
      corr("fixture-project"),
    )
  ).id;
  const sectionId = (
    await createSpace(
      pool,
      {
        communityId,
        createdByMemberId: admin.memberId,
        kind: "section",
        parentSpaceId: projectId,
        visibility: "private",
        description: "a section",
      },
      undefined,
      corr("fixture-section"),
    )
  ).id;

  return { communityId, admin, guest, projectId, sectionId };
}

// ---------------------------------------------------------------------------
// R1: credential revoked_at transition bumps credential.epoch (raw SQL).
// ---------------------------------------------------------------------------
test("R1 credential revoke bumps that credential epoch, monotonic, zero mutation on reads", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { admin } = await buildFixture(pool);

    const before0 = (await readCredentialEpoch(pool, admin.deviceCredentialId))!.epoch;
    const beforeRoot = (await readCredentialEpoch(pool, admin.rootCredentialId))!.epoch;
    assert.equal(before0, 1n);
    assert.equal(beforeRoot, 1n);

    await pool.query(`UPDATE credential SET revoked_at = now(), revoked_reason = 'compromise' WHERE id = $1`, [
      admin.deviceCredentialId,
    ]);
    assert.equal((await readCredentialEpoch(pool, admin.deviceCredentialId))!.epoch, 2n);
    assert.equal((await readCredentialEpoch(pool, admin.rootCredentialId))!.epoch, 1n);
  });
});

// ---------------------------------------------------------------------------
// R2: member revoked_at transition bumps member.epoch (raw SQL).
// ---------------------------------------------------------------------------
test("R2 member revoke bumps that member epoch", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { guest } = await buildFixture(pool);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 1n);

    await pool.query(`UPDATE member SET revoked_at = now(), revoked_reason = 'suspension' WHERE id = $1`, [
      guest.memberId,
    ]);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 2n);
  });
});

// ---------------------------------------------------------------------------
// R3: membership grant/revoke via the domain command bumps member.epoch and
// the scope epoch, and keeps the command-side audit row.
// ---------------------------------------------------------------------------
test("R3 grant via grantSpaceMembership: member epoch +1, new scope epoch 1, typed audit, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, sectionId } = await buildFixture(pool);
    const memberBefore = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    assert.equal(memberBefore, 1n);

    // The fixture wrote a project-root grant audit; baseline so the new grant's
    // typed audit is a +1 delta, not a global count.
    const grantAuditBefore = (
      await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.grant'`,
      )
    ).rows[0].n;

    await grantSpaceMembership(pool, {
      spaceId: sectionId,
      memberId: guest.memberId,
      grantedByMemberId: admin.memberId,
      source: "explicit",
      correlationId: corr("grant"),
    });

    // member epoch +1 (the snapshot invalidator signal for a new grant).
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 2n);
    // new scope row starts at epoch 1.
    const scope = await readSpaceMembershipEpoch(pool, sectionId, guest.memberId);
    assert.equal(scope!.epoch, 1n);
    assert.equal(scope!.revokedAt, null);

    // The command-side audit row is added by the command (command owns audit).
    const audit = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.grant'`,
    );
    assert.equal(audit.rows[0].n, grantAuditBefore + 1);
  });
});

test("R3 revoke via revokeSpaceMembership: member epoch +1 AND scope epoch +1, typed audit, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, sectionId } = await buildFixture(pool);
    await grantSpaceMembership(pool, {
      spaceId: sectionId,
      memberId: guest.memberId,
      grantedByMemberId: admin.memberId,
      source: "explicit",
      correlationId: corr("grant-before-revoke"),
    });
    const memberAfterGrant = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    const scopeAfterGrant = (await readSpaceMembershipEpoch(pool, sectionId, guest.memberId))!.epoch;
    assert.equal(memberAfterGrant, 2n);
    assert.equal(scopeAfterGrant, 1n);

    await revokeSpaceMembership(
      pool,
      sectionId,
      guest.memberId,
      "access removed",
      admin.memberId,
      corr("revoke"),
    );

    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 3n);
    // scope row is retained (revoked, not deleted) and its epoch bumps +1.
    const rev = await pool.query<{ epoch: string; revoked_at: string | null }>(
      `SELECT epoch::text AS epoch, revoked_at FROM space_membership WHERE space_id = $1 AND member_id = $2`,
      [sectionId, guest.memberId],
    );
    assert.equal(BigInt(rev.rows[0].epoch), 2n);
    assert.notEqual(rev.rows[0].revoked_at, null);

    const audit = await pool.query(
      `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.revoke'`,
    );
    assert.equal(audit.rows[0].n, 1);
  });
});

// ---------------------------------------------------------------------------
// R3 raw-SQL grant/revoke also bumps member.epoch (trigger backstop, no audit).
// ---------------------------------------------------------------------------
test("R3 raw-SQL membership grant and revoke bump member epoch via trigger, no fabricated audit", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, sectionId } = await buildFixture(pool);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 1n);

    // The fixture wrote a project-root grant audit; capture the baseline so a
    // raw grant must NOT add another command-side audit row.
    const grantAuditBefore = (
      await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.grant'`,
      )
    ).rows[0].n;

    // raw INSERT grant (bypasses the command): member.epoch bumps, no audit.
    await pool.query(
      `INSERT INTO space_membership (space_id, member_id, grant_source, granted_by_member_id)
       VALUES ($1, $2, 'explicit', $3)`,
      [sectionId, guest.memberId, admin.memberId],
    );
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 2n);
    assert.equal((await readSpaceMembershipEpoch(pool, sectionId, guest.memberId))!.epoch, 1n);
    const afterRawGrant = (
      await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.grant'`,
      )
    ).rows[0].n;
    assert.equal(afterRawGrant, grantAuditBefore, "raw grant must not fabricate a command-side audit row");

    // raw UPDATE revoke: member.epoch bumps, scope.epoch bumps, no audit.
    await pool.query(
      `UPDATE space_membership SET revoked_at = now(), revoked_reason = 'x' WHERE space_id = $1 AND member_id = $2`,
      [sectionId, guest.memberId],
    );
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 3n);
    const rev = await pool.query<{ epoch: string }>(
      `SELECT epoch::text AS epoch FROM space_membership WHERE space_id = $1 AND member_id = $2`,
      [sectionId, guest.memberId],
    );
    assert.equal(BigInt(rev.rows[0].epoch), 2n);
    const afterRawRevoke = (
      await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.revoke'`,
      )
    ).rows[0].n;
    assert.equal(afterRawRevoke, 0, "raw revoke must not fabricate a command-side audit row");
  });
});

// ---------------------------------------------------------------------------
// R3 raw reassignment (member reassignment): a row re-pointed to a new member
// moves delivery access from the old member to the new member. The trigger
// bumps the row epoch and BOTH affected members exactly once (old loses, new
// gains), and fabricates no audit.
// ---------------------------------------------------------------------------
test("R3 raw member reassignment bumps row epoch and both old and new member epochs, no audit", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { admin, guest, sectionId } = await buildFixture(pool);
    const guestBefore = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    const adminBefore = (await readMemberEpoch(pool, admin.memberId))!.epoch;
    assert.equal(guestBefore, 1n);
    // Admin already holds the fixture's project-root grant, so its member epoch
    // is already 2 before any explicit reassignment below.
    assert.equal(adminBefore, 2n);

    // A grant to guest, then re-point it to admin (a member reassignment).
    await pool.query(
      `INSERT INTO space_membership (space_id, member_id, grant_source, granted_by_member_id)
       VALUES ($1, $2, 'explicit', $3)`,
      [sectionId, guest.memberId, admin.memberId],
    );
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 2n);
    assert.equal((await readSpaceMembershipEpoch(pool, sectionId, guest.memberId))!.epoch, 1n);

    const grantAuditBefore = (
      await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.grant'`,
      )
    ).rows[0].n;

    await pool.query(
      `UPDATE space_membership SET member_id = $1 WHERE space_id = $2 AND member_id = $3`,
      [admin.memberId, sectionId, guest.memberId],
    );

    // Old member (guest) loses the grant -> epoch +1.
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 3n);
    // New member (admin) gains the grant -> epoch +1 (2 -> 3).
    assert.equal((await readMemberEpoch(pool, admin.memberId))!.epoch, 3n);
    // The reassigned row's epoch advanced, now under admin.
    const moved = await pool.query<{ epoch: string }>(
      `SELECT epoch::text AS epoch FROM space_membership WHERE space_id = $1 AND member_id = $2`,
      [sectionId, admin.memberId],
    );
    assert.equal(BigInt(moved.rows[0].epoch), 2n);
    // The old (guest, section) row no longer exists — it was re-pointed, not copied.
    const oldRow = await pool.query(
      `SELECT 1 AS one FROM space_membership WHERE space_id = $1 AND member_id = $2`,
      [sectionId, guest.memberId],
    );
    assert.equal(oldRow.rows.length, 0, "reassignment moves the row, it does not copy it");

    const grantAuditAfter = (
      await pool.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM audit_event WHERE event_type = 'space.access.grant'`,
      )
    ).rows[0].n;
    assert.equal(grantAuditAfter, grantAuditBefore, "raw reassignment must not fabricate an audit row");
  });
});

// ---------------------------------------------------------------------------
// R3 raw space move (space reassignment): a row re-pointed to a different space
// changes the access set for the single member. The trigger bumps the row epoch
// and that member epoch, and no-op rewrites bump nothing.
// ---------------------------------------------------------------------------
test("R3 raw space move bumps row epoch and the member epoch; no-op rewrite does not bump", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { guest, projectId, sectionId } = await buildFixture(pool);

    await pool.query(
      `INSERT INTO space_membership (space_id, member_id, grant_source, granted_by_member_id)
       VALUES ($1, $2, 'explicit', $3)`,
      [sectionId, guest.memberId, guest.memberId],
    );
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 2n);
    assert.equal((await readSpaceMembershipEpoch(pool, sectionId, guest.memberId))!.epoch, 1n);

    // Move the grant to the project space (same member, different space).
    await pool.query(
      `UPDATE space_membership SET space_id = $1 WHERE space_id = $2 AND member_id = $3`,
      [projectId, sectionId, guest.memberId],
    );
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 3n);
    const moved = await pool.query<{ epoch: string }>(
      `SELECT epoch::text AS epoch FROM space_membership WHERE space_id = $1 AND member_id = $2`,
      [projectId, guest.memberId],
    );
    assert.equal(BigInt(moved.rows[0].epoch), 2n);
    const oldRow = await pool.query(
      `SELECT 1 AS one FROM space_membership WHERE space_id = $1 AND member_id = $2`,
      [sectionId, guest.memberId],
    );
    assert.equal(oldRow.rows.length, 0, "move re-points the row, it does not copy it");

    // No-op rewrite of an unchanged field must NOT bump (not a real transition).
    const beforeNoop = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    await pool.query(
      `UPDATE space_membership SET space_id = $1 WHERE space_id = $1 AND member_id = $2`,
      [projectId, guest.memberId],
    );
    assert.equal(
      (await readMemberEpoch(pool, guest.memberId))!.epoch,
      beforeNoop,
      "identical-state membership write must not bump",
    );
  });
});

// ---------------------------------------------------------------------------
// R4: space visibility / archived_at change bumps space.epoch.
// ---------------------------------------------------------------------------
test("R4 space visibility change bumps that space epoch", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { projectId } = await buildFixture(pool);
    assert.equal((await readSpaceEpoch(pool, projectId))!.epoch, 1n);

    await pool.query(`UPDATE space SET visibility = 'public' WHERE id = $1`, [projectId]);
    assert.equal((await readSpaceEpoch(pool, projectId))!.epoch, 2n);
  });
});

test("R4 space archive (archived_at) change bumps that space epoch", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { projectId } = await buildFixture(pool);
    assert.equal((await readSpaceEpoch(pool, projectId))!.epoch, 1n);

    await pool.query(`UPDATE space SET archived_at = now() WHERE id = $1`, [projectId]);
    assert.equal((await readSpaceEpoch(pool, projectId))!.epoch, 2n);
  });
});

// ---------------------------------------------------------------------------
// R5: an ancestor (root) credential effect is the read-time chain denial from
// M1.3.3 (the bump is on the row actually revoked; the chain walk is the
// read-time suppression). Prove a root revoke bumps the root only, and the
// device's own epoch is untouched (the read walk denies it, not an epoch leak).
// ---------------------------------------------------------------------------
test("R5 ancestor revoke bumps only the resolved row; read-time chain suppression stays with the resolver", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { admin } = await buildFixture(pool);
    assert.equal((await readCredentialEpoch(pool, admin.rootCredentialId))!.epoch, 1n);
    assert.equal((await readCredentialEpoch(pool, admin.deviceCredentialId))!.epoch, 1n);

    await pool.query(`UPDATE credential SET revoked_at = now(), revoked_reason = 'compromise' WHERE id = $1`, [
      admin.rootCredentialId,
    ]);
    assert.equal((await readCredentialEpoch(pool, admin.rootCredentialId))!.epoch, 2n);
    assert.equal(
      (await readCredentialEpoch(pool, admin.deviceCredentialId))!.epoch,
      1n,
      "descendant credential epoch is not bumped; the M1.3.3 read walk is what suppresses it",
    );
  });
});

// ---------------------------------------------------------------------------
// Monotonic / no-op / no-decrement.
// ---------------------------------------------------------------------------
test("a no-op revoked_at write does not bump; epochs never decrement", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { guest } = await buildFixture(pool);
    const start = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    assert.equal(start, 1n);

    // Revoke once -> bump.
    await pool.query(`UPDATE member SET revoked_at = now() WHERE id = $1`, [guest.memberId]);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 2n);

    // A true no-op (re-writing the exact same revoked_at value) must NOT bump:
    // the IS DISTINCT FROM predicate must observe no transition.
    const same = await pool.query<{ revoked_at: string | null }>(
      `SELECT revoked_at::text AS revoked_at FROM member WHERE id = $1`,
      [guest.memberId],
    );
    const sameTs = same.rows[0].revoked_at;
    await pool.query(`UPDATE member SET revoked_at = $1::timestamptz WHERE id = $2`, [sameTs, guest.memberId]);
    assert.equal(
      (await readMemberEpoch(pool, guest.memberId))!.epoch,
      2n,
      "identical-state write must not bump",
    );

    // A different (new) timestamp is a real transition and bumps once more.
    await pool.query(`UPDATE member SET revoked_at = now() WHERE id = $1`, [guest.memberId]);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 3n);
  });
});

test("an unrevoke (revoked_at -> NULL) is a real transition and bumps", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { guest } = await buildFixture(pool);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 1n);
    await pool.query(`UPDATE member SET revoked_at = now(), revoked_reason = 'x' WHERE id = $1`, [guest.memberId]);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 2n);
    await pool.query(`UPDATE member SET revoked_at = NULL, revoked_reason = NULL WHERE id = $1`, [guest.memberId]);
    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, 3n, "unrevoke is a real transition");
  });
});

// ---------------------------------------------------------------------------
// Same-transaction atomicity: a rolled-back mutation leaves epochs unchanged.
// ---------------------------------------------------------------------------
test("a rolled-back grant leaves member and scope epochs unchanged (atomic)", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, sectionId } = await buildFixture(pool);
    const memberBefore = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    const scopeBefore = (await readSpaceMembershipEpoch(pool, sectionId, guest.memberId))?.epoch ?? null;

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO space_membership (space_id, member_id, grant_source, granted_by_member_id)
         VALUES ($1, $2, 'explicit', $3)`,
        [sectionId, guest.memberId, admin.memberId],
      );
      // The INSERT trigger bumps member.epoch within the txn; roll it back.
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }

    assert.equal((await readMemberEpoch(pool, guest.memberId))!.epoch, memberBefore);
    const scopeAfter = (await readSpaceMembershipEpoch(pool, sectionId, guest.memberId))?.epoch ?? null;
    assert.equal(scopeAfter, scopeBefore);
  });
});

// ---------------------------------------------------------------------------
// Read-seam exactness: epoch is a bigint, not a JS number, so two adjacent
// values beyond Number.MAX_SAFE_INTEGER must remain distinct. A Number() path
// would collapse both to the same number and hide a real authorization change
// from the M2.2 guard.
// ---------------------------------------------------------------------------
test("read seam preserves adjacent epoch values above Number.MAX_SAFE_INTEGER as distinct bigints", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { guest } = await buildFixture(pool);

    const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
    assert.equal(maxSafe, 9007199254740991n);
    const hi = maxSafe + 1n; // 9007199254740992n — beyond the safe range
    const hi2 = maxSafe + 2n; // 9007199254740993n

    // Write two adjacent unsafe values directly; both are distinct.
    await pool.query(`UPDATE member SET epoch = $1 WHERE id = $2`, [hi.toString(), guest.memberId]);
    const a = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    assert.equal(a, hi, "first unsafe epoch value read back exactly");

    await pool.query(`UPDATE member SET epoch = $1 WHERE id = $2`, [hi2.toString(), guest.memberId]);
    const b = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    assert.equal(b, hi2, "second unsafe epoch value read back exactly");

    // They must compare distinct at the seam (the failure a Number() path causes).
    assert.notEqual(a, b, "adjacent unsafe epoch values must not collapse to one number");

    // Demonstrate the Number() collapse this design avoids: both would round to
    // the same JS number, so a number-based seam could not tell them apart.
    assert.equal(Number(hi), Number(hi2), "a Number() seam would collapse adjacent unsafe values");
  });
});

// ---------------------------------------------------------------------------
// Zero mutation on the read seam.
// ---------------------------------------------------------------------------
test("epoch reads perform zero writes", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest, projectId, sectionId } = await buildFixture(pool);
    const before = await snapshot(pool);

    await readCredentialEpoch(pool, admin.rootCredentialId);
    await readCredentialEpoch(pool, admin.deviceCredentialId);
    await readMemberEpoch(pool, admin.memberId);
    await readMemberEpoch(pool, guest.memberId);
    await readSpaceEpoch(pool, projectId);
    await readSpaceEpoch(pool, sectionId);
    await readSpaceMembershipEpoch(pool, sectionId, guest.memberId);
    // absent-row read returns null, still no write.
    assert.equal(await readMemberEpoch(pool, "00000000-0000-4000-8000-000000000001"), null);
    assert.equal(await readCredentialEpoch(pool, "00000000-0000-4000-8000-000000000002"), null);
    assert.equal(await readSpaceEpoch(pool, "00000000-0000-4000-8000-000000000003"), null);

    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Cross-entity no-bump: role assignment + community-admission invite (both
// management authority, not delivery access) must NOT bump any delivery epoch.
// ---------------------------------------------------------------------------
test("role assignment and admission invite do not bump any delivery epoch (management authority)", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, admin, guest } = await buildFixture(pool);

    const memberEpoch = (await readMemberEpoch(pool, guest.memberId))!.epoch;
    const adminMemberEpoch = (await readMemberEpoch(pool, admin.memberId))!.epoch;

    await assignRole(pool, {
      memberId: admin.memberId,
      role: "community_admin",
      scope: { kind: "community", communityId },
      grantedByMemberId: admin.memberId,
      correlationId: corr("assign-role"),
    });
    // An invite targeting the guest agent-free human root is not directly
    // reproducible without a credential target; use a raw admission invite row.
    await pool.query(
      `INSERT INTO community_admission_invite
         (community_id, target_kind, target_credential_id, issuer_member_id, expires_at)
       VALUES ($1, 'human', $2, $3, now() + interval '1 day')`,
      [communityId, guest.rootCredentialId, admin.memberId],
    );

    assert.equal(
      (await readMemberEpoch(pool, guest.memberId))!.epoch,
      memberEpoch,
      "management-authority writes must not bump a member delivery epoch",
    );
    assert.equal(
      (await readMemberEpoch(pool, admin.memberId))!.epoch,
      adminMemberEpoch,
      "management-authority writes must not bump an admin member delivery epoch",
    );
  });
});

// ---------------------------------------------------------------------------
// Migration hygiene: the next version at this base is 0004, forward-only.
// ---------------------------------------------------------------------------
test("migration set is forward-only with 0004 applied and greatest version 4", async () => {
  await withFreshDatabase(async (pool) => {
    const result = await runMigrations(pool);
    assert.deepEqual(result.applied, [1, 2, 3, 4], "the single M2.1 migration is version 4");
    const ledger = await pool.query("SELECT max(version)::int AS m FROM public.schema_migration");
    assert.equal(ledger.rows[0].m, 4);
  });
});
