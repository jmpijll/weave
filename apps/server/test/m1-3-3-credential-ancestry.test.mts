import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes, randomUUID } from "node:crypto";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { runMigrations } from "../src/db/migrate.ts";
import { resolveCredentialToActiveMember } from "../src/auth/credential-ancestry.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) {
  console.error(
    "m1-3-3 credential ancestry: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL — M1.3.3 read-time authorization evidence is mandatory)",
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
  const database = `weave_m133_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
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

interface FixturePerson {
  personId: string;
  rootCredentialId: string;
  deviceCredentialId: string;
  hostCredentialId: string;
  hostId: string;
  agentCredentialId: string;
  agentId: string;
  humanMemberId: string;
  agentMemberId: string;
}

interface Fixture {
  communityId: string;
  owner: FixturePerson;
}

async function insertCredential(
  pool: pg.Pool,
  personId: string,
  publicKey: string,
  kind: string,
  parent: string | null = null,
): Promise<string> {
  const res = await pool.query(
    `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
     VALUES ($1, $2, 'ed25519', $3, $4) RETURNING id`,
    [personId, publicKey, kind, parent],
  );
  return res.rows[0].id;
}

async function createValidPerson(
  pool: pg.Pool,
  communityId: string,
  label: string,
): Promise<FixturePerson> {
  const personId = (
    await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", [label])
  ).rows[0].id;

  const rootCredentialId = await insertCredential(pool, personId, `${label}-root-pub`, "human");
  const deviceCredentialId = await insertCredential(
    pool,
    personId,
    `${label}-device-pub`,
    "human",
    rootCredentialId,
  );

  const hostCredentialId = await insertCredential(
    pool,
    personId,
    `${label}-host-pub`,
    "host",
    rootCredentialId,
  );
  const hostId = (
    await pool.query(`INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2) RETURNING id`, [
      personId,
      hostCredentialId,
    ])
  ).rows[0].id;
  const agentCredentialId = await insertCredential(
    pool,
    personId,
    `${label}-agent-pub`,
    "agent",
    hostCredentialId,
  );
  const agentId = (
    await pool.query(`INSERT INTO agent (host_id, credential_id) VALUES ($1, $2) RETURNING id`, [
      hostId,
      agentCredentialId,
    ])
  ).rows[0].id;

  const humanMemberId = (
    await pool.query(
      `INSERT INTO member (community_id, subject_kind, person_id, agent_id)
       VALUES ($1, 'human', $2, NULL) RETURNING id`,
      [communityId, personId],
    )
  ).rows[0].id;
  const agentMemberId = (
    await pool.query(
      `INSERT INTO member (community_id, subject_kind, person_id, agent_id)
       VALUES ($1, 'agent', NULL, $2) RETURNING id`,
      [communityId, agentId],
    )
  ).rows[0].id;

  return {
    personId,
    rootCredentialId,
    deviceCredentialId,
    hostCredentialId,
    hostId,
    agentCredentialId,
    agentId,
    humanMemberId,
    agentMemberId,
  };
}

async function buildFixture(pool: pg.Pool): Promise<Fixture> {
  const communityId = (
    await pool.query(
      `INSERT INTO community (canonical_tls_origin, name, bootstrap_complete)
       VALUES ($1, $2, TRUE) RETURNING id`,
      ["https://m133.example", "M133 Fixture"],
    )
  ).rows[0].id;
  const owner = await createValidPerson(pool, communityId, "owner");
  return { communityId, owner };
}

async function snapshot(pool: pg.Pool): Promise<Record<string, number>> {
  const tables = [
    "community",
    "person",
    "credential",
    "host",
    "agent",
    "member",
    "recovery_verifier",
    "recovery_challenge",
    "audit_event",
    "space",
    "space_membership",
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
    assert.equal(after[table], before[table], `table ${table} must be unchanged by a resolution attempt`);
  }
}

async function expectResolve(
  pool: pg.Pool,
  credentialId: string,
  communityId: string,
  expectedMemberId: string,
): Promise<void> {
  const result = await resolveCredentialToActiveMember(pool, { credentialId, communityId });
  assert.equal(result?.memberId, expectedMemberId, `expected resolve to member ${expectedMemberId}`);
}

async function expectDeny(
  pool: pg.Pool,
  credentialId: string,
  communityId: string,
): Promise<void> {
  const result = await resolveCredentialToActiveMember(pool, { credentialId, communityId });
  assert.equal(result, null, `expected an opaque denial for credential ${credentialId}`);
}

/** Disable the credential tree-shape write triggers so a malformed row can be
 * fabricated directly (reads must not trust the write-side trigger). */
async function disableCredentialTriggers(pool: pg.Pool): Promise<void> {
  await pool.query(`ALTER TABLE credential DISABLE TRIGGER credential_tree_shape`);
  await pool.query(`ALTER TABLE credential DISABLE TRIGGER credential_dependents`);
}

// ---------------------------------------------------------------------------
// Valid resolution: human device and agent credential.
// ---------------------------------------------------------------------------
test("valid human device resolves to the active human member, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    await expectResolve(pool, owner.deviceCredentialId, communityId, owner.humanMemberId);
    await assertZeroMutation(pool, before);
  });
});

test("valid agent credential resolves to the active agent member, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    await expectResolve(pool, owner.agentCredentialId, communityId, owner.agentMemberId);
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Fresh denial after direct root / host / target revocation (no cache).
// ---------------------------------------------------------------------------
test("revoking the root denies a live human device on the next fresh read, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    // First read succeeds...
    await expectResolve(pool, owner.deviceCredentialId, communityId, owner.humanMemberId);

    // ...then revoke the root and prove the NEXT fresh read denies (S7 core).
    await pool.query(`UPDATE credential SET revoked_at = now(), revoked_reason = 'compromise' WHERE id = $1`, [
      owner.rootCredentialId,
    ]);
    await expectDeny(pool, owner.deviceCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("revoking the host (ancestor) denies a live agent on the next fresh read, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    await expectResolve(pool, owner.agentCredentialId, communityId, owner.agentMemberId);

    await pool.query(`UPDATE credential SET revoked_at = now(), revoked_reason = 'compromise' WHERE id = $1`, [
      owner.hostCredentialId,
    ]);
    await expectDeny(pool, owner.agentCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("revoking the target credential itself denies on the next fresh read, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    await expectResolve(pool, owner.deviceCredentialId, communityId, owner.humanMemberId);

    await pool.query(`UPDATE credential SET revoked_at = now(), revoked_reason = 'compromise' WHERE id = $1`, [
      owner.deviceCredentialId,
    ]);
    await expectDeny(pool, owner.deviceCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("revoking the human member denies resolution even with a live credential chain, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    await pool.query(`UPDATE member SET revoked_at = now(), revoked_reason = 'suspension' WHERE id = $1`, [
      owner.humanMemberId,
    ]);
    await expectDeny(pool, owner.deviceCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Missing credential / missing or inactive member.
// ---------------------------------------------------------------------------
test("an absent credential denies, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId } = await buildFixture(pool);
    const before = await snapshot(pool);

    await expectDeny(pool, randomUUID(), communityId);
    await assertZeroMutation(pool, before);
  });
});

test("a credential with no active member for the community denies, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId } = await buildFixture(pool);

    // A person whose root/device exist but who has NO member row.
    const orphan = await createValidPerson(pool, communityId, "orphan");
    // orphan has an active human member already (createValidPerson makes one);
    // delete it to simulate absent membership.
    await pool.query(`DELETE FROM member WHERE id = $1`, [orphan.humanMemberId]);
    const before = await snapshot(pool);

    await expectDeny(pool, orphan.deviceCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Direct root / host presentation is never a session actor.
// ---------------------------------------------------------------------------
test("a human root presented directly denies (roots are never direct actors), zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    await expectDeny(pool, owner.rootCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("a host credential presented directly denies (hosts are never direct actors), zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    await expectDeny(pool, owner.hostCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Cross-community: the member must belong to the trusted community.
// ---------------------------------------------------------------------------
test("a credential whose member belongs to a different community denies, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const otherCommunityId = (
      await pool.query(
        `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
        ["https://other.example", "Other"],
      )
    ).rows[0].id;
    const before = await snapshot(pool);

    // Resolve using a community the person is NOT a member of.
    await expectDeny(pool, owner.deviceCredentialId, otherCommunityId);
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Fabricated malformed chains (fabricated below the write triggers, which reads
// must not trust): cycle, over-depth, cross-person, malformed typed path.
// ---------------------------------------------------------------------------
test("a DB-fabricated cycle denies without unbounded traversal, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId } = await buildFixture(pool);
    await disableCredentialTriggers(pool);

    // Close a two-node loop: b.parent = a, then a.parent = b. The SQL depth cap
    // terminates the walk; the validator must still refuse it.
    const loopPersonId = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["loop-person"])
    ).rows[0].id;
    const a = await insertCredential(pool, loopPersonId, "cycle-a", "human", null);
    const b = await insertCredential(pool, loopPersonId, "cycle-b", "human", a);
    await pool.query(`UPDATE credential SET parent_credential_id = $1 WHERE id = $2`, [b, a]);
    const before = await snapshot(pool);

    await expectDeny(pool, a, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("an over-depth chain (>3 hops) denies at the cap, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId } = await buildFixture(pool);
    await disableCredentialTriggers(pool);

    // Build a 5-node human chain (root -> n1 -> n2 -> n3 -> start) by
    // fabricating a shape no write trigger would allow. The walk must stop at
    // the three-hop cap and deny rather than walk unbounded.
    const chainPersonId = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["chain-person"])
    ).rows[0].id;
    const root = await insertCredential(pool, chainPersonId, "ov-root", "human", null);
    const n1 = await insertCredential(pool, chainPersonId, "ov-1", "human", root);
    const n2 = await insertCredential(pool, chainPersonId, "ov-2", "human", n1);
    const n3 = await insertCredential(pool, chainPersonId, "ov-3", "human", n2);
    const start = await insertCredential(pool, chainPersonId, "ov-4", "human", n3);
    void n1;
    const before = await snapshot(pool);

    await expectDeny(pool, start, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("a cross-person chain denies, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    await disableCredentialTriggers(pool);

    // A device owned by a different person but parented to owner's root.
    const otherPersonId = (
      await pool.query("INSERT INTO person (display_name) VALUES ($1) RETURNING id", ["other-person"])
    ).rows[0].id;
    const crossDevice = await insertCredential(
      pool,
      otherPersonId,
      "cross-device-pub",
      "human",
      owner.rootCredentialId,
    );
    const before = await snapshot(pool);

    await expectDeny(pool, crossDevice, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("a malformed typed path (agent directly under a human root) denies, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    await disableCredentialTriggers(pool);

    // An agent credential parented directly to the human root (no host hop).
    const badAgent = await insertCredential(
      pool,
      owner.personId,
      "bad-agent-pub",
      "agent",
      owner.rootCredentialId,
    );
    const before = await snapshot(pool);

    await expectDeny(pool, badAgent, communityId);
    await assertZeroMutation(pool, before);
  });
});

test("a host credential present directly denies even though it belongs to a valid owner, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { communityId, owner } = await buildFixture(pool);
    const before = await snapshot(pool);

    // Host is a valid credential in a valid chain but must never resolve as an actor.
    await expectDeny(pool, owner.hostCredentialId, communityId);
    await assertZeroMutation(pool, before);
  });
});
