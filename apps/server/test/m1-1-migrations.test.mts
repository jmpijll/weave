import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import {
  MigrationError,
  runMigrations,
} from "../src/db/migrate.ts";
import {
  createDatabaseConfig,
  createDatabasePool,
} from "../src/db/pool.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";

if (!BASE_URL) {
  console.log(
    "m1-1 migrations integration: SKIP (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL to exercise this layer)",
  );
  process.exit(0);
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
  const database = `weave_m1_1_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
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

/** Assert a single-statement insert/update/delete fails and matches the message. */
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

test("fresh database migrates exactly once; re-run applies nothing", async () => {
  await withFreshDatabase(async (pool) => {
    const first = await runMigrations(pool);
    assert.deepEqual(first.applied, [1]);
    assert.equal(first.skipped, 0);

    const tables = await pool.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public'
       ORDER BY table_name`,
    );
    const names = tables.rows.map((r) => r.table_name);
    for (const expected of [
      "schema_migration",
      "community",
      "person",
      "credential",
      "host",
      "agent",
      "audit_event",
    ]) {
      assert.ok(names.includes(expected), `expected table ${expected} to exist`);
    }

    const second = await runMigrations(pool);
    assert.deepEqual(second.applied, []);
    assert.equal(second.skipped, 1);
  });
});

test("a migration recorded in history but not in this build is refused (future schema)", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const client = await pool.connect();
    try {
      await client.query(
        "INSERT INTO public.schema_migration (version, checksum) VALUES ($1, $2)",
        [9999, "deadbeef"],
      );
    } finally {
      client.release();
    }
    await assert.rejects(runMigrations(pool), (error: unknown) => {
      assert.ok(error instanceof MigrationError);
      assert.match(error.message, /ahead of this build/);
      return true;
    });
  });
});

test("a changed checksum on an applied migration is refused", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const client = await pool.connect();
    try {
      await client.query(
        "UPDATE public.schema_migration SET checksum = $1 WHERE version = 1",
        ["0".repeat(64)],
      );
    } finally {
      client.release();
    }
    await assert.rejects(runMigrations(pool), (error: unknown) => {
      assert.ok(error instanceof MigrationError);
      assert.match(error.message, /checksum differs/);
      return true;
    });
  });
});

test("concurrent migration starts do not race: exactly one applies, one skips", async () => {
  await withFreshDatabase(async (pool) => {
    const [a, b] = await Promise.all([runMigrations(pool), runMigrations(pool)]);
    const appliedCount = (a.applied.length === 1 ? 1 : 0) + (b.applied.length === 1 ? 1 : 0);
    assert.equal(appliedCount, 1, "exactly one concurrent run applies the migration");
    const ledger = await pool.query("SELECT count(*)::int AS n FROM public.schema_migration");
    assert.equal(ledger.rows[0].n, 1);
  });
});

test("Postgres enforces the Pass 40/41 credential-tree shape", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);

    const p1 = (await pool.query(
      "INSERT INTO person (display_name) VALUES ($1) RETURNING id",
      ["person-one"],
    )).rows[0].id;
    const p2 = (await pool.query(
      "INSERT INTO person (display_name) VALUES ($1) RETURNING id",
      ["person-two"],
    )).rows[0].id;

    const root1 = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind)
       VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
      [p1, "root1-public"],
    )).rows[0].id;

    // exactly one active root per person (Pass 41)
    await expectReject(
      pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind)
       VALUES ($1, $2, 'ed25519', 'human')`,
      [p1, "root1b-public"],
      "duplicate key",
    );

    // a human device under the same person's root is valid
    const device1 = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
      [p1, "device1-public", root1],
    )).rows[0].id;

    // cross-person parent denied
    await expectReject(
      pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3)`,
      [p2, "dev-p2", root1],
      "same person",
    );

    // self-parent denied (check constraint)
    await expectReject(
      pool,
      `INSERT INTO credential (id, person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, $3, 'ed25519', 'human', $1)`,
      ["00000000-0000-4000-8000-000000000099", p1, "self-parent"],
      "cannot parent itself",
    );
    await expectReject(
      pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3)`,
      [p1, "device2-public", device1],
      "activation root",
    );

    // host and agent credentials must have a parent
    await expectReject(
      pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind)
       VALUES ($1, $2, 'ed25519', 'host')`,
      [p1, "host-no-parent"],
      "must have a parent",
    );

    // host parents only to the owner's active root (not a device)
    await expectReject(
      pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'host', $3)`,
      [p1, "host-under-device", device1],
      "owner active root",
    );

    // a valid host under the root
    const hostCred = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'host', $3) RETURNING id`,
      [p1, "host1-public", root1],
    )).rows[0].id;

    // agent parents only to a host credential, not a human root
    await expectReject(
      pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'agent', $3)`,
      [p1, "agent-under-root", root1],
      "host credential",
    );

    // a valid agent under the host credential
    const agentCred = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'agent', $3) RETURNING id`,
      [p1, "agent1-public", hostCred],
    )).rows[0].id;

    // host ownership record must match the host credential owner
    await expectReject(
      pool,
      `INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2)`,
      [p2, hostCred],
      "host owner must match",
    );

    const host = (await pool.query(
      `INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2) RETURNING id`,
      [p1, hostCred],
    )).rows[0].id;

    // agent record must parent to the recorded host credential (cross-host denied)
    const hostCred2 = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'host', $3) RETURNING id`,
      [p1, "host2-public", root1],
    )).rows[0].id;
    const host2 = (await pool.query(
      `INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2) RETURNING id`,
      [p1, hostCred2],
    )).rows[0].id;

    await expectReject(
      pool,
      `INSERT INTO agent (host_id, credential_id) VALUES ($1, $2)`,
      [host2, agentCred],
      "cross-host",
    );

    await pool.query(
      `INSERT INTO agent (host_id, credential_id) VALUES ($1, $2)`,
      [host, agentCred],
    );

    // revoked ancestor denies a new descendant
    await pool.query(
      "UPDATE credential SET revoked_at = now(), revoked_reason = 'compromise' WHERE id = $1",
      [root1],
    );
    await expectReject(
      pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3)`,
      [p1, "device-after-revoke", root1],
      "must not be revoked",
    );
  });
});

test("audit_event is append-only", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const community = (await pool.query(
      `INSERT INTO community (canonical_tls_origin, name)
       VALUES ($1, $2) RETURNING id`,
      ["https://weave.example", "Weave Test"],
    )).rows[0].id;

    const audit = await pool.query(
      `INSERT INTO audit_event (event_type, community_id, target_type, target_id, correlation_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      ["credential.root_enrol", community, "person", "who", "corr-1"],
    );

    await expectReject(
      pool,
      "UPDATE audit_event SET event_type = 'tampered' WHERE id = $1",
      [audit.rows[0].id],
      "append-only",
    );
    await expectReject(
      pool,
      "DELETE FROM audit_event WHERE id = $1",
      [audit.rows[0].id],
      "append-only",
    );
  });
});
