import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MigrationError, runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";

if (!BASE_URL) {
  console.error(
    "m1-3 recovery schema: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL — M1.3.1 migration and recovery-constraint evidence is mandatory)",
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
  const database = `weave_m1_3_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
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

/** Seed a community and a person, returning their ids. */
async function seedScope(pool: pg.Pool) {
  const community = (await pool.query(
    `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
    ["https://recovery.example", "Recovery Test"],
  )).rows[0].id;
  const person = (await pool.query(
    `INSERT INTO person (display_name) VALUES ($1) RETURNING id`,
    ["recovery-user"],
  )).rows[0].id;
  return { community, person };
}

test("fresh database migrates exactly once, including the recovery schema; re-run applies nothing", async () => {
  await withFreshDatabase(async (pool) => {
    const first = await runMigrations(pool);
    assert.deepEqual(first.applied, [1, 2, 3]);
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
      "member",
      "role",
      "permission",
      "role_permission",
      "space",
      "space_membership",
      "member_role_assignment",
      "community_admission_invite",
      "space_invite",
      "audit_event",
      "recovery_verifier",
      "recovery_challenge",
    ]) {
      assert.ok(names.includes(expected), `expected table ${expected} to exist`);
    }

    // The recovery schema must not have created a refusal-code registry table.
    assert.ok(
      !names.includes("refusal_code") && !names.includes("error_code"),
      "no refusal-code / error-code registry table may be created by the recovery migration",
    );

    const second = await runMigrations(pool);
    assert.deepEqual(second.applied, []);
    assert.equal(second.skipped, 3);
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

test("a changed checksum on an applied migration is refused (altered history)", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const client = await pool.connect();
    try {
      await client.query(
        "UPDATE public.schema_migration SET checksum = $1 WHERE version = 3",
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

test("exactly one active recovery verifier per (person, community)", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, person } = await seedScope(pool);

    const first = (await pool.query(
      `INSERT INTO recovery_verifier (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [person, community, "verifier-public-key-a", 4],
    )).rows[0].id;

    // A second active verifier for the same (person, community) is rejected.
    await expectReject(
      pool,
      `INSERT INTO recovery_verifier (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4)`,
      [person, community, "verifier-public-key-b", 4],
      "duplicate key",
    );

    // A second person in the same community is allowed (constraint is per tuple).
    async function freshPerson() {
      return (await pool.query(
        `INSERT INTO person (display_name) VALUES ($1) RETURNING id`,
        ["another-recovery-user"],
      )).rows[0].id;
    }
    const person2 = await freshPerson();
    await pool.query(
      `INSERT INTO recovery_verifier (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4)`,
      [person2, community, "verifier-public-key-c", 4],
    );

    // Revoking the first frees the slot for a replacement verifier (fresh row,
    // revoked row retained for audit).
    await pool.query(
      `UPDATE recovery_verifier SET revoked_at = now(), revoked_reason = 'compromise'
       WHERE id = $1`,
      [first],
    );
    const replacement = (await pool.query(
      `INSERT INTO recovery_verifier (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [person, community, "verifier-public-key-d", 4],
    )).rows[0].id;
    assert.ok(replacement);
  });
});

test("recovery_challenge is bound to the (verifier, person, community) tuple", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, person } = await seedScope(pool);
    async function freshPerson() {
      return (await pool.query(
        `INSERT INTO person (display_name) VALUES ($1) RETURNING id`,
        ["scope-person"],
      )).rows[0].id;
    }
    const person2 = await freshPerson();

    const verifier = (await pool.query(
      `INSERT INTO recovery_verifier (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [person, community, "verifier-public-key", 4],
    )).rows[0].id;

    const challengeCommon = { canonical_tls_origin: "wss://recovery.example:8443" };
    const nonce = Buffer.alloc(32, 7);

    // A valid challenge against the correct tuple is accepted.
    await pool.query(
      `INSERT INTO recovery_challenge
         (verifier_id, person_id, community_id, canonical_tls_origin, nonce,
          intended_device_public_key, environment_code, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '1 hour')`,
      [verifier, person, community, challengeCommon.canonical_tls_origin, nonce, "device-pub-1", 4],
    );

    // A challenge whose person_id disagrees with the verifier tuple is rejected
    // (composite FK): the verifier row is (person, community); presenting for
    // person2 must fail.
    await expectReject(
      pool,
      `INSERT INTO recovery_challenge
         (verifier_id, person_id, community_id, canonical_tls_origin, nonce,
          intended_device_public_key, environment_code, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '1 hour')`,
      [verifier, person2, community, challengeCommon.canonical_tls_origin, nonce, "device-pub-2", 4],
      "recovery_challenge_verifier_binding",
    );

    // A challenge for a non-existent verifier id must also fail the FK.
    await expectReject(
      pool,
      `INSERT INTO recovery_challenge
         (verifier_id, person_id, community_id, canonical_tls_origin, nonce,
          intended_device_public_key, environment_code, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '1 hour')`,
      ["00000000-0000-4000-8000-0000000000fe", person, community, challengeCommon.canonical_tls_origin, nonce, "device-pub-3", 4],
      "recovery_challenge_verifier_binding",
    );
  });
});

test("recovery schema enforces the fixed v1 version/algorithm values and permitted environment codes", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, person } = await seedScope(pool);

    // Verifier: non-1 version/algorithm values must reject. Establish a valid
    // verifier per case first (the version CHECK fires before the composite
    // binding and requires a single fixed environment_code per scope).
    await pool.query(
      `INSERT INTO recovery_verifier (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4)`,
      [person, community, "verifier-pub-ok", 4],
    );
    await expectReject(
      pool,
      `INSERT INTO recovery_verifier
         (person_id, community_id, public_key, environment_code, protocol_version)
       VALUES ($1, $2, $3, $4, $5)`,
      [person, community, "verifier-pub-proto", 4, 2],
      "recovery_verifier_protocol_version_check",
    );
    await expectReject(
      pool,
      `INSERT INTO recovery_verifier
         (person_id, community_id, public_key, environment_code, algorithm_code)
       VALUES ($1, $2, $3, $4, $5)`,
      [person, community, "verifier-pub-alg", 4, 2],
      "recovery_verifier_algorithm_code_check",
    );
    await expectReject(
      pool,
      `INSERT INTO recovery_verifier
         (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4)`,
      [person, community, "verifier-pub-env", 5],
      "recovery_verifier_environment_code_check",
    );
  });
});

test("recovery_challenge stores a fixed-size 32-byte nonce and public keys as text", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, person } = await seedScope(pool);
    const verifier = (await pool.query(
      `INSERT INTO recovery_verifier (person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [person, community, "verifier-pub", 4],
    )).rows[0].id;

    // A non-32-byte nonce is rejected.
    await expectReject(
      pool,
      `INSERT INTO recovery_challenge
         (verifier_id, person_id, community_id, canonical_tls_origin, nonce,
          intended_device_public_key, environment_code, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '1 hour')`,
      [verifier, person, community, "wss://recovery.example:8443", Buffer.alloc(16), "device-pub", 4],
      "recovery_challenge_nonce_check",
    );

    // The nonce column is bytea and the public-key columns are text.
    const columns = (await pool.query(
      `SELECT column_name, data_type FROM information_schema.columns
       WHERE table_name = 'recovery_challenge'
         AND column_name IN ('nonce', 'intended_device_public_key', 'canonical_tls_origin', 'consumed_at')
       ORDER BY column_name`,
    )).rows;
    const map: Record<string, string> = {};
    for (const row of columns) map[row.column_name] = row.data_type;
    assert.equal(map.nonce, "bytea");
    assert.equal(map.intended_device_public_key, "text");
    assert.equal(map.canonical_tls_origin, "text");
    assert.equal(map.consumed_at, "timestamp with time zone");
  });
});

test("recovery verifier and challenge use timestamp lifecycle fields, not harness booleans", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, person } = await seedScope(pool);

    const verifierCols = (await pool.query(
      `SELECT column_name, data_type FROM information_schema.columns
       WHERE table_name = 'recovery_verifier'
         AND column_name IN ('revoked_at', 'revoked_reason', 'created_at', 'public_key', 'algorithm')
       ORDER BY column_name`,
    )).rows;
    const vmap: Record<string, string> = {};
    for (const row of verifierCols) vmap[row.column_name] = row.data_type;
    assert.equal(vmap.revoked_at, "timestamp with time zone");
    assert.equal(vmap.created_at, "timestamp with time zone");
    assert.equal(vmap.public_key, "text");
    assert.equal(vmap.algorithm, "text");

    // No boolean lifecycle columns anywhere in the recovery tables.
    const boolCols = (await pool.query(
      `SELECT table_name, column_name FROM information_schema.columns
       WHERE table_schema = 'public'
         AND table_name IN ('recovery_verifier', 'recovery_challenge')
         AND data_type = 'boolean'`,
    )).rows;
    assert.equal(boolCols.length, 0, "recovery tables must not use boolean lifecycle flags");
  });
});

test("migration runner refuses a backfilled lower-numbered pending migration (forward-only preserved)", async () => {
  await withFreshDatabase(async (pool) => {
    const dir = await mkdtemp(join(tmpdir(), "weave-m3-backfill-"));
    try {
      await writeFile(join(dir, "0004_fourth.sql"), "CREATE TABLE fourth_table (id int);");
      const first = await runMigrations(pool, { migrationsDir: dir });
      assert.deepEqual(first.applied, [4]);

      // A newly introduced lower version must not run after version 4 is applied.
      await writeFile(join(dir, "0002_second.sql"), "CREATE TABLE second_table2 (id int);");
      await assert.rejects(runMigrations(pool, { migrationsDir: dir }), (error: unknown) => {
        assert.ok(error instanceof MigrationError);
        assert.match(error.message, /forward-only violated/);
        return true;
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
