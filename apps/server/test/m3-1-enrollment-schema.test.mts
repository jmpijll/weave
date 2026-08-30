import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MigrationError, runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";

if (!BASE_URL) {
  console.error(
    "m3-1 enrollment schema: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL — M3.1 pairing-token + host schema evidence is mandatory)",
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
  const database = `weave_m31_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
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

/** Seed a community, a person, a human-owner root credential, and a valid
 * (kind=host, parented to the human root) host credential. Returns their ids. */
async function seedScope(pool: pg.Pool) {
  const community = (await pool.query(
    `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
    ["https://m31.example", "M3.1 Test"],
  )).rows[0].id;
  const person = (await pool.query(
    `INSERT INTO person (display_name) VALUES ($1) RETURNING id`,
    ["m31-owner"],
  )).rows[0].id;
  const credential = (await pool.query(
    `INSERT INTO credential (person_id, public_key, algorithm, kind)
     VALUES ($1, $2, $3, 'human') RETURNING id`,
    [person, "0".repeat(64), "ed25519"],
  )).rows[0].id;
  const hostCredential = (await pool.query(
    `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
     VALUES ($1, $2, $3, 'host', $4) RETURNING id`,
    [person, "1".repeat(64), "ed25519", credential],
  )).rows[0].id;
  return { community, person, credential, hostCredential };
}

test("fresh database applies 0005 once; re-run applies nothing", async () => {
  await withFreshDatabase(async (pool) => {
    const first = await runMigrations(pool);
    assert.deepEqual(first.applied, [1, 2, 3, 4, 5, 6]);
    assert.equal(first.skipped, 0);

    const tables = await pool.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' ORDER BY table_name`,
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
      "pairing_token",
    ]) {
      assert.ok(names.includes(expected), `expected table ${expected} to exist`);
    }

    const second = await runMigrations(pool);
    assert.deepEqual(second.applied, []);
    assert.equal(second.skipped, 6);
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

test("pairing_token exposes the frozen column set with correct types and defaults", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const columns = (await pool.query(
      `SELECT column_name, data_type, is_nullable, column_default
       FROM information_schema.columns
       WHERE table_name = 'pairing_token'
       ORDER BY column_name`,
    )).rows;
    const map: Record<string, { data_type: string; is_nullable: string; column_default: string | null }> = {};
    for (const row of columns) map[row.column_name] = row;

    // Exactly the frozen contract §2 column set — no extras such as issued_at.
    const cols = columns.map((r) => r.column_name);
    for (const expected of [
      "id",
      "issued_by_credential_id",
      "host_public_key",
      "community_id",
      "expires_at",
      "consumed_at",
    ]) {
      assert.ok(cols.includes(expected), `pairing_token must carry ${expected}`);
    }
    assert.equal(cols.length, 6, "pairing_token must have exactly the six frozen columns");

    assert.equal(map.id.data_type, "uuid");
    assert.equal(map.id.is_nullable, "NO");
    assert.ok(map.id.column_default?.includes("gen_random_uuid()"), "id defaults to gen_random_uuid()");
    assert.equal(map.issued_by_credential_id.data_type, "uuid");
    assert.equal(map.host_public_key.data_type, "text");
    assert.equal(map.community_id.data_type, "uuid");
    assert.equal(map.expires_at.data_type, "timestamp with time zone");
    assert.equal(map.consumed_at.data_type, "timestamp with time zone");
    assert.equal(map.consumed_at.is_nullable, "YES");
  });
});

test("pairing_token enforces references and the strict 64-char lowercase-hex host key", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, credential } = await seedScope(pool);
    const base = {
      insert: `INSERT INTO pairing_token
         (issued_by_credential_id, host_public_key, community_id, expires_at)
       VALUES ($1, $2, $3, now() + interval '1 hour')`,
    };

    // A valid lowercase 64-char hex host key inserts.
    await pool.query(base.insert, [credential, "aa".repeat(32), community]);

    // Uppercase hex is refused (strict lowercase floor).
    await expectReject(pool, base.insert, [credential, "AA".repeat(32), community], "pairing_token_host_public_key_lower_hex");
    // Non-hex characters are refused.
    await expectReject(pool, base.insert, [credential, "z".repeat(64), community], "pairing_token_host_public_key_lower_hex");
    // Wrong length (63 hex chars) is refused.
    await expectReject(pool, base.insert, [credential, "a".repeat(63), community], "pairing_token_host_public_key_lower_hex");
    // Wrong length (65 hex chars) is refused.
    await expectReject(pool, base.insert, [credential, "a".repeat(65), community], "pairing_token_host_public_key_lower_hex");

    // issued_by_credential_id FK is enforced (a non-existent credential refuses).
    await expectReject(
      pool,
      base.insert,
      ["00000000-0000-4000-8000-0000000000fe", "ab".repeat(32), community],
      "foreign key",
    );
    // community_id FK is enforced (a non-existent community refuses).
    await expectReject(
      pool,
      base.insert,
      [credential, "ab".repeat(32), "00000000-0000-4000-8000-0000000000ed"],
      "foreign key",
    );
  });
});

test("consumed_at is nullable and a consumed token is a state, not a deletion", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, credential } = await seedScope(pool);
    const token = (await pool.query(
      `INSERT INTO pairing_token
         (issued_by_credential_id, host_public_key, community_id, expires_at)
       VALUES ($1, $2, $3, now() + interval '1 hour') RETURNING id, consumed_at`,
      [credential, "aa".repeat(32), community],
    )).rows[0];
    assert.equal(token.consumed_at, null, "a pending token has NULL consumed_at");

    const updated = await pool.query(
      `UPDATE pairing_token SET consumed_at = now() WHERE id = $1 RETURNING consumed_at`,
      [token.id],
    );
    assert.ok(updated.rows[0].consumed_at, "consumed_at becomes set on consume");
    const count = (await pool.query(`SELECT count(*)::int AS n FROM pairing_token`)).rows[0].n;
    assert.equal(count, 1, "consume must not delete the row");
  });
});

test("host carries the four additive columns with production norms and defaults", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { person, hostCredential } = await seedScope(pool);

    const columns = (await pool.query(
      `SELECT column_name, data_type, is_nullable, column_default
       FROM information_schema.columns
       WHERE table_name = 'host'
         AND column_name IN ('capabilities', 'last_seen_at', 'status', 'paired_at')
       ORDER BY column_name`,
    )).rows;
    const map: Record<string, { data_type: string; is_nullable: string; column_default: string | null }> = {};
    for (const row of columns) map[row.column_name] = row;

    for (const expected of ["capabilities", "last_seen_at", "status", "paired_at"]) {
      assert.ok(map[expected], `host must carry ${expected}`);
    }

    assert.equal(map.capabilities.data_type, "jsonb");
    assert.equal(map.capabilities.is_nullable, "NO");
    assert.ok(
      map.capabilities.column_default?.includes("harnesses"),
      "capabilities defaults to the frozen HostCapabilities empty form",
    );
    assert.equal(map.last_seen_at.data_type, "timestamp with time zone");
    assert.equal(map.last_seen_at.is_nullable, "YES");
    assert.equal(map.status.data_type, "text");
    assert.equal(map.status.is_nullable, "NO");
    assert.ok(map.status.column_default?.includes("offline"), "status defaults to offline");
    assert.equal(map.paired_at.data_type, "timestamp with time zone");
    assert.equal(map.paired_at.is_nullable, "NO");
    assert.ok(map.paired_at.column_default?.includes("now()"), "paired_at defaults to insertion time");

    // Insert a host: defaults are applied, and it backfills pre-existing rows.
    const inserted = (await pool.query(
      `INSERT INTO host (owner_person_id, credential_id) VALUES ($1, $2)
       RETURNING capabilities, status, paired_at, last_seen_at`,
      [person, hostCredential],
    )).rows[0];
    assert.deepEqual(inserted.capabilities, { harnesses: [] }, "capabilities defaults to the empty frozen HostCapabilities form");
    assert.equal(inserted.status, "offline", "status defaults to offline");
    assert.ok(inserted.paired_at, "paired_at is non-null on insert");
    assert.equal(inserted.last_seen_at, null, "last_seen_at is null for a fresh host");
  });
});

test("host.status is constrained to the frozen ready/degraded/offline set", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { person, credential } = await seedScope(pool);

    async function newHostCredential(seed: string) {
      return (await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
         VALUES ($1, $2, $3, 'host', $4) RETURNING id`,
        [person, seed, "ed25519", credential],
      )).rows[0].id;
    }

    for (const status of ["ready", "degraded", "offline"]) {
      const hc = await newHostCredential(status);
      await pool.query(
        `INSERT INTO host (owner_person_id, credential_id, status) VALUES ($1, $2, $3)`,
        [person, hc, status],
      );
    }

    const hcBad = await newHostCredential("bad");
    await expectReject(
      pool,
      `INSERT INTO host (owner_person_id, credential_id, status) VALUES ($1, $2, $3)`,
      [person, hcBad, "unknown"],
      "check",
    );
    await expectReject(
      pool,
      `INSERT INTO host (owner_person_id, credential_id, status) VALUES ($1, $2, $3)`,
      [person, hcBad, "READY"],
      "check",
    );
  });
});

test("host.capabilities is server-validated JSONB: any JSON object and null-refused", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { person, credential } = await seedScope(pool);
    const hostCredential = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, $3, 'host', $4) RETURNING id`,
      [person, "2".repeat(64), "ed25519", credential],
    )).rows[0].id;

    const inserted = (await pool.query(
      `INSERT INTO host (owner_person_id, credential_id, capabilities) VALUES ($1, $2, $3)
       RETURNING capabilities`,
      [person, hostCredential, JSON.stringify({ harnesses: [{ harness: "opencode" }] })],
    )).rows[0];
    assert.deepEqual(inserted.capabilities, { harnesses: [{ harness: "opencode" }] });

    // A NULL capabilities insert is refused (NOT NULL).
    await expectReject(
      pool,
      `INSERT INTO host (owner_person_id, credential_id, capabilities) VALUES ($1, $2, $3)`,
      [person, hostCredential, null],
      "null value",
    );
  });
});

test("EnrollHostPayload is HTTP-only: not a WireMessage member", async () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const source = await readFile(join(root, "packages/protocol/src/index.ts"), "utf8");
  assert.ok(source.includes("export interface EnrollHostPayload"), "EnrollHostPayload must remain exported");
  assert.equal(source.includes("EnrollHostMessage"), false, "EnrollHostMessage must not exist (HTTP-only, not WireMessage)");
  assert.equal(source.includes('"enroll.host"'), false, '"enroll.host" must not appear as a WireMessage type');
});
