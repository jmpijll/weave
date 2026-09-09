import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";

if (!BASE_URL) {
  console.error(
    "m3-2 persistence: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL — M3.2 pairing relational-substrate evidence is mandatory)",
  );
  process.exit(1);
}

const MAX_MS = "9007199254740991";
const MAX_ISSUE_MS = "9007199254140991";
const DURATION_MS = "600000";

let dbCounter = 0;
function swapDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

async function withFreshDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T> {
  const admin = new Client({ connectionString: BASE_URL });
  await admin.connect();
  const database = `weave_m32_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
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

const MIGRATIONS_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "migrations");

/** Seed community + person + unrevoked human root + unrevoked human device +
 * active human membership. Returns ids. Credential keys derive from the tag
 * so independent seeds never collide on the identity unique constraint. */
async function seedEligibleIssuer(pool: pg.Pool, tag: string) {
  const { createHash } = await import("node:crypto");
  const rootKey = createHash("sha256").update(`root:${tag}`).digest("hex");
  const deviceKey = createHash("sha256").update(`device:${tag}`).digest("hex");
  const community = (await pool.query(
    `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
    [`https://${tag}.example`, "M3.2 Test"],
  )).rows[0].id;
  const person = (await pool.query(
    `INSERT INTO person (display_name) VALUES ($1) RETURNING id`,
    [`${tag}-owner`],
  )).rows[0].id;
  const root = (await pool.query(
    `INSERT INTO credential (person_id, public_key, algorithm, kind)
     VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
    [person, rootKey],
  )).rows[0].id;
  const device = (await pool.query(
    `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
     VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
    [person, deviceKey, root],
  )).rows[0].id;
  const member = (await pool.query(
    `INSERT INTO member (community_id, subject_kind, person_id)
     VALUES ($1, 'human', $2) RETURNING id`,
    [community, person],
  )).rows[0].id;
  return { community, person, root, device, member };
}

function insertToken(issuedAt: string, expiresAt: string) {
  return {
    insert: `INSERT INTO pairing_token
       (issued_by_credential_id, host_public_key, community_id, issued_at, policy_version, expires_at)
     VALUES ($1, $2, $3, $4, 1, $5) RETURNING id, issued_at, expires_at, consumed_at`,
    params: (device: string, community: string) =>
      [device, "aa".repeat(32), community, issuedAt, expiresAt],
  };
}

test("fresh database migrates [1..7]; rerun applies nothing; ledger holds 7", async () => {
  await withFreshDatabase(async (pool) => {
    const first = await runMigrations(pool);
    assert.deepEqual(first.applied, [1, 2, 3, 4, 5, 6, 7]);
    assert.equal(first.skipped, 0);

    const names = (await pool.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' ORDER BY table_name`,
    )).rows.map((r) => r.table_name);
    assert.ok(names.includes("pairing_policy_registry"), "policy registry must exist");
    assert.ok(names.includes("pairing_token"), "pairing_token must exist");

    const second = await runMigrations(pool);
    assert.deepEqual(second.applied, []);
    assert.equal(second.skipped, 7);

    const ledger = (await pool.query(`SELECT count(*)::int AS n FROM public.schema_migration`)).rows[0].n;
    assert.equal(ledger, 7, "ledger must hold seven checksummed migrations");
  });
});

test("pairing_token carries exact bigint lifecycle columns with no defaults", async () => {
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

    for (const expected of [
      "id",
      "issued_by_credential_id",
      "host_public_key",
      "community_id",
      "issued_at",
      "policy_version",
      "expires_at",
      "consumed_at",
    ]) {
      assert.ok(map[expected], `pairing_token must carry ${expected}`);
    }
    assert.equal(columns.length, 8, "pairing_token must have exactly the eight I2 columns");

    assert.equal(map.issued_at.data_type, "bigint");
    assert.equal(map.issued_at.is_nullable, "NO");
    assert.equal(map.issued_at.column_default, null, "issued_at must have no default");
    assert.equal(map.expires_at.data_type, "bigint");
    assert.equal(map.expires_at.is_nullable, "NO");
    assert.equal(map.expires_at.column_default, null, "expires_at must have no default");
    assert.equal(map.consumed_at.data_type, "bigint");
    assert.equal(map.consumed_at.is_nullable, "YES");
    assert.equal(map.consumed_at.column_default, null, "consumed_at must have no default");
    assert.equal(map.policy_version.data_type, "integer");
    assert.equal(map.policy_version.is_nullable, "NO");
    assert.equal(map.policy_version.column_default, null, "policy_version must have no default");
  });
});

test("policy registry seeds exactly (1, 600000) and refuses every mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const rows = (await pool.query(`SELECT version, duration_ms FROM pairing_policy_registry`)).rows;
    assert.equal(rows.length, 1, "exactly one policy row must exist");
    assert.equal(rows[0].version, 1);
    assert.equal(String(rows[0].duration_ms), DURATION_MS, "duration must cross as exact text");

    await expectReject(pool,
      `UPDATE pairing_policy_registry SET duration_ms = $1 WHERE version = 1`, ["600001"],
      "immutable");
    await expectReject(pool,
      `DELETE FROM pairing_policy_registry WHERE version = 1`, [],
      "immutable");
    await expectReject(pool,
      `INSERT INTO pairing_policy_registry (version, duration_ms) VALUES (2, 600000)`, [],
      "pairing_policy_registry_version_check");
  });
});

test("nonempty pairing_token table fails the 0007 migration closed", async () => {
  await withFreshDatabase(async (pool) => {
    // Apply only 0001..0006 from an isolated copy, then plant a legacy row.
    const partial = await mkdtemp(join(tmpdir(), "weave-m32-partial-"));
    try {
      await cp(MIGRATIONS_ROOT, partial, { recursive: true });
      const { rm: rmFile } = await import("node:fs/promises");
      await rmFile(join(partial, "0007_m32_pairing_relational_substrate.sql"), { force: true });
      const first = await runMigrations(pool, { migrationsDir: partial });
      assert.deepEqual(first.applied, [1, 2, 3, 4, 5, 6]);
    } finally {
      await rm(partial, { recursive: true, force: true });
    }

    const community = (await pool.query(
      `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
      ["https://guard.example", "Guard Test"],
    )).rows[0].id;
    const person = (await pool.query(
      `INSERT INTO person (display_name) VALUES ($1) RETURNING id`,
      ["guard-owner"],
    )).rows[0].id;
    const credential = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind)
       VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
      [person, "0".repeat(64)],
    )).rows[0].id;
    await pool.query(
      `INSERT INTO pairing_token (issued_by_credential_id, host_public_key, community_id, expires_at)
       VALUES ($1, $2, $3, now() + interval '1 hour')`,
      [credential, "bb".repeat(32), community],
    );

    // The full migration set must now refuse 0007 without recording it.
    await assert.rejects(runMigrations(pool), (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      return message.includes("pairing_token is not empty");
    });
    const versions = (await pool.query(
      `SELECT version FROM public.schema_migration ORDER BY version`,
    )).rows.map((r) => r.version);
    assert.deepEqual(versions, [1, 2, 3, 4, 5, 6], "failed 0007 must record nothing");

    // The failed migration rolled back its DDL: legacy timestamp types remain
    // and no policy registry or I2 trigger survives.
    const expiresType = (await pool.query(
      `SELECT data_type FROM information_schema.columns
       WHERE table_name = 'pairing_token' AND column_name = 'expires_at'`,
    )).rows[0].data_type;
    assert.equal(expiresType, "timestamp with time zone", "failed 0007 must leave legacy expires_at");
    const registry = (await pool.query(
      `SELECT count(*)::int AS n FROM information_schema.tables
       WHERE table_name = 'pairing_policy_registry'`,
    )).rows[0].n;
    assert.equal(registry, 0, "failed 0007 must leave no policy registry");
    const triggers = (await pool.query(
      `SELECT trigger_name FROM information_schema.triggers
       WHERE trigger_name IN ('enforce_pairing_token_insert', 'refuse_pairing_policy_mutation',
                              'refuse_pairing_token_truncate', 'refuse_pairing_policy_truncate')`,
    )).rows;
    assert.equal(triggers.length, 0, "failed 0007 must leave no I2 triggers");
  });
});

test("valid issue stores exact bigint facts with derived expiry; values cross as text", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, device } = await seedEligibleIssuer(pool, "issue");
    const { insert, params } = insertToken("123456", "723456");
    const row = (await pool.query(insert, params(device, community))).rows[0];
    assert.equal(String(row.issued_at), "123456");
    assert.equal(String(row.expires_at), "723456", "expiry must equal issued_at + 600000");
    assert.equal(row.consumed_at, null);
    assert.equal(typeof row.expires_at, "string", "bigint must cross the Node boundary as text");
    assert.equal(BigInt(row.expires_at) - BigInt(row.issued_at), 600000n);
  });
});

test("boundary issue at max succeeds; first overflow and mismatched expiry fail", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, device } = await seedEligibleIssuer(pool, "bound");

    const ok = insertToken(MAX_ISSUE_MS, MAX_MS);
    const row = (await pool.query(ok.insert, ok.params(device, community))).rows[0];
    assert.equal(String(row.expires_at), MAX_MS, "max issue must derive max expiry exactly");

    const overflow = insertToken("9007199254140992", MAX_MS);
    await expectReject(pool, overflow.insert, overflow.params(device, community), "overflow");

    const mismatch = insertToken("123456", "723457");
    await expectReject(pool, mismatch.insert, mismatch.params(device, community), "expires_at");

    const negative = insertToken("-1", "599999");
    await expectReject(pool, negative.insert, negative.params(device, community), "is not an exact millisecond");

    await expectReject(pool,
      `INSERT INTO pairing_token
         (issued_by_credential_id, host_public_key, community_id, issued_at, policy_version, expires_at)
       VALUES ($1, $2, $3, $4, 2, $5)`,
      [device, "aa".repeat(32), community, "123456", "723456"],
      "policy");
    const boundaryCount = (await pool.query(`SELECT count(*)::int AS n FROM pairing_token`)).rows[0].n;
    assert.equal(boundaryCount, 1, "only the max-boundary row lands; every refusal lands nothing");
  });
});

test("only the eligible human device issues: full E1 matrix fails closed", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, person, root, device } = await seedEligibleIssuer(pool, "e1");

    async function attempt(issuer: string, comm: string, fragment: string) {
      const { insert } = insertToken("1000", "601000");
      await expectReject(pool, insert,
        [issuer, "cc".repeat(32), comm, "1000", "601000"], fragment);
    }

    // Root, host, agent, and unknown issuers fail.
    await attempt(root, community, "issuer");
    const hostCred = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'host', $3) RETURNING id`,
      [person, "2".repeat(64), root],
    )).rows[0].id;
    await attempt(hostCred, community, "issuer");
    const agentCred = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'agent', $3) RETURNING id`,
      [person, "3".repeat(64), hostCred],
    )).rows[0].id;
    await attempt(agentCred, community, "issuer");
    await attempt("00000000-0000-4000-8000-0000000000fe", community, "issuer");

    // Revoked device, revoked root, and cross-person device fail.
    const revokedDevice = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
      [person, "4".repeat(64), root],
    )).rows[0].id;
    await pool.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [revokedDevice]);
    await attempt(revokedDevice, community, "issuer");

    const otherPerson = (await pool.query(
      `INSERT INTO person (display_name) VALUES ($1) RETURNING id`, ["e1-other"],
    )).rows[0].id;
    const otherRoot = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind)
       VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
      [otherPerson, "5".repeat(64)],
    )).rows[0].id;
    // A cross-person device cannot even be planted: the 0001 credential-tree
    // trigger refuses the placement itself. The I2 trigger retains its
    // cross-person recheck as defense in depth only.
    await expectReject(pool,
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3)`,
      [person, "6".repeat(64), otherRoot],
      "cross-person denied");

    const doomedPerson = (await pool.query(
      `INSERT INTO person (display_name) VALUES ($1) RETURNING id`, ["e1-doomed"],
    )).rows[0].id;
    const doomedRoot = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind)
       VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
      [doomedPerson, "7".repeat(64)],
    )).rows[0].id;
    const doomedDevice = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
      [doomedPerson, "8".repeat(64), doomedRoot],
    )).rows[0].id;
    await pool.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [doomedRoot]);
    await attempt(doomedDevice, community, "issuer");

    // Inactive membership, missing membership, and foreign-community membership fail.
    await pool.query(`UPDATE member SET revoked_at = now() WHERE id = (SELECT id FROM member WHERE person_id = $1)`, [person]);
    await attempt(device, community, "issuer");

    const stranger = (await pool.query(
      `INSERT INTO person (display_name) VALUES ($1) RETURNING id`, ["e1-stranger"],
    )).rows[0].id;
    const strangerRoot = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind)
       VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
      [stranger, "9".repeat(64)],
    )).rows[0].id;
    const strangerDevice = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
      [stranger, "a".repeat(64), strangerRoot],
    )).rows[0].id;
    await attempt(strangerDevice, community, "issuer");

    const elsewhere = (await pool.query(
      `INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`,
      ["https://elsewhere.example", "Elsewhere"],
    )).rows[0].id;
    await attempt(device, elsewhere, "issuer");
  });
});

test("insert carrying consumed_at is refused and lands no row", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, device } = await seedEligibleIssuer(pool, "pending");
    await expectReject(pool,
      `INSERT INTO pairing_token
         (issued_by_credential_id, host_public_key, community_id, issued_at, policy_version, expires_at, consumed_at)
       VALUES ($1, $2, $3, '1000', 1, '601000', '601000')`,
      [device, "dd".repeat(32), community],
      "must not carry consumed_at");
    const count = (await pool.query(`SELECT count(*)::int AS n FROM pairing_token`)).rows[0].n;
    assert.equal(count, 0, "refused insert must land no row");
  });
});

test("TRUNCATE is refused on pairing_token and the policy registry", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, device } = await seedEligibleIssuer(pool, "notrunc");
    const { insert, params } = insertToken("2000", "602000");
    await pool.query(insert, params(device, community));

    await expectReject(pool, `TRUNCATE pairing_token`, [], "may not be truncated");
    // Single-table registry TRUNCATE is refused by PostgreSQL's own
    // referenced-FK guard before the statement trigger; the row still
    // survives. The registry trigger itself is proven by the multi-table
    // form below (where the FK check passes) and the catalog assertion.
    await expectReject(pool, `TRUNCATE pairing_policy_registry`, [], "truncat");
    // Multi-table form traverses the FK; the statement trigger still refuses.
    await expectReject(pool,
      `TRUNCATE pairing_token, pairing_policy_registry`, [], "may not be truncated");
    // Registry-first order demonstrates the registry statement trigger
    // itself: the intentional truncation error, never an OLD-record path
    // (TRUNCATE fires no row trigger at all).
    await expectReject(pool,
      `TRUNCATE pairing_policy_registry, pairing_token`, [], "may not be truncated");
    const triggerRows = (await pool.query(
      `SELECT tgname FROM pg_trigger WHERE NOT tgisinternal AND tgname LIKE 'refuse_pairing%'`,
    )).rows.map((r) => r.tgname);
    assert.ok(triggerRows.includes("refuse_pairing_token_truncate"), "token TRUNCATE trigger must exist");
    assert.ok(triggerRows.includes("refuse_pairing_policy_truncate"), "policy TRUNCATE trigger must exist");

    const tokens = (await pool.query(`SELECT count(*)::int AS n FROM pairing_token`)).rows[0].n;
    assert.equal(tokens, 1, "lifecycle row must survive TRUNCATE attempts");
    const policies = (await pool.query(`SELECT count(*)::int AS n FROM pairing_policy_registry`)).rows[0].n;
    assert.equal(policies, 1, "policy seed must survive TRUNCATE attempts");
  });
});

test("independent issuers do not serialize on the immutable policy row", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const first = await seedEligibleIssuer(pool, "conc-a");
    const second = await seedEligibleIssuer(pool, "conc-b");

    const a = await pool.connect();
    const b = await pool.connect();
    try {
      await a.query("BEGIN");
      await a.query(
        `INSERT INTO pairing_token
           (issued_by_credential_id, host_public_key, community_id, issued_at, policy_version, expires_at)
         VALUES ($1, $2, $3, '3000', 1, '603000')`,
        [first.device, "ee".repeat(32), first.community],
      );

      // A short lock timeout turns any policy-row serialization into a failure.
      await b.query("BEGIN");
      await b.query("SET LOCAL lock_timeout = '2s'");
      await b.query(
        `INSERT INTO pairing_token
           (issued_by_credential_id, host_public_key, community_id, issued_at, policy_version, expires_at)
         VALUES ($1, $2, $3, '3001', 1, '603001')`,
        [second.device, "ef".repeat(32), second.community],
      );
      await b.query("COMMIT");
      await a.query("COMMIT");

      const count = (await pool.query(`SELECT count(*)::int AS n FROM pairing_token`)).rows[0].n;
      assert.equal(count, 2, "both independent issues must land");
    } finally {
      a.release();
      b.release();
    }
  });
});
test("post-lock revalidation refuses an issuer revoked mid-issue", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, device } = await seedEligibleIssuer(pool, "race");

    const blocker = await pool.connect();
    const issuer = await pool.connect();
    try {
      // Blocker holds the device row: the issue below must pass its
      // unlocked pre-checks on a valid device, then wait on the
      // ascending-UUID lock inside the trigger.
      await blocker.query("BEGIN");
      await blocker.query(`SELECT 1 FROM credential WHERE id = $1 FOR UPDATE`, [device]);
      const issuerPid = (await issuer.query(`SELECT pg_backend_pid() AS pid`)).rows[0].pid;

      const attempt = issuer.query(
        `INSERT INTO pairing_token
           (issued_by_credential_id, host_public_key, community_id, issued_at, policy_version, expires_at)
         VALUES ($1, $2, $3, '4000', 1, '604000')`,
        [device, "f0".repeat(32), community],
      );
      // Wait until the issue is blocked on the row lock.
      const deadline = Date.now() + 10000;
      for (;;) {
        const waiting = (await pool.query(
          `SELECT count(*)::int AS n FROM pg_stat_activity
           WHERE pid = $1 AND wait_event_type = 'Lock'`, [issuerPid])).rows[0].n;
        if (waiting === 1) break;
        if (Date.now() > deadline) throw new Error("issue never reached the row lock");
        await new Promise((r) => setTimeout(r, 25));
      }

      // Revoke the device while the issue waits, then release it into the
      // post-lock revalidation step.
      await blocker.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [device]);
      await blocker.query("COMMIT");

      await assert.rejects(attempt, (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        return message.includes("revoked under lock");
      });
      const count = (await pool.query(`SELECT count(*)::int AS n FROM pairing_token`)).rows[0].n;
      assert.equal(count, 0, "mid-issue revocation must land no row");
    } finally {
      blocker.release();
      issuer.release();
    }
  });
});

test("issued facts are immutable; consume is one-way; delete is refused", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { community, device } = await seedEligibleIssuer(pool, "life");
    const { insert, params } = insertToken("5000", "605000");
    const id = (await pool.query(insert, params(device, community))).rows[0].id;

    const otherDevice = (await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ((SELECT person_id FROM credential WHERE id = $1), $2, 'ed25519', 'human',
               (SELECT parent_credential_id FROM credential WHERE id = $1)) RETURNING id`,
      [device, "b".repeat(64)],
    )).rows[0].id;

    await expectReject(pool,
      `UPDATE pairing_token SET issued_by_credential_id = $2 WHERE id = $1`,
      [id, otherDevice], "immutable");
    await expectReject(pool,
      `UPDATE pairing_token SET host_public_key = $2 WHERE id = $1`,
      [id, "dd".repeat(32)], "immutable");
    await expectReject(pool,
      `UPDATE pairing_token SET issued_at = $2 WHERE id = $1`,
      [id, "5001"], "immutable");
    await expectReject(pool,
      `UPDATE pairing_token SET expires_at = $2 WHERE id = $1`,
      [id, "605001"], "immutable");

    const consumed = (await pool.query(
      `UPDATE pairing_token SET consumed_at = $2 WHERE id = $1 RETURNING consumed_at`,
      [id, "605000"],
    )).rows[0].consumed_at;
    assert.equal(String(consumed), "605000", "first consume transition must land");

    await expectReject(pool,
      `UPDATE pairing_token SET consumed_at = $2 WHERE id = $1`,
      [id, "605001"], "consumed");
    await expectReject(pool,
      `UPDATE pairing_token SET consumed_at = NULL WHERE id = $1`,
      [id], "consumed");

    await expectReject(pool,
      `DELETE FROM pairing_token WHERE id = $1`, [id], "may not be deleted");

    const count = (await pool.query(`SELECT count(*)::int AS n FROM pairing_token`)).rows[0].n;
    assert.equal(count, 1, "lifecycle operations must not remove the row");
  });
});

test("persistence operations write no audit row", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const before = (await pool.query(`SELECT count(*)::int AS n FROM audit_event`)).rows[0].n;
    const { community, device } = await seedEligibleIssuer(pool, "quiet");
    const { insert, params } = insertToken("7000", "607000");
    const id = (await pool.query(insert, params(device, community))).rows[0].id;
    await pool.query(`UPDATE pairing_token SET consumed_at = $2 WHERE id = $1`, [id, "607000"]);
    const after = (await pool.query(`SELECT count(*)::int AS n FROM audit_event`)).rows[0].n;
    assert.equal(after, before, "I2 persistence must not emit audit rows");
  });
});
