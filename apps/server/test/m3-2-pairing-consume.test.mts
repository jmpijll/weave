/**
 * Weave M3.2 I4.2 — locked token consume / host enroll (PostgreSQL 16).
 *
 * Requires DATABASE_URL pointing at a PostgreSQL 16 admin database; each
 * case runs in a disposable database with all migrations applied.
 */
import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { buildConsumeRecord, buildHostPossessionRecord, buildIssuanceRecord } from "@weave/protocol";
import { runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { issuePairingToken } from "../src/domain/pairing-issue.ts";
import { consumePairingToken } from "../src/domain/pairing-consume.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) {
  console.error(
    "m3-2 pairing consume: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL)",
  );
  process.exit(1);
}

let dbCounter = 0;
function swapDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

async function withFreshDatabase<T>(fn: (pool: pg.Pool, connectionString: string) => Promise<T>): Promise<T> {
  const admin = new Client({ connectionString: BASE_URL });
  await admin.connect();
  const database = `weave_i42_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
  } finally {
    await admin.end();
  }
  const connectionString = swapDatabase(BASE_URL, database);
  const pool = createDatabasePool(createDatabaseConfig(connectionString));
  try {
    await runMigrations(pool);
    return await fn(pool, connectionString);
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

function hexOf(publicKey: ReturnType<typeof generateKeyPairSync>["publicKey"]): string {
  const jwk = publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Ed25519 JWK x missing");
  return Buffer.from(jwk.x, "base64url").toString("hex");
}

interface IssuerSeed {
  community: string;
  person: string;
  root: string;
  device: string;
  member: string;
  deviceKey: ReturnType<typeof generateKeyPairSync>;
  devicePublicHex: string;
}

async function seedEligibleIssuer(pool: pg.Pool, tag: string): Promise<IssuerSeed> {
  const deviceKey = generateKeyPairSync("ed25519");
  const rootKey = generateKeyPairSync("ed25519");
  const devicePublicHex = hexOf(deviceKey.publicKey);
  const rootPublicHex = hexOf(rootKey.publicKey);
  const community = (
    await pool.query(`INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`, [
      `https://${tag}.example`,
      "I4.2 Test",
    ])
  ).rows[0].id as string;
  const person = (
    await pool.query(`INSERT INTO person (display_name) VALUES ($1) RETURNING id`, [`${tag}-owner`])
  ).rows[0].id as string;
  const root = (
    await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind) VALUES ($1, $2, 'ed25519', 'human') RETURNING id`,
      [person, rootPublicHex],
    )
  ).rows[0].id as string;
  const device = (
    await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
      [person, devicePublicHex, root],
    )
  ).rows[0].id as string;
  const member = (
    await pool.query(`INSERT INTO member (community_id, subject_kind, person_id) VALUES ($1, 'human', $2) RETURNING id`, [
      community,
      person,
    ])
  ).rows[0].id as string;
  return { community, person, root, device, member, deviceKey, devicePublicHex };
}

interface TokenSetup {
  seed: IssuerSeed;
  hostKey: ReturnType<typeof generateKeyPairSync>;
  hostPublic: string;
  stableId: string;
  issuedAt: string;
}

async function issueToken(pool: pg.Pool, tag: string, issuedAt?: string): Promise<TokenSetup> {
  const seed = await seedEligibleIssuer(pool, tag);
  const hostKey = generateKeyPairSync("ed25519");
  const hostPublic = hexOf(hostKey.publicKey);
  const stableId = randomUUID();
  const at = issuedAt ?? String(Date.now() - 1000);
  const issueFields = { stableId, hostPublic, community: seed.community, device: seed.device, issuedAt: at };
  const proof = sign(null, Buffer.from(buildIssuanceRecord(issueFields)), seed.deviceKey.privateKey).toString("hex");
  const issued = await issuePairingToken(pool, { ...issueFields, proof }, randomUUID());
  assert.deepEqual(issued, { ok: true, retry: false });
  return { seed, hostKey, hostPublic, stableId, issuedAt: at };
}

async function insertTokenDirect(
  pool: pg.Pool,
  seed: IssuerSeed,
  hostPublic: string,
  stableId: string,
  issuedAtMs: number,
): Promise<void> {
  // Raw insert satisfying the 0007 backstop (exact derivation, eligible
  // issuer): permits already-expired or nearly-expired rows the issue path
  // would never mint.
  await pool.query(
    `INSERT INTO pairing_token (id, issued_by_credential_id, host_public_key, community_id, issued_at, expires_at, policy_version)
     VALUES ($1, $2, $3, $4, $5, $6, 1)`,
    [stableId, seed.device, hostPublic, seed.community, String(issuedAtMs), String(issuedAtMs + 600_000)],
  );
}

async function expiredSetup(pool: pg.Pool, tag: string, ageMs: number): Promise<TokenSetup> {
  const seed = await seedEligibleIssuer(pool, tag);
  const hostKey = generateKeyPairSync("ed25519");
  const hostPublic = hexOf(hostKey.publicKey);
  const stableId = randomUUID();
  const issuedAt = String(Date.now() - ageMs);
  await insertTokenDirect(pool, seed, hostPublic, stableId, Date.now() - ageMs);
  return { seed, hostKey, hostPublic, stableId, issuedAt };
}

function signConsume(
  deviceKey: ReturnType<typeof generateKeyPairSync>,
  fields: { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string; consumeFreshness: string },
): string {
  return sign(null, Buffer.from(buildConsumeRecord(fields)), deviceKey.privateKey).toString("hex");
}

function signHost(
  hostKey: ReturnType<typeof generateKeyPairSync>,
  fields: { stableId: string; hostPublic: string; issuedAt: string },
): string {
  return sign(null, Buffer.from(buildHostPossessionRecord(fields)), hostKey.privateKey).toString("hex");
}

function validConsumeInput(setup: TokenSetup, overrides: Record<string, string> = {}) {
  const freshness = String(Date.now());
  const fields = {
    stableId: setup.stableId,
    hostPublic: setup.hostPublic,
    community: setup.seed.community,
    device: setup.seed.device,
    issuedAt: setup.issuedAt,
    consumeFreshness: freshness,
    ...overrides,
  };
  return {
    ...fields,
    ownerProof: signConsume(setup.seed.deviceKey, fields),
    hostProof: signHost(setup.hostKey, {
      stableId: fields.stableId,
      hostPublic: fields.hostPublic,
      issuedAt: fields.issuedAt,
    }),
  };
}

async function tokenState(pool: pg.Pool, stableId: string) {
  const r = await pool.query(
    `SELECT consumed_at FROM pairing_token WHERE id = $1`,
    [stableId],
  );
  return r.rows.length === 0 ? null : r.rows[0].consumed_at;
}

async function artifactCounts(pool: pg.Pool, stableId: string) {
  const hostCreds = Number(
    (await pool.query(`SELECT count(*)::text AS n FROM credential WHERE kind = 'host'`)).rows[0].n,
  );
  const hosts = Number((await pool.query(`SELECT count(*)::text AS n FROM host`)).rows[0].n);
  const audits = Number(
    (await pool.query(`SELECT count(*)::text AS n FROM audit_event WHERE event_type = 'host.enrolled'`)).rows[0].n,
  );
  void stableId;
  return { hostCreds, hosts, audits };
}

test("first consume commits token + host credential + host + exactly one audit", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "first");
    const input = validConsumeInput(setup);
    assert.deepEqual(await consumePairingToken(pool, input, randomUUID()), { ok: true });
    assert.notEqual(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 1, hosts: 1, audits: 1 });
    const audit = (await pool.query(`SELECT target_type, target_id, metadata::text AS metadata FROM audit_event WHERE event_type = 'host.enrolled'`)).rows[0];
    assert.equal(audit.target_type, "host");
    assert.match(audit.target_id as string, /^host\//);
    assert.equal(audit.metadata, "{}");
  });
});

test("unknown token refuses with no artifacts", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "unknown");
    const input = validConsumeInput(setup, { stableId: randomUUID() });
    assert.deepEqual(await consumePairingToken(pool, input, randomUUID()), { ok: false });
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("expired token refuses and stays pending", async () => {
  await withFreshDatabase(async (pool) => {
    // Token that already expired: issued 700s ago, 600s policy duration.
    const setup = await expiredSetup(pool, "expired", 700_000);
    const input = validConsumeInput(setup);
    assert.deepEqual(await consumePairingToken(pool, input, randomUUID()), { ok: false });
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("second consume of the same token refuses: exactly one winner", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "winner");
    const first = validConsumeInput(setup);
    assert.deepEqual(await consumePairingToken(pool, first, randomUUID()), { ok: true });
    const second = validConsumeInput(setup);
    assert.deepEqual(await consumePairingToken(pool, second, randomUUID()), { ok: false });
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 1, hosts: 1, audits: 1 });
  });
});

test("concurrent competing consumes yield exactly one winner", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "race");
    const a = validConsumeInput(setup);
    const b = validConsumeInput(setup);
    const [ra, rb] = await Promise.all([
      consumePairingToken(pool, a, randomUUID()),
      consumePairingToken(pool, b, randomUUID()),
    ]);
    assert.equal(Number(ra.ok) + Number(rb.ok), 1);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 1, hosts: 1, audits: 1 });
  });
});

test("every immutable binding swap refuses with token pending", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "swaps");
    const other = await seedEligibleIssuer(pool, "swaps-other");
    const otherHost = createHash("sha256").update(randomBytes(16)).digest("hex");
    const swaps: Record<string, Record<string, string>> = {
      hostPublic: { hostPublic: otherHost },
      community: { community: other.community },
      device: { device: other.device },
      issuedAt: { issuedAt: String(Date.now() - 2000) },
      consumeFreshness: { consumeFreshness: String(Date.now() - 500_000) },
    };
    for (const [name, override] of Object.entries(swaps)) {
      // Sign the swapped fields under the rightful keys so the swap itself —
      // not a proof mismatch — is what refuses (except consumeFreshness,
      // whose staleness refuses on the clock).
      const freshness = (override.consumeFreshness ?? String(Date.now()));
      const fields = {
        stableId: setup.stableId,
        hostPublic: setup.hostPublic,
        community: setup.seed.community,
        device: setup.seed.device,
        issuedAt: setup.issuedAt,
        consumeFreshness: freshness,
        ...override,
      };
      const input = {
        ...fields,
        ownerProof: signConsume(setup.seed.deviceKey, fields),
        hostProof: signHost(setup.hostKey, {
          stableId: fields.stableId,
          hostPublic: setup.hostPublic,
          issuedAt: setup.issuedAt,
        }),
      };
      assert.deepEqual(await consumePairingToken(pool, input, randomUUID()), { ok: false }, `swap ${name}`);
    }
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("stored-key proof authority: cross-key substitution refuses", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "proofs");
    const otherDevice = generateKeyPairSync("ed25519");
    const otherHost = generateKeyPairSync("ed25519");
    const base = validConsumeInput(setup);
    const fields = {
      stableId: base.stableId,
      hostPublic: base.hostPublic,
      community: base.community,
      device: base.device,
      issuedAt: base.issuedAt,
      consumeFreshness: base.consumeFreshness,
    };
    // Owner proof from a foreign device key.
    assert.deepEqual(
      await consumePairingToken(
        pool,
        { ...base, ownerProof: signConsume(otherDevice, fields) },
        randomUUID(),
      ),
      { ok: false },
    );
    // Host proof from a foreign host key.
    assert.deepEqual(
      await consumePairingToken(
        pool,
        {
          ...base,
          hostProof: sign(
            null,
            Buffer.from(
              buildHostPossessionRecord({ stableId: base.stableId, hostPublic: base.hostPublic, issuedAt: base.issuedAt }),
            ),
            otherHost.privateKey,
          ).toString("hex"),
        },
        randomUUID(),
      ),
      { ok: false },
    );
    // Garbage proofs.
    assert.deepEqual(await consumePairingToken(pool, { ...base, ownerProof: "cd".repeat(64) }, randomUUID()), { ok: false });
    assert.deepEqual(await consumePairingToken(pool, { ...base, hostProof: "ab".repeat(64) }, randomUUID()), { ok: false });
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("duplicate global host key rolls back and leaves the token pending", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "dupkey");
    // Occupy the token's host key globally under another person/root.
    const squatter = await seedEligibleIssuer(pool, "dupkey-squatter");
    await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1, $2, 'ed25519', 'host', $3)`,
      [squatter.person, setup.hostPublic, squatter.root],
    );
    const input = validConsumeInput(setup);
    assert.deepEqual(await consumePairingToken(pool, input, randomUUID()), { ok: false });
    assert.equal(await tokenState(pool, setup.stableId), null);
    const hosts = Number((await pool.query(`SELECT count(*)::text AS n FROM host`)).rows[0].n);
    const audits = Number(
      (await pool.query(`SELECT count(*)::text AS n FROM audit_event WHERE event_type = 'host.enrolled'`)).rows[0].n,
    );
    assert.equal(hosts, 0);
    assert.equal(audits, 0);
    // No partial host credential for the enrollee was left behind either:
    // only the squatter's pre-existing host credential exists.
    const hostCreds = Number(
      (await pool.query(`SELECT count(*)::text AS n FROM credential WHERE kind = 'host'`)).rows[0].n,
    );
    assert.equal(hostCreds, 1);
  });
});

test("audit failure rolls back consume, host credential, and host", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "auditfail");
    await pool.query(
      `CREATE OR REPLACE FUNCTION i42_raise() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'i42 audit fault'; END; $$ LANGUAGE plpgsql`,
    );
    await pool.query(`CREATE TRIGGER i42_raise_audit BEFORE INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION i42_raise()`);
    const input = validConsumeInput(setup);
    await assert.rejects(consumePairingToken(pool, input, randomUUID()));
    await pool.query(`DROP TRIGGER i42_raise_audit ON audit_event`);
    await pool.query(`DROP FUNCTION i42_raise()`);
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
    // The same authorized request succeeds once the fault is gone.
    const retry = validConsumeInput(setup);
    assert.deepEqual(await consumePairingToken(pool, retry, randomUUID()), { ok: true });
  });
});

test("no proof or body sentinel reaches the audit row", async () => {
  await withFreshDatabase(async (pool) => {
    const setup = await issueToken(pool, "sentinel");
    const input = validConsumeInput(setup);
    await consumePairingToken(pool, input, randomUUID());
    const rows = (
      await pool.query(`SELECT target_id, metadata::text AS metadata, correlation_id FROM audit_event WHERE event_type = 'host.enrolled'`)
    ).rows;
    assert.equal(rows.length, 1);
    const blob = JSON.stringify(rows[0]);
    assert.ok(!blob.includes(input.ownerProof.slice(0, 32)), "owner proof must not reach audit");
    assert.ok(!blob.includes(input.hostProof.slice(0, 32)), "host proof must not reach audit");
    assert.ok(!blob.includes(setup.hostPublic.slice(0, 32)), "host key must not reach audit");
    assert.ok(!blob.includes(setup.seed.devicePublicHex.slice(0, 32)), "device key must not reach audit");
  });
});

/** Wait until the given backend is blocked on a row lock. */
async function awaitRowLock(pool: pg.Pool, pid: unknown): Promise<void> {
  const deadline = Date.now() + 10000;
  for (;;) {
    const waiting = (
      await pool.query(
        `SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock'`,
        [pid],
      )
    ).rows[0].n as number;
    if (waiting === 1) return;
    if (Date.now() > deadline) throw new Error("consume never reached the row lock");
    await new Promise((r) => setTimeout(r, 25));
  }
}

test("invalid carrier refuses without acquiring or waiting on the token lock", async () => {
  await withFreshDatabase(async (pool, connectionString) => {
    const setup = await issueToken(pool, "nolockwait");
    const base = validConsumeInput(setup);
    const invalid = { ...base, ownerProof: "cd".repeat(64) };
    const consumePool = createDatabasePool(createDatabaseConfig(connectionString, 1));
    try {
      const blocker = await pool.connect();
      try {
        await blocker.query("BEGIN");
        await blocker.query(`SELECT 1 FROM pairing_token WHERE id = $1 FOR UPDATE`, [setup.stableId]);
        // The token lock is held by the blocker for the whole attempt: an
        // invalid carrier must refuse via the unlocked pre-check instead of
        // blocking on the lock.
        const attempt = consumePairingToken(consumePool, invalid, randomUUID());
        const result = await Promise.race([
          attempt.then((r) => ({ ...r, waited: false })),
          new Promise<{ ok: boolean; waited: boolean }>((resolve) =>
            setTimeout(() => resolve({ ok: false, waited: true }), 3000),
          ),
        ]);
        assert.deepEqual(result, { ok: false, waited: false });
        await blocker.query("COMMIT");
      } finally {
        blocker.release();
      }
    } finally {
      await consumePool.end();
    }
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("token-first lock: consume waits on a held token lock then succeeds", async () => {
  await withFreshDatabase(async (pool, connectionString) => {
    const setup = await issueToken(pool, "tokenlock");
    const input = validConsumeInput(setup);
    const consumePool = createDatabasePool(createDatabaseConfig(connectionString, 1));
    try {
      const pid = (await consumePool.query(`SELECT pg_backend_pid() AS pid`)).rows[0].pid;
      const blocker = await pool.connect();
      try {
        await blocker.query("BEGIN");
        await blocker.query(`SELECT 1 FROM pairing_token WHERE id = $1 FOR UPDATE`, [setup.stableId]);
        const attempt = consumePairingToken(consumePool, input, randomUUID());
        await awaitRowLock(pool, pid);
        await blocker.query("COMMIT");
        assert.deepEqual(await attempt, { ok: true });
      } finally {
        blocker.release();
      }
    } finally {
      await consumePool.end();
    }
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 1, hosts: 1, audits: 1 });
  });
});

test("expiry while waiting on the token lock refuses with token pending", async () => {
  await withFreshDatabase(async (pool, connectionString) => {
    // Token expiring ~2s from now: still valid at issue, expired after the wait.
    const setup = await expiredSetup(pool, "expirywait", 598_000);
    const consumePool = createDatabasePool(createDatabaseConfig(connectionString, 1));
    try {
      const pid = (await consumePool.query(`SELECT pg_backend_pid() AS pid`)).rows[0].pid;
      const blocker = await pool.connect();
      try {
        await blocker.query("BEGIN");
        await blocker.query(`SELECT 1 FROM pairing_token WHERE id = $1 FOR UPDATE`, [setup.stableId]);
        // Build the input now (fresh), then hold the lock past expiry.
        const input = validConsumeInput(setup);
        const attempt = consumePairingToken(consumePool, input, randomUUID());
        await awaitRowLock(pool, pid);
        await new Promise((r) => setTimeout(r, 3500));
        await blocker.query("COMMIT");
        assert.deepEqual(await attempt, { ok: false });
      } finally {
        blocker.release();
      }
    } finally {
      await consumePool.end();
    }
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("device revoked during consume lock-wait refuses with no artifacts", async () => {
  await withFreshDatabase(async (pool, connectionString) => {
    const setup = await issueToken(pool, "lockwait-device");
    const input = validConsumeInput(setup);
    const consumePool = createDatabasePool(createDatabaseConfig(connectionString, 1));
    try {
      const pid = (await consumePool.query(`SELECT pg_backend_pid() AS pid`)).rows[0].pid;
      const blocker = await pool.connect();
      try {
        await blocker.query("BEGIN");
        await blocker.query(`SELECT 1 FROM credential WHERE id = $1 FOR UPDATE`, [setup.seed.device]);
        const attempt = consumePairingToken(consumePool, input, randomUUID());
        await awaitRowLock(pool, pid);
        await blocker.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [setup.seed.device]);
        await blocker.query("COMMIT");
        assert.deepEqual(await attempt, { ok: false });
      } finally {
        blocker.release();
      }
    } finally {
      await consumePool.end();
    }
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("root revoked during consume lock-wait refuses with no artifacts", async () => {
  await withFreshDatabase(async (pool, connectionString) => {
    const setup = await issueToken(pool, "lockwait-root");
    const input = validConsumeInput(setup);
    const consumePool = createDatabasePool(createDatabaseConfig(connectionString, 1));
    try {
      const pid = (await consumePool.query(`SELECT pg_backend_pid() AS pid`)).rows[0].pid;
      const blocker = await pool.connect();
      try {
        await blocker.query("BEGIN");
        await blocker.query(`SELECT 1 FROM credential WHERE id = $1 FOR UPDATE`, [setup.seed.root]);
        const attempt = consumePairingToken(consumePool, input, randomUUID());
        await awaitRowLock(pool, pid);
        await blocker.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [setup.seed.root]);
        await blocker.query("COMMIT");
        assert.deepEqual(await attempt, { ok: false });
      } finally {
        blocker.release();
      }
    } finally {
      await consumePool.end();
    }
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});

test("member revoked during consume lock-wait refuses with no artifacts", async () => {
  await withFreshDatabase(async (pool, connectionString) => {
    const setup = await issueToken(pool, "lockwait-member");
    const input = validConsumeInput(setup);
    const consumePool = createDatabasePool(createDatabaseConfig(connectionString, 1));
    try {
      const pid = (await consumePool.query(`SELECT pg_backend_pid() AS pid`)).rows[0].pid;
      const blocker = await pool.connect();
      try {
        await blocker.query("BEGIN");
        await blocker.query(`SELECT 1 FROM member WHERE id = $1 FOR UPDATE`, [setup.seed.member]);
        const attempt = consumePairingToken(consumePool, input, randomUUID());
        await awaitRowLock(pool, pid);
        await blocker.query(`UPDATE member SET revoked_at = now() WHERE id = $1`, [setup.seed.member]);
        await blocker.query("COMMIT");
        assert.deepEqual(await attempt, { ok: false });
      } finally {
        blocker.release();
      }
    } finally {
      await consumePool.end();
    }
    assert.equal(await tokenState(pool, setup.stableId), null);
    assert.deepEqual(await artifactCounts(pool, setup.stableId), { hostCreds: 0, hosts: 0, audits: 0 });
  });
});
