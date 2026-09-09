/**
 * Weave M3.2 I4.1 — proof-gated token issuance (PostgreSQL 16).
 *
 * Requires DATABASE_URL pointing at a PostgreSQL 16 admin database; each
 * case runs in a disposable database with all migrations applied.
 */
import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { buildIssuanceRecord } from "@weave/protocol";
import { runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { issuePairingToken } from "../src/domain/pairing-issue.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) {
  console.error(
    "m3-2 pairing issue: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL)",
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
  const database = `weave_i41_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
  } finally {
    await admin.end();
  }
  const pool = createDatabasePool(createDatabaseConfig(swapDatabase(BASE_URL, database)));
  try {
    await runMigrations(pool);
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
      "I4.1 Test",
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

function signIssuance(
  deviceKey: ReturnType<typeof generateKeyPairSync>,
  fields: { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string },
): string {
  const record = buildIssuanceRecord(fields);
  return sign(null, Buffer.from(record), deviceKey.privateKey).toString("hex");
}

function freshFields(seed: IssuerSeed, overrides: Record<string, string> = {}) {
  return {
    stableId: randomUUID(),
    hostPublic: createHash("sha256").update(randomBytes(16)).digest("hex"),
    community: seed.community,
    device: seed.device,
    issuedAt: String(Date.now() - 1000),
    ...overrides,
  };
}

async function tokenCount(pool: pg.Pool): Promise<number> {
  const r = await pool.query(`SELECT count(*)::text AS n FROM pairing_token`);
  return Number(r.rows[0].n);
}

async function auditCount(pool: pg.Pool, stableId?: string): Promise<number> {
  const r = stableId
    ? await pool.query(
        `SELECT count(*)::text AS n FROM audit_event WHERE event_type = 'pairing.token.issued' AND target_id = $1`,
        [`pairing_token/${stableId}`],
      )
    : await pool.query(
        `SELECT count(*)::text AS n FROM audit_event WHERE event_type = 'pairing.token.issued'`,
      );
  return Number(r.rows[0].n);
}

test("first issue commits one pending token and exactly one audit", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "first");
    const fields = freshFields(seed);
    const proof = signIssuance(seed.deviceKey, fields);
    const requestId = randomUUID();
    const result = await issuePairingToken(pool, { ...fields, proof }, requestId);
    assert.deepEqual(result, { ok: true, retry: false });
    assert.equal(await tokenCount(pool), 1);
    assert.equal(await auditCount(pool, fields.stableId), 1);
    const row = (await pool.query(`SELECT * FROM pairing_token WHERE id = $1`, [fields.stableId])).rows[0];
    assert.equal(row.consumed_at, null);
    assert.equal(String(row.host_public_key), fields.hostPublic);
    const audit = (
      await pool.query(
        `SELECT community_id, actor_person_id, actor_credential_id, actor_member_id, target_type, target_id, metadata, correlation_id FROM audit_event WHERE target_id = $1`,
        [`pairing_token/${fields.stableId}`],
      )
    ).rows[0];
    assert.equal(String(audit.community_id), seed.community);
    assert.equal(String(audit.actor_person_id), seed.person);
    assert.equal(String(audit.actor_credential_id), seed.device);
    assert.equal(String(audit.actor_member_id), seed.member);
    assert.equal(audit.target_type, "pairing_token");
    assert.deepEqual(audit.metadata, {});
    assert.equal(audit.correlation_id, requestId);
  });
});

test("exact retry accepts with no second row or audit", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "retry");
    const fields = freshFields(seed);
    const proof = signIssuance(seed.deviceKey, fields);
    const first = await issuePairingToken(pool, { ...fields, proof }, randomUUID());
    assert.deepEqual(first, { ok: true, retry: false });
    const second = await issuePairingToken(pool, { ...fields, proof }, randomUUID());
    assert.deepEqual(second, { ok: true, retry: true });
    assert.equal(await tokenCount(pool), 1);
    assert.equal(await auditCount(pool, fields.stableId), 1);
  });
});

test("non-exact same-ID claims are refused with no new audit", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "nonexact");
    const fields = freshFields(seed);
    const proof = signIssuance(seed.deviceKey, fields);
    assert.deepEqual((await issuePairingToken(pool, { ...fields, proof }, randomUUID())).ok, true);
    // Changed host key, freshly signed.
    const swapped = { ...fields, hostPublic: createHash("sha256").update("other").digest("hex") };
    const swappedProof = signIssuance(seed.deviceKey, swapped);
    assert.deepEqual(await issuePairingToken(pool, { ...swapped, proof: swappedProof }, randomUUID()), {
      ok: false,
    });
    // Changed issuedAt, freshly signed.
    const retimed = { ...fields, issuedAt: String(Date.now() - 2000) };
    const retimedProof = signIssuance(seed.deviceKey, retimed);
    assert.deepEqual(await issuePairingToken(pool, { ...retimed, proof: retimedProof }, randomUUID()), {
      ok: false,
    });
    assert.equal(await tokenCount(pool), 1);
    assert.equal(await auditCount(pool, fields.stableId), 1);
  });
});

test("proof substitution and key substitution are refused", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "proofsub");
    const fields = freshFields(seed);
    // Random garbage proof.
    assert.deepEqual(
      await issuePairingToken(pool, { ...fields, proof: "ab".repeat(64) }, randomUUID()),
      { ok: false },
    );
    // Proof signed by an unrelated key.
    const other = generateKeyPairSync("ed25519");
    const foreignProof = sign(null, Buffer.from(buildIssuanceRecord(fields)), other.privateKey).toString("hex");
    assert.deepEqual(await issuePairingToken(pool, { ...fields, proof: foreignProof }, randomUUID()), {
      ok: false,
    });
    assert.equal(await tokenCount(pool), 0);
    assert.equal(await auditCount(pool), 0);
  });
});

test("stale and future issue times are refused at the edges", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "time");
    const now = Date.now();
    const stale = freshFields(seed, { issuedAt: String(now - 130_000) });
    assert.deepEqual(
      await issuePairingToken(pool, { ...stale, proof: signIssuance(seed.deviceKey, stale) }, randomUUID()),
      { ok: false },
    );
    const future = freshFields(seed, { issuedAt: String(now + 40_000) });
    assert.deepEqual(
      await issuePairingToken(pool, { ...future, proof: signIssuance(seed.deviceKey, future) }, randomUUID()),
      { ok: false },
    );
    assert.equal(await tokenCount(pool), 0);
    assert.equal(await auditCount(pool), 0);
  });
});

test("expiry overflow is refused", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "overflow");
    // issuedAt chosen so issuedAt + 600000 exceeds the 2^53-1 ceiling.
    // Freshness also refuses this, but the refusal family is what matters.
    const fields = freshFields(seed, { issuedAt: "9007199254740991" });
    assert.deepEqual(
      await issuePairingToken(pool, { ...fields, proof: signIssuance(seed.deviceKey, fields) }, randomUUID()),
      { ok: false },
    );
    assert.equal(await tokenCount(pool), 0);
  });
});

test("revoked device, revoked root, revoked member, foreign community refuse", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "revoke");
    const attempt = async (tag: string) => {
      const fields = freshFields(seed, { stableId: randomUUID() });
      void tag;
      return issuePairingToken(pool, { ...fields, proof: signIssuance(seed.deviceKey, fields) }, randomUUID());
    };
    await pool.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [seed.device]);
    assert.deepEqual(await attempt("device"), { ok: false });
    await pool.query(`UPDATE credential SET revoked_at = NULL WHERE id = $1`, [seed.device]);
    await pool.query(`UPDATE credential SET revoked_at = now() WHERE id = $1`, [seed.root]);
    assert.deepEqual(await attempt("root"), { ok: false });
    await pool.query(`UPDATE credential SET revoked_at = NULL WHERE id = $1`, [seed.root]);
    await pool.query(`UPDATE member SET revoked_at = now() WHERE id = $1`, [seed.member]);
    assert.deepEqual(await attempt("member"), { ok: false });
    await pool.query(`UPDATE member SET revoked_at = NULL WHERE id = $1`, [seed.member]);
    // Foreign community with no membership.
    const foreign = (
      await pool.query(`INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`, [
        `https://foreign.example`,
        "Foreign",
      ])
    ).rows[0].id as string;
    const fields = freshFields(seed, { community: foreign });
    assert.deepEqual(
      await issuePairingToken(pool, { ...fields, proof: signIssuance(seed.deviceKey, fields) }, randomUUID()),
      { ok: false },
    );
    assert.equal(await tokenCount(pool), 0);
    assert.equal(await auditCount(pool), 0);
  });
});

test("host-kind credential as device is refused", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "hostkind");
    const hostKey = createHash("sha256").update("hostkind").digest("hex");
    const hostCred = (
      await pool.query(
        `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1, $2, 'ed25519', 'host', $3) RETURNING id`,
        [seed.person, hostKey, seed.root],
      )
    ).rows[0].id as string;
    const fields = freshFields(seed, { device: hostCred });
    const record = buildIssuanceRecord(fields);
    void record;
    // No valid signature exists for this shape under the device key; any proof refuses.
    assert.deepEqual(
      await issuePairingToken(pool, { ...fields, proof: "cd".repeat(64) }, randomUUID()),
      { ok: false },
    );
    assert.equal(await tokenCount(pool), 0);
  });
});

test("concurrent exact same-ID issues yield one row and one audit", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "race");
    const fields = freshFields(seed);
    const proof = signIssuance(seed.deviceKey, fields);
    const [a, b] = await Promise.all([
      issuePairingToken(pool, { ...fields, proof }, randomUUID()),
      issuePairingToken(pool, { ...fields, proof }, randomUUID()),
    ]);
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
    assert.equal(await tokenCount(pool), 1);
    assert.equal(await auditCount(pool, fields.stableId), 1);
  });
});

test("two independent issuers do not collide", async () => {
  await withFreshDatabase(async (pool) => {
    const seedA = await seedEligibleIssuer(pool, "conca");
    const seedB = await seedEligibleIssuer(pool, "concb");
    const fieldsA = freshFields(seedA);
    const fieldsB = freshFields(seedB);
    const [a, b] = await Promise.all([
      issuePairingToken(pool, { ...fieldsA, proof: signIssuance(seedA.deviceKey, fieldsA) }, randomUUID()),
      issuePairingToken(pool, { ...fieldsB, proof: signIssuance(seedB.deviceKey, fieldsB) }, randomUUID()),
    ]);
    assert.deepEqual(a, { ok: true, retry: false });
    assert.deepEqual(b, { ok: true, retry: false });
    assert.equal(await tokenCount(pool), 2);
    assert.equal(await auditCount(pool), 2);
  });
});

test("audit failure rolls back the new token", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "auditfail");
    // Force audit failure with a trigger that raises.
    await pool.query(
      `CREATE OR REPLACE FUNCTION i41_raise() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'i41 audit fault'; END; $$ LANGUAGE plpgsql`,
    );
    await pool.query(`CREATE TRIGGER i41_raise_audit BEFORE INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION i41_raise()`);
    const fields = freshFields(seed);
    await assert.rejects(issuePairingToken(pool, { ...fields, proof: signIssuance(seed.deviceKey, fields) }, randomUUID()));
    await pool.query(`DROP TRIGGER i41_raise_audit ON audit_event`);
    await pool.query(`DROP FUNCTION i41_raise()`);
    assert.equal(await tokenCount(pool), 0);
    assert.equal(await auditCount(pool), 0);
    // The same authorized request succeeds once the fault is gone.
    const retry = await issuePairingToken(pool, { ...fields, proof: signIssuance(seed.deviceKey, fields) }, randomUUID());
    assert.deepEqual(retry, { ok: true, retry: false });
  });
});

test("no proof or body sentinel reaches the audit row", async () => {
  await withFreshDatabase(async (pool) => {
    const seed = await seedEligibleIssuer(pool, "sentinel");
    const fields = freshFields(seed);
    const proof = signIssuance(seed.deviceKey, fields);
    await issuePairingToken(pool, { ...fields, proof }, randomUUID());
    const rows = (
      await pool.query(`SELECT target_id, metadata::text AS metadata, correlation_id FROM audit_event`)
    ).rows;
    assert.equal(rows.length, 1);
    const blob = JSON.stringify(rows[0]);
    assert.ok(!blob.includes(proof.slice(0, 32)), "proof must not reach audit");
    assert.ok(!blob.includes(seed.devicePublicHex.slice(0, 32)), "device key must not reach audit");
    assert.ok(!blob.includes(fields.hostPublic.slice(0, 32)), "host key must not reach audit");
  });
});
