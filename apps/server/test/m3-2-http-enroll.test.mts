/**
 * Weave M3.2 I4.2 — `POST /v1/hosts/enroll` HTTP response table.
 *
 * Proves P1 structural failures return fixed 400 bad_request, every expected
 * post-P1 refusal collapses to the single fixed 404 enroll_rejected relation,
 * an accepted enroll returns 200 accepted, and no proof/body/key sentinel
 * reaches outcome logs or envelopes.
 */
import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { buildConsumeRecord, buildHostPossessionRecord, buildIssuanceRecord } from "@weave/protocol";
import { createWeaveServer } from "../src/index.ts";
import type { LogFields } from "../src/log.ts";
import { runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { issuePairingToken } from "../src/domain/pairing-issue.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) {
  console.error("m3-2 http enroll: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16)");
  process.exit(1);
}

function swapDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

interface LiveServer {
  base: string;
  pool: pg.Pool;
  logs: Array<{ event: string; fields: LogFields }>;
}

async function withLiveServer<T>(fn: (srv: LiveServer) => Promise<T>): Promise<T> {
  const admin = new Client({ connectionString: BASE_URL });
  await admin.connect();
  const database = `weave_i42http_${process.pid}_${randomBytes(3).toString("hex")}`;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
  } finally {
    await admin.end();
  }
  const pool = createDatabasePool(createDatabaseConfig(swapDatabase(BASE_URL, database)));
  await runMigrations(pool);
  const logs: Array<{ event: string; fields: LogFields }> = [];
  const server = createWeaveServer({
    readiness: async () => true,
    pool,
    outcomeLogger: (event, fields) => {
      logs.push({ event, fields });
    },
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  try {
    return await fn({ base: `http://127.0.0.1:${port}`, pool, logs });
  } finally {
    server.close();
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

async function seedIssuer(pool: pg.Pool) {
  const deviceKey = generateKeyPairSync("ed25519");
  const rootKey = generateKeyPairSync("ed25519");
  const community = (
    await pool.query(`INSERT INTO community (canonical_tls_origin, name) VALUES ($1, $2) RETURNING id`, [
      `https://enroll-http-${randomBytes(4).toString("hex")}.example`,
      "Enroll HTTP Test",
    ])
  ).rows[0].id as string;
  const person = (await pool.query(`INSERT INTO person (display_name) VALUES ($1) RETURNING id`, ["owner"])).rows[0]
    .id as string;
  const root = (
    await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind) VALUES ($1, $2, 'ed25519', 'human') RETURNING id`, [
      person,
      hexOf(rootKey.publicKey),
    ])
  ).rows[0].id as string;
  const device = (
    await pool.query(
      `INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1, $2, 'ed25519', 'human', $3) RETURNING id`,
      [person, hexOf(deviceKey.publicKey), root],
    )
  ).rows[0].id as string;
  await pool.query(`INSERT INTO member (community_id, subject_kind, person_id) VALUES ($1, 'human', $2)`, [
    community,
    person,
  ]);
  return { community, device, deviceKey };
}

async function mintToken(pool: pg.Pool, seed: { community: string; device: string; deviceKey: ReturnType<typeof generateKeyPairSync> }) {
  const hostKey = generateKeyPairSync("ed25519");
  const hostPublic = hexOf(hostKey.publicKey);
  const issueFields = {
    stableId: randomUUID(),
    hostPublic,
    community: seed.community,
    device: seed.device,
    issuedAt: String(Date.now() - 1000),
  };
  const proof = sign(null, Buffer.from(buildIssuanceRecord(issueFields)), seed.deviceKey.privateKey).toString("hex");
  assert.deepEqual(await issuePairingToken(pool, { ...issueFields, proof }, randomUUID()), { ok: true, retry: false });
  return { hostKey, ...issueFields };
}

function enrollBody(
  token: { stableId: string; hostPublic: string; community: string; device: string; issuedAt: string },
  deviceKey: ReturnType<typeof generateKeyPairSync>,
  hostKey: ReturnType<typeof generateKeyPairSync>,
) {
  const fields = {
    stableId: token.stableId,
    hostPublic: token.hostPublic,
    community: token.community,
    device: token.device,
    issuedAt: token.issuedAt,
    consumeFreshness: String(Date.now()),
  };
  const ownerProof = sign(null, Buffer.from(buildConsumeRecord(fields)), deviceKey.privateKey).toString("hex");
  const hostProof = sign(
    null,
    Buffer.from(buildHostPossessionRecord({ stableId: token.stableId, hostPublic: token.hostPublic, issuedAt: token.issuedAt })),
    hostKey.privateKey,
  ).toString("hex");
  return { ...fields, ownerProof, hostProof };
}

async function post(base: string, path: string, init: RequestInit = {}) {
  return fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
    body: init.body as string | undefined,
  });
}

test("P1 failures return fixed 400 bad_request", async () => {
  await withLiveServer(async ({ base }) => {
    const get = await fetch(`${base}/v1/hosts/enroll`);
    assert.equal(get.status, 400);
    assert.equal((await get.json() as { error: { code: string } }).error.code, "bad_request");
    const media = await fetch(`${base}/v1/hosts/enroll`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "{}",
    });
    assert.equal(media.status, 400);
    const bad = await post(base, "/v1/hosts/enroll", { body: "{oops" });
    assert.equal(bad.status, 400);
    const missing = await post(base, "/v1/hosts/enroll", { body: `{"stableId":"x"}` });
    assert.equal(missing.status, 400);
    assert.equal(((await missing.json()) as { error: { code: string } }).error.code, "bad_request");
    const extra = await post(base, "/v1/hosts/enroll", {
      body: JSON.stringify({
        stableId: randomUUID(), hostPublic: "a".repeat(64), community: randomUUID(), device: randomUUID(),
        issuedAt: "1", consumeFreshness: "2", ownerProof: "c".repeat(128), hostProof: "d".repeat(128), bonus: 1,
      }),
    });
    assert.equal(extra.status, 400);
    // Duplicate required key (plain + escape-encoded) is P1.
    const dup = await post(base, "/v1/hosts/enroll", {
      body: `{"stableId":"${randomUUID()}","stableId":"${randomUUID()}"}`,
    });
    assert.equal(dup.status, 400);
  });
});

test("accepted enroll returns 200; all expected post-P1 failures collapse to fixed 404", async () => {
  await withLiveServer(async ({ base, pool, logs }) => {
    const seed = await seedIssuer(pool);
    const token = await mintToken(pool, seed);
    const body = enrollBody(token, seed.deviceKey, token.hostKey);
    const first = await post(base, "/v1/hosts/enroll", { body: JSON.stringify(body) });
    assert.equal(first.status, 200);
    const firstJson = (await first.json()) as { status: string; requestId: string };
    assert.equal(firstJson.status, "accepted");
    assert.match(firstJson.requestId, /^[0-9a-f-]{36}$/);

    // Replayed consume of the same token: consumed -> fixed 404.
    const replay = await post(base, "/v1/hosts/enroll", { body: JSON.stringify(enrollBody(token, seed.deviceKey, token.hostKey)) });
    assert.equal(replay.status, 404);
    assert.equal(((await replay.json()) as { error: { code: string; message: string } }).error.code, "enroll_rejected");

    // Unknown token: fixed 404.
    const ghost = await post(base, "/v1/hosts/enroll", {
      body: JSON.stringify({ ...body, stableId: randomUUID() }),
    });
    assert.equal(ghost.status, 404);

    // Garbage proofs: fixed 404, never 401/400.
    const badProof = await post(base, "/v1/hosts/enroll", {
      body: JSON.stringify({ ...body, stableId: randomUUID(), ownerProof: "ab".repeat(64), hostProof: "cd".repeat(64) }),
    });
    assert.equal(badProof.status, 404);
    assert.equal(((await badProof.json()) as { error: { code: string; message: string } }).error.message, "enrollment was not accepted");

    // No proof/body/key sentinel reaches captured outcome logs or envelopes.
    const blob = JSON.stringify(logs) + JSON.stringify(firstJson);
    assert.ok(!blob.includes(body.ownerProof.slice(0, 32)), "owner proof must not reach logs/bodies");
    assert.ok(!blob.includes(body.hostProof.slice(0, 32)), "host proof must not reach logs/bodies");
    assert.ok(!blob.includes(body.hostPublic.slice(0, 32)), "host key must not reach logs/bodies");
  });
});

test("injected audit failure returns redacted 503 with token left pending", async () => {
  await withLiveServer(async ({ base, pool }) => {
    const seed = await seedIssuer(pool);
    const token = await mintToken(pool, seed);
    await pool.query(
      `CREATE OR REPLACE FUNCTION i42http_raise() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'i42 http audit fault'; END; $$ LANGUAGE plpgsql`,
    );
    await pool.query(`CREATE TRIGGER i42http_raise_audit BEFORE INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION i42http_raise()`);
    const body = enrollBody(token, seed.deviceKey, token.hostKey);
    const res = await post(base, "/v1/hosts/enroll", { body: JSON.stringify(body) });
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "1");
    assert.deepEqual(await res.json(), { status: "not_ready" });
    await pool.query(`DROP TRIGGER i42http_raise_audit ON audit_event`);
    await pool.query(`DROP FUNCTION i42http_raise()`);
    // Rolled back: token pending, no host artifacts.
    const state = (await pool.query(`SELECT consumed_at FROM pairing_token WHERE id = $1`, [token.stableId])).rows[0];
    assert.equal(state.consumed_at, null);
    assert.equal(Number((await pool.query(`SELECT count(*)::text AS n FROM host`)).rows[0].n), 0);
    assert.equal(
      Number((await pool.query(`SELECT count(*)::text AS n FROM audit_event WHERE event_type = 'host.enrolled'`)).rows[0].n),
      0,
    );
    // Same request succeeds once the fault is gone.
    const retry = await post(base, "/v1/hosts/enroll", {
      body: JSON.stringify(enrollBody(token, seed.deviceKey, token.hostKey)),
    });
    assert.equal(retry.status, 200);
  });
});

test("not-ready server returns redacted 503 without a request id", async () => {
  const server = createWeaveServer({ readiness: async () => false });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  try {
    const res = await post(`http://127.0.0.1:${port}`, "/v1/hosts/enroll", { body: `{}` });
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "1");
    assert.deepEqual(await res.json(), { status: "not_ready" });
  } finally {
    server.close();
  }
});
