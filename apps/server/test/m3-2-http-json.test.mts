/**
 * Weave M3.2 I4.1 — shared strict JSON helper + `POST /v1/pairing-tokens` HTTP.
 *
 * Proves the public response table, duplicate-key handling (plain and
 * escape-encoded), exact-shape enforcement, first/retry response equivalence,
 * fixed refusal families, redacted outcome logging, and that the recovery
 * route behavior is preserved through the shared helper.
 */
import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { buildIssuanceRecord } from "@weave/protocol";
import { createWeaveServer } from "../src/index.ts";
import type { LogFields } from "../src/log.ts";
import { runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { hasDuplicateRequiredKey } from "../src/http/json-body.ts";

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) {
  console.error("m3-2 http json: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16)");
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
  close: () => Promise<void>;
  logs: Array<{ event: string; fields: LogFields }>;
}

async function withLiveServer<T>(fn: (srv: LiveServer) => Promise<T>): Promise<T> {
  const admin = new Client({ connectionString: BASE_URL });
  await admin.connect();
  const database = `weave_i41http_${process.pid}_${randomBytes(3).toString("hex")}`;
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
    return await fn({
      base: `http://127.0.0.1:${port}`,
      pool,
      close: async () => {
        server.close();
        await pool.end();
      },
      logs,
    });
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
      `https://http-${randomBytes(4).toString("hex")}.example`,
      "HTTP Test",
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

function carrierBody(seed: { community: string; device: string; deviceKey: ReturnType<typeof generateKeyPairSync> }) {
  const fields = {
    stableId: randomUUID(),
    hostPublic: createHash("sha256").update(randomBytes(16)).digest("hex"),
    community: seed.community,
    device: seed.device,
    issuedAt: String(Date.now() - 1000),
  };
  const proof = sign(null, Buffer.from(buildIssuanceRecord(fields)), seed.deviceKey.privateKey).toString("hex");
  return { ...fields, proof };
}

async function post(base: string, path: string, init: RequestInit = {}) {
  return fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
    body: init.body as string | undefined,
  });
}

test("duplicate-key scanner decodes escapes before comparison", () => {
  const keys = ["stableId", "proof"] as const;
  assert.equal(hasDuplicateRequiredKey(`{"stableId":"a","stableId":"b"}`, keys), true);
  assert.equal(hasDuplicateRequiredKey(`{"stableId":"a","\\u0073tableId":"b"}`, keys), true);
  assert.equal(hasDuplicateRequiredKey(`{"stableId":"a","proof":"b"}`, keys), false);
  assert.equal(hasDuplicateRequiredKey(`{"a":1,"a":2}`, keys), false);
  assert.equal(hasDuplicateRequiredKey(`not json`, keys), false);
});

test("P1 failures return fixed 400 bad_request", async () => {
  await withLiveServer(async ({ base }) => {
    // Wrong method.
    const get = await fetch(`${base}/v1/pairing-tokens`);
    assert.equal(get.status, 400);
    assert.equal((await get.json() as { error: { code: string } }).error.code, "bad_request");
    // Wrong media.
    const media = await fetch(`${base}/v1/pairing-tokens`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "{}",
    });
    assert.equal(media.status, 400);
    // Invalid JSON.
    const bad = await post(base, "/v1/pairing-tokens", { body: "{oops" });
    assert.equal(bad.status, 400);
    // Oversize.
    const big = await post(base, "/v1/pairing-tokens", { body: `{"x":"${"y".repeat(9000)}"}` });
    assert.equal(big.status, 400);
    // Missing member.
    const missing = await post(base, "/v1/pairing-tokens", { body: `{"stableId":"x"}` });
    assert.equal(missing.status, 400);
    // Extra member.
    const extra = await post(base, "/v1/pairing-tokens", {
      body: JSON.stringify({ a: 1, stableId: randomUUID(), hostPublic: "a".repeat(64), community: randomUUID(), device: randomUUID(), issuedAt: "1", proof: "b".repeat(128), bonus: 2 }),
    });
    assert.equal(extra.status, 400);
  });
});

test("plain and escape-encoded duplicate keys return 400", async () => {
  await withLiveServer(async ({ base }) => {
    const seed = { community: randomUUID(), device: randomUUID(), deviceKey: generateKeyPairSync("ed25519") };
    const body = carrierBody(seed);
    const raw = JSON.stringify(body);
    const dupRaw = raw.replace(`"proof":`, `"proof":"${"0".repeat(128)}","proof":`);
    const dup = await post(base, "/v1/pairing-tokens", { body: dupRaw });
    assert.equal(dup.status, 400);
    assert.equal(((await dup.json()) as { error: { code: string } }).error.code, "bad_request");
    const dupEscaped = raw.replace(`"proof":`, `"\\u0070roof":"${"0".repeat(128)}","proof":`);
    const dup2 = await post(base, "/v1/pairing-tokens", { body: dupEscaped });
    assert.equal(dup2.status, 400);
  });
});

test("first issue and exact retry return equivalent accepted bodies", async () => {
  await withLiveServer(async ({ base, pool, logs }) => {
    const seed = await seedIssuer(pool);
    const body = carrierBody(seed);
    const first = await post(base, "/v1/pairing-tokens", { body: JSON.stringify(body) });
    assert.equal(first.status, 200);
    const firstJson = (await first.json()) as { status: string; requestId: string };
    assert.equal(firstJson.status, "accepted");
    assert.match(firstJson.requestId, /^[0-9a-f-]{36}$/);
    const second = await post(base, "/v1/pairing-tokens", { body: JSON.stringify(body) });
    assert.equal(second.status, 200);
    const secondJson = (await second.json()) as { status: string; requestId: string };
    assert.equal(secondJson.status, "accepted");
    assert.notEqual(secondJson.requestId, firstJson.requestId);
    // Byte-equivalent except the server-generated request ID.
    assert.equal(
      JSON.stringify({ ...secondJson, requestId: "X" }),
      JSON.stringify({ ...firstJson, requestId: "X" }),
    );
    // Refusal family: garbage proof is a fixed 401.
    const refused = await post(base, "/v1/pairing-tokens", {
      body: JSON.stringify({ ...body, stableId: randomUUID(), proof: "ab".repeat(64) }),
    });
    assert.equal(refused.status, 401);
    const refusedJson = (await refused.json()) as { error: { code: string; message: string } };
    assert.equal(refusedJson.error.code, "issuance_rejected");
    assert.equal(refusedJson.error.message, "issuance was not accepted");
    // No proof/body sentinel reaches captured outcome logs or accepted bodies.
    const blob = JSON.stringify(logs) + JSON.stringify(firstJson) + JSON.stringify(secondJson);
    assert.ok(!blob.includes(body.proof.slice(0, 32)), "proof must not reach logs/bodies");
    assert.ok(!blob.includes(body.hostPublic.slice(0, 32)), "host key must not reach logs/bodies");
    // Unknown /v1 path keeps the generic 404; recovery route keeps 400 behavior.
    const unknown = await fetch(`${base}/v1/nope`);
    assert.equal(unknown.status, 404);
    const recovery = await post(base, "/v1/identity/recovery/verify", { body: `{}` });
    assert.equal(recovery.status, 400);
    assert.equal(((await recovery.json()) as { error: { code: string } }).error.code, "bad_request");
  });
});

test("not-ready server returns redacted 503 without a request id", async () => {
  const server = createWeaveServer({ readiness: async () => false });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  try {
    const res = await post(`http://127.0.0.1:${port}`, "/v1/pairing-tokens", { body: `{}` });
    assert.equal(res.status, 503);
    assert.equal(res.headers.get("retry-after"), "1");
    assert.deepEqual(await res.json(), { status: "not_ready" });
  } finally {
    server.close();
  }
});
