import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import http from "node:http";
import type { ClientRequest } from "node:http";
import { createWeaveServer } from "../src/index.ts";
import type { ServerOptions, TestOnlyV1Operation } from "../src/index.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { runMigrations } from "../src/db/migrate.ts";
import {
  buildRecoveryTranscript,
  decodeLowerHexEd25519Key,
  decodeLowerHexEd25519Signature,
} from "@weave/protocol";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const { Client } = pg;

const BASE_URL = process.env.DATABASE_URL ?? "";

if (!BASE_URL) {
  console.error(
    "m1-3-2 recovery verify: FAIL (DATABASE_URL not set; start a disposable PostgreSQL 16 and set DATABASE_URL — the M1.3.2 app-boundary negative suite is mandatory)",
  );
  process.exit(1);
}

const ENVIRONMENT_CODE = 4;
const DOMAIN = "weave/recovery/proof";

let dbCounter = 0;
function swapDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

async function withFreshDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T> {
  const admin = new Client({ connectionString: BASE_URL });
  await admin.connect();
  const database = `weave_m132_test_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
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

interface EdKeypair {
  privateKey: KeyObject;
  publicHex: string;
}

function makeKeypair(): EdKeypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  return { privateKey, publicHex: Buffer.from(jwk.x as string, "base64url").toString("hex") };
}

function signEd25519(privateKey: KeyObject, data: Buffer): string {
  return sign(null, data, privateKey).toString("hex");
}

interface SeededRequest {
  body: Record<string, unknown>;
  transcript: Buffer;
  root: EdKeypair;
  verifier: EdKeypair;
  challenge: {
    id: string;
    person: string;
    verifier: string;
    community: string;
    tlsOrigin: string;
    nonceHex: string;
    deviceHex: string;
    expiryMs: number;
  };
}

const FIXED = {
  person: "00112233-4455-6677-8899-aabbccddeeff",
  verifier: "10213243-5465-7687-98a9-bacbdcedfe0f",
  community: "11111111-2222-3333-4444-555555555555",
  challenge: "abcdefab-cdef-4abc-8def-abcdefabcdef",
  tlsOrigin: "wss://verify.example:8443",
  nonceHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  deviceHex: "9f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
  expiry: 2593440000000,
};

function fixedChallenge(): SeededRequest["challenge"] {
  return {
    id: FIXED.challenge,
    person: FIXED.person,
    verifier: FIXED.verifier,
    community: FIXED.community,
    tlsOrigin: FIXED.tlsOrigin,
    nonceHex: FIXED.nonceHex,
    deviceHex: FIXED.deviceHex,
    expiryMs: FIXED.expiry,
  };
}

function buildBody(ch: SeededRequest["challenge"], rootSig: string, proofSig: string): Record<string, unknown> {
  return {
    challengeId: ch.id,
    personId: ch.person,
    recoveryVerifierId: ch.verifier,
    communityId: ch.community,
    protocolVersion: 1,
    schemeVersion: 1,
    algorithmCode: 1,
    environmentCode: ENVIRONMENT_CODE,
    tlsOrigin: ch.tlsOrigin,
    nonce: ch.nonceHex,
    intendedDevicePublicKey: ch.deviceHex,
    canonicalTranscript: buildTranscript(ch).toString("hex"),
    rootSignature: rootSig,
    recoveryProofSignature: proofSig,
  };
}

function buildTranscript(ch: SeededRequest["challenge"]): Buffer {
  return buildRecoveryTranscript({
    domain: DOMAIN,
    protocolVersion: 1,
    schemeVersion: 1,
    environmentCode: ENVIRONMENT_CODE,
    signatureAlgorithmCode: 1,
    tlsOrigin: ch.tlsOrigin,
    personId: ch.person,
    recoveryVerifierId: ch.verifier,
    communityId: ch.community,
    challengeId: ch.id,
    nonce: decodeLowerHexEd25519Key(ch.nonceHex) as Uint8Array,
    intendedDevicePublicKey: decodeLowerHexEd25519Key(ch.deviceHex) as Uint8Array,
    expiryUnixMs: ch.expiryMs,
  });
}

interface SeedOptions {
  community?: boolean;
  person?: boolean;
  rootRevoked?: boolean;
  verifierRevoked?: boolean;
  challengeConsumed?: boolean;
  challengeExpired?: boolean;
  rootOverride?: string; // a different root public hex, with no matching credential unless seeded
}

async function seedSetup(pool: pg.Pool, options: SeedOptions = {}): Promise<SeededRequest> {
  const root = makeKeypair();
  const verifier = makeKeypair();
  const ch = fixedChallenge();
  // For the expired state the transcript must be signed over the same (past)
  // expiry the db stores, so the transcript matches before the state check.
  if (options.challengeExpired) ch.expiryMs = Date.now() - 60_000;

  await pool.query(
    `INSERT INTO community (id, canonical_tls_origin, name) VALUES ($1, $2, $3)`,
    [ch.community, "https://community.example", "m132 community"],
  );
  await pool.query(`INSERT INTO person (id, display_name) VALUES ($1, $2)`, [ch.person, "m132 user"]);

  await pool.query(
    `INSERT INTO credential (id, person_id, public_key, algorithm, kind, parent_credential_id, revoked_at)
     VALUES ($1, $2, $3, 'ed25519', 'human', NULL, $4)`,
    [randomUUID(), ch.person, root.publicHex, options.rootRevoked ? new Date() : null],
  );

  await pool.query(
    `INSERT INTO recovery_verifier (id, person_id, community_id, public_key, environment_code, revoked_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [ch.verifier, ch.person, ch.community, verifier.publicHex, ENVIRONMENT_CODE, options.verifierRevoked ? new Date() : null],
  );

  const expiresAt = options.challengeExpired ? new Date(ch.expiryMs) : new Date(ch.expiryMs);
  const consumedAt = options.challengeConsumed ? new Date() : null;
  await pool.query(
    `INSERT INTO recovery_challenge
       (id, verifier_id, person_id, community_id, canonical_tls_origin, nonce,
        intended_device_public_key, environment_code, expires_at, consumed_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      ch.id,
      ch.verifier,
      ch.person,
      ch.community,
      ch.tlsOrigin,
      Buffer.from(ch.nonceHex, "hex"),
      ch.deviceHex,
      ENVIRONMENT_CODE,
      expiresAt,
      consumedAt,
    ],
  );

  const transcript = buildTranscript(ch);
  const body = buildBody(ch, signEd25519(root.privateKey, transcript), signEd25519(verifier.privateKey, transcript));
  return { body, transcript, root, verifier, challenge: ch };
}

async function snapshot(pool: pg.Pool): Promise<Record<string, number>> {
  const tables = [
    "community",
    "person",
    "recovery_challenge",
    "recovery_verifier",
    "credential",
    "audit_event",
    "member",
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
    assert.equal(after[table], before[table], `table ${table} must be unchanged after a verify attempt`);
  }
}

async function withServer<T>(
  pool: pg.Pool,
  fn: (base: string) => Promise<T>,
  admission?: { maxInFlight: number; bodyDeadlineMs: number },
  readiness?: () => Promise<boolean>,
  boundaryOptions: Pick<ServerOptions, "outcomeLogger" | "testOnlyV1Operations"> = {},
): Promise<T> {
  const server = createWeaveServer({
    pool,
    readiness: readiness ?? (async () => true),
    admission,
    ...boundaryOptions,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

async function post(base: string, path: string, body: unknown, headers: Record<string, string> = {}) {
  // A Buffer/Uint8Array (e.g. an invalid-UTF-8 raw body) must be sent as raw
  // bytes, never JSON-stringified into valid `{type,data}` text.
  const payload = body instanceof Uint8Array || typeof body === "string" ? body : JSON.stringify(body);
  return await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: payload as BodyInit,
  });
}

function portOf(base: string): number {
  const url = new URL(base);
  return Number(url.port);
}

/**
 * Open a request that sends the headers and a partial body but never `end`s, so
 * the server's bounded body read holds its admission slot until the deadline or
 * until the client aborts. Resolves with the server's eventual response (for a
 * deadline the server responds after `bodyDeadlineMs`; for saturation the
 * client must abort to release the slot).
 */
function openRawRequest(
  base: string,
  opts?: { method?: string; contentType?: string; partialBody?: string },
): {
  req: ClientRequest;
  response: Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }>;
} {
  const req = http.request({
    hostname: "127.0.0.1",
    port: portOf(base),
    method: opts?.method ?? "POST",
    path: "/v1/identity/recovery/verify",
    headers: { "content-type": opts?.contentType ?? "application/json" },
  });
  const response = new Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }>((resolve, reject) => {
    req.on("response", (res) => {
      let raw = "";
      res.on("data", (chunk) => {
        raw += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: raw, headers: res.headers }));
      res.on("error", reject);
    });
    req.on("error", reject);
  });
  req.flushHeaders();
  req.write(opts?.partialBody ?? '{"protocolVersion":');
  return { req, response };
}

function openPartialRequest(base: string): {
  req: ClientRequest;
  response: Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }>;
} {
  return openRawRequest(base);
}

type CapturedLog = Record<string, unknown>;

async function captureLogs<T>(fn: () => Promise<T>): Promise<{ value: T; logs: CapturedLog[] }> {
  const original = console.log;
  const lines: string[] = [];
  console.log = (...values: unknown[]) => {
    if (values.length === 1 && typeof values[0] === "string") lines.push(values[0]);
  };
  try {
    const value = await fn();
    const logs = lines.map((line) => JSON.parse(line) as CapturedLog);
    return { value, logs };
  } finally {
    console.log = original;
  }
}

function events(logs: CapturedLog[], event: string): CapturedLog[] {
  return logs.filter((entry) => entry.event === event);
}

function recordOutcomes(logs: CapturedLog[]): NonNullable<ServerOptions["outcomeLogger"]> {
  return (event, fields) => logs.push({ event, ...fields });
}

function assertS8LogShape(event: CapturedLog, requestId: string): void {
  assert.deepEqual(Object.keys(event).sort(), ["durationMs", "event", "outcome", "requestId", "route", "status"]);
  assert.equal(event.requestId, requestId);
  assert.equal(typeof event.durationMs, "number");
}

function assertTransportLogShape(event: CapturedLog): void {
  assert.deepEqual(Object.keys(event).sort(), ["correlationId", "durationMs", "event", "outcome", "retryAfter", "route", "status"]);
  assert.equal(event.status, 503);
  assert.equal(event.retryAfter, "1");
  assert.ok(typeof event.correlationId === "string" && event.correlationId.length > 0);
  assert.equal(typeof event.durationMs, "number");
}

// ---------------------------------------------------------------------------
// Positive conformance against the published public vector (public subset only:
// challenge values, canonical transcript, both signatures, both public keys).
// No phrase / entropy / seed / private key is imported into runtime or tests.
// ---------------------------------------------------------------------------
test("published public vector: 200 verified, transcript round-trips, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const vector = {
      person: "00112233-4455-6677-8899-aabbccddeeff",
      verifier: "10213243-5465-7687-98a9-bacbdcedfe0f",
      community: "11111111-2222-3333-4444-555555555555",
      challenge: "abcdefab-cdef-4abc-8def-abcdefabcdef",
      tlsOrigin: "wss://recovery-poc.invalid:8443",
      nonceHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      deviceHex: "9f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
      expiryMs: 1893456000000,
      rootPublic: "3b78e104fc84de1dcebad27385d47c99fbe24f167ef6390304e2c08fb36463b1",
      verifierPublic: "2e7527137152878e7a6bced5d3a30b1e0d4bd1f705173fa7b026779e4cc76640",
      canonicalTranscript:
        "001477656176652f7265636f766572792f70726f6f66000100010401001f7773733a2f2f7265636f766572792d706f632e696e76616c69643a3834343300112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f11111111222233334444555555555555abcdefabcdef4abc8defabcdefabcdef000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f9f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f000001b8dac5b400",
      rootSignature:
        "da937dad825ec65e4fc2253dd34d5d30138d73d2f71f4f445a18832be937a9a5f44571b56236df4c26316fd770681073b5e59e782cc536f6d033423b6e96340d",
      proofSignature:
        "4f39c0d6b74db27ca79c717a930b9a966911721827e5bbaa61d8398a52545ccfec6ba99eee20e868c4218eb87c0d89ab303a25ad2966ca0e86661922754fbb05",
    };

    await pool.query(`INSERT INTO community (id, canonical_tls_origin, name) VALUES ($1, $2, $3)`, [
      vector.community,
      "https://vector.example",
      "vector community",
    ]);
    await pool.query(`INSERT INTO person (id, display_name) VALUES ($1, $2)`, [vector.person, "vector user"]);
    await pool.query(
      `INSERT INTO credential (id, person_id, public_key, algorithm, kind, parent_credential_id)
       VALUES ($1, $2, $3, 'ed25519', 'human', NULL)`,
      [randomUUID(), vector.person, vector.rootPublic],
    );
    await pool.query(
      `INSERT INTO recovery_verifier (id, person_id, community_id, public_key, environment_code)
       VALUES ($1, $2, $3, $4, 4)`,
      [vector.verifier, vector.person, vector.community, vector.verifierPublic],
    );
    await pool.query(
      `INSERT INTO recovery_challenge
         (id, verifier_id, person_id, community_id, canonical_tls_origin, nonce,
          intended_device_public_key, environment_code, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 4, $8)`,
      [
        vector.challenge,
        vector.verifier,
        vector.person,
        vector.community,
        vector.tlsOrigin,
        Buffer.from(vector.nonceHex, "hex"),
        vector.deviceHex,
        new Date(vector.expiryMs),
      ],
    );

    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const body = buildBody(
        {
          id: vector.challenge,
          person: vector.person,
          verifier: vector.verifier,
          community: vector.community,
          tlsOrigin: vector.tlsOrigin,
          nonceHex: vector.nonceHex,
          deviceHex: vector.deviceHex,
          expiryMs: vector.expiryMs,
        },
        vector.rootSignature,
        vector.proofSignature,
      );
      // The client-built transcript must equal the published canonical hex.
      assert.equal(body.canonicalTranscript, vector.canonicalTranscript);
      const res = await post(base, "/v1/identity/recovery/verify", body);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("content-type"), "application/json; charset=utf-8");
      const json = (await res.json()) as { status: string; requestId: string };
      assert.equal(json.status, "verified");
      assert.ok(typeof json.requestId === "string" && json.requestId.length > 0);
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// POST-only and media-type handling.
// ---------------------------------------------------------------------------
test("non-POST method to the verify path is bad_request 400, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const res = await fetch(`${base}/v1/identity/recovery/verify`, { method: "GET" });
      assert.equal(res.status, 400);
      const json = (await res.json()) as { error: { code: string } };
      assert.equal(json.error.code, "bad_request");
      assert.equal(res.headers.get("content-type"), "application/json; charset=utf-8");
    });
    await assertZeroMutation(pool, before);
  });
});

test("missing or wrong media type is bad_request 400, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const wrong = await post(base, "/v1/identity/recovery/verify", body, { "content-type": "text/plain" });
      assert.equal(wrong.status, 400);
      assert.equal(((await wrong.json()) as { error: { code: string } }).error.code, "bad_request");

      const missing = await fetch(`${base}/v1/identity/recovery/verify`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      assert.equal(missing.status, 400);
      assert.equal(((await missing.json()) as { error: { code: string } }).error.code, "bad_request");
    });
    await assertZeroMutation(pool, before);
  });
});

test("bodies larger than 8 KiB raw bytes are bad_request 400 (8 KiB bound), zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const oversized = JSON.stringify({ ...body, padding: "x".repeat(9000) });
      assert.ok(Buffer.byteLength(oversized) > 8192);
      const res = await post(base, "/v1/identity/recovery/verify", oversized);
      assert.equal(res.status, 400);
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, "bad_request");
    });
    await assertZeroMutation(pool, before);
  });
});

test("a body of exactly 8,192 raw UTF-8 bytes is accepted (limit is inclusive), zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const baseJson = JSON.stringify(body);
      // Pad with insignificant trailing whitespace so the raw body is exactly 8,192 bytes.
      const exact = baseJson + " ".repeat(8192 - Buffer.byteLength(baseJson));
      assert.equal(Buffer.byteLength(exact), 8192);
      const res = await post(base, "/v1/identity/recovery/verify", exact);
      assert.equal(res.status, 200);
      assert.equal(((await res.json()) as { status: string }).status, "verified");
    });
    await assertZeroMutation(pool, before);
  });
});

test("a body of exactly 8,193 raw UTF-8 bytes is refused (boundary is exclusive), zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const baseJson = JSON.stringify(body);
      const over = baseJson + " ".repeat(8193 - Buffer.byteLength(baseJson));
      assert.equal(Buffer.byteLength(over), 8193);
      const res = await post(base, "/v1/identity/recovery/verify", over);
      assert.equal(res.status, 400);
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, "bad_request");
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Format guards (F6): unsupported protocol / algorithm / environment; bad scheme.
// ---------------------------------------------------------------------------
test("unsupported protocol/algorithm/environment and invalid scheme are bad_request 400, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ protocolVersion: 2 }, "unsupported_protocol_version"],
      [{ algorithmCode: 2 }, "unsupported_algorithm"],
      [{ environmentCode: 9 }, "unsupported_environment"],
      [{ schemeVersion: 2 }, "bad_request"],
      [{ protocolVersion: "not-a-number" }, "bad_request"],
    ];
    await withServer(pool, async (base) => {
      for (const [overrides, expected] of cases) {
        const mutated = { ...body, ...overrides };
        const res = await post(base, "/v1/identity/recovery/verify", mutated);
        assert.equal(res.status, 400);
        assert.equal(((await res.json()) as { error: { code: string } }).error.code, expected);
      }
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Structural validation: strict lower-hex malformed => bad_request 400.
// ---------------------------------------------------------------------------
test("non-lower-hex or wrong-length key/signature/transcript reject as bad_request 400, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body, transcript } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const mutated: Array<Record<string, unknown>> = [
        { ...body, nonce: (body.nonce as string).toUpperCase() },
        { ...body, intendedDevicePublicKey: (body.intendedDevicePublicKey as string).toUpperCase() },
        { ...body, canonicalTranscript: (body.canonicalTranscript as string).slice(0, -1) }, // odd length
        { ...body, canonicalTranscript: (body.canonicalTranscript as string).toUpperCase() },
        { ...body, rootSignature: (body.rootSignature as string).toUpperCase() },
        { ...body, recoveryProofSignature: (body.recoveryProofSignature as string).slice(1) }, // wrong length
        { ...body, challengeId: "not-a-uuid" },
        { ...body, tlsOrigin: "https://not-wss.example" },
      ];
      const transcriptBytes = transcript.toString("hex");
      for (const m of mutated) {
        const res = await post(base, "/v1/identity/recovery/verify", m);
        assert.equal(res.status, 400);
        assert.equal(((await res.json()) as { error: { code: string } }).error.code, "bad_request");
      }
      // sanity: unchanged body still verified
      const ok = await post(base, "/v1/identity/recovery/verify", body);
      assert.equal(ok.status, 200);
      assert.equal(transcriptBytes, body.canonicalTranscript);
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Missing vs malformed signature (proof_missing 401 vs bad_request 400).
// ---------------------------------------------------------------------------
test("absent signature is proof_missing 401; present-but-malformed or null is bad_request 400, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const absentRoot = { ...body };
      delete absentRoot.rootSignature;
      const r1 = await post(base, "/v1/identity/recovery/verify", absentRoot);
      assert.equal(r1.status, 401);
      assert.equal(((await r1.json()) as { error: { code: string } }).error.code, "proof_missing");

      const absentProof = { ...body, recoveryProofSignature: undefined };
      const r2 = await post(base, "/v1/identity/recovery/verify", absentProof);
      assert.equal(r2.status, 401);
      assert.equal(((await r2.json()) as { error: { code: string } }).error.code, "proof_missing");

      // Present-but-null is malformed, NOT missing: bad_request 400.
      const nullRoot = { ...body, rootSignature: null };
      const r3 = await post(base, "/v1/identity/recovery/verify", nullRoot);
      assert.equal(r3.status, 400);
      assert.equal(((await r3.json()) as { error: { code: string } }).error.code, "bad_request");

      const nullProof = { ...body, recoveryProofSignature: null };
      const r4 = await post(base, "/v1/identity/recovery/verify", nullProof);
      assert.equal(r4.status, 400);
      assert.equal(((await r4.json()) as { error: { code: string } }).error.code, "bad_request");
    });
    await assertZeroMutation(pool, before);
  });
});

test("invalid UTF-8 raw JSON body is bad_request 400, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      // A valid-JSON ASCII prefix followed by an invalid UTF-8 byte sequence.
      const invalid = Buffer.concat([Buffer.from('{"protocolVersion":'), Buffer.from([0xc3, 0x28]), Buffer.from('}')]);
      // The fatal decoder genuinely rejects the sequence (this must not be
      // asserted inline, where it would throw before the HTTP request).
      assert.throws(() => new TextDecoder("utf-8", { fatal: true }).decode(invalid));
      const res = await post(base, "/v1/identity/recovery/verify", invalid);
      assert.equal(res.status, 400);
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, "bad_request");
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Binding substitution => collapsed binding_mismatch 401 (N4 single code).
// ---------------------------------------------------------------------------
test("any substituted bound value is binding_mismatch 401, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const cases: Array<Record<string, unknown>> = [
        { ...body, personId: randomUUID() },
        { ...body, communityId: randomUUID() },
        { ...body, recoveryVerifierId: randomUUID() },
        { ...body, tlsOrigin: "wss://other.example:8443" },
        { ...body, intendedDevicePublicKey: "a".repeat(64) },
        // A well-formed but wrong nonce (valid 64 lower-hex, decodes to 32 bytes)
        // — must be binding_mismatch, not bad_request, and the proofs still verify
        // over the unchanged supplied transcript.
        { ...body, nonce: "c".repeat(64) },
        { ...body, protocolVersion: 1, environmentCode: 3 }, // env differs from stored row
      ];
      for (const m of cases) {
        const res = await post(base, "/v1/identity/recovery/verify", m);
        assert.equal(res.status, 401);
        assert.equal(((await res.json()) as { error: { code: string } }).error.code, "binding_mismatch");
      }
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// transcript_invalid vs proof_invalid distinction.
// ---------------------------------------------------------------------------
test("transcript_invalid needs both signatures valid over the altered transcript; tampered/stale proofs are proof_invalid 401, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body, root, verifier, challenge: ch } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      // UNDER THE PROOF-FIRST ORDER: signatures are verified over the supplied
      // transcript BEFORE any binding result. A transcript altered in isolation
      // (flipped byte) keeps the ORIGINAL signatures, so the proofs fail and the
      // request is `proof_invalid` — NOT `transcript_invalid`.
      const flipped = Buffer.from(body.canonicalTranscript as string, "hex");
      flipped[10] ^= 0xff;
      const staleProofs = { ...body, canonicalTranscript: flipped.toString("hex") };
      const r1 = await post(base, "/v1/identity/recovery/verify", staleProofs);
      assert.equal(r1.status, 401);
      assert.equal(((await r1.json()) as { error: { code: string } }).error.code, "proof_invalid");

      // A `transcript_invalid` requires BOTH signatures to verify over the
      // supplied transcript while the rebuilt bytes differ. Build a transcript
      // with a different expiry and re-sign it with the real root/verifier keys;
      // the request bindings remain unchanged, so proofs pass and the rebuilt S9
      // (from the stored expiry) differs -> `transcript_invalid`.
      const altExpiry = ch.expiryMs + 1;
      const alt = buildRecoveryTranscript({
        domain: DOMAIN,
        protocolVersion: 1,
        schemeVersion: 1,
        environmentCode: ENVIRONMENT_CODE,
        signatureAlgorithmCode: 1,
        tlsOrigin: ch.tlsOrigin,
        personId: ch.person,
        recoveryVerifierId: ch.verifier,
        communityId: ch.community,
        challengeId: ch.id,
        nonce: decodeLowerHexEd25519Key(ch.nonceHex) as Uint8Array,
        intendedDevicePublicKey: decodeLowerHexEd25519Key(ch.deviceHex) as Uint8Array,
        expiryUnixMs: altExpiry,
      });
      const transcriptInvalid = {
        ...body,
        canonicalTranscript: alt.toString("hex"),
        rootSignature: signEd25519(root.privateKey, alt),
        recoveryProofSignature: signEd25519(verifier.privateKey, alt),
      };
      const r2 = await post(base, "/v1/identity/recovery/verify", transcriptInvalid);
      assert.equal(r2.status, 401);
      assert.equal(((await r2.json()) as { error: { code: string } }).error.code, "transcript_invalid");

      // Tamper the root signature (valid 128 lower-hex) over the exact transcript.
      const sig = Buffer.from(body.rootSignature as string, "hex");
      sig[0] ^= 0xff;
      const proofInvalid = { ...body, rootSignature: sig.toString("hex") };
      const r3 = await post(base, "/v1/identity/recovery/verify", proofInvalid);
      assert.equal(r3.status, 401);
      assert.equal(((await r3.json()) as { error: { code: string } }).error.code, "proof_invalid");

      // Tamper the recovery proof signature.
      const proofSig = Buffer.from(body.recoveryProofSignature as string, "hex");
      proofSig[0] ^= 0xff;
      const proofInvalid2 = { ...body, recoveryProofSignature: proofSig.toString("hex") };
      const r4 = await post(base, "/v1/identity/recovery/verify", proofInvalid2);
      assert.equal(r4.status, 401);
      assert.equal(((await r4.json()) as { error: { code: string } }).error.code, "proof_invalid");
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// N4: absent challenge yields a generic not_found 404 envelope.
// ---------------------------------------------------------------------------
test("absent challenge is not_found 404 with generic envelope, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const res = await post(base, "/v1/identity/recovery/verify", { ...body, challengeId: randomUUID() });
      assert.equal(res.status, 404);
      const json = (await res.json()) as { error: { code: string; message: string; requestId: string } };
      assert.equal(json.error.code, "not_found");
      assert.equal(json.error.message, "resource not found");
      assert.ok(json.error.requestId.length > 0);
    });
    await assertZeroMutation(pool, before);
  });
});

test("unknown /v1 path is the generic S8 not_found; /health and /ready preserved, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const unknown = await fetch(`${base}/v1/identity/recovery/does-not-exist`);
      assert.equal(unknown.status, 404);
      const json = (await unknown.json()) as { error: { code: string } };
      assert.equal(json.error.code, "not_found");

      const health = await fetch(`${base}/health`);
      assert.equal(health.status, 200);
      const ready = await fetch(`${base}/ready`);
      assert.equal(ready.status, 200);
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// State / revocation (409, proofs verified, zero mutation).
// ---------------------------------------------------------------------------
test("consumed / expired / revoked-root / revoked-verifier each return their 409", async () => {
  for (const [options, expected] of [
    [{ challengeConsumed: true }, "challenge_consumed"],
    [{ challengeExpired: true }, "challenge_expired"],
    [{ rootRevoked: true }, "root_revoked"],
    [{ verifierRevoked: true }, "verifier_revoked"],
  ] as Array<[SeedOptions, string]>) {
    await withFreshDatabase(async (pool) => {
      await runMigrations(pool);
      const { body } = await seedSetup(pool, options);
      const before = await snapshot(pool);
      await withServer(pool, async (base) => {
        const res = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(res.status, 409, `expected 409 for ${expected}`);
        assert.equal(((await res.json()) as { error: { code: string } }).error.code, expected);
      });
      await assertZeroMutation(pool, before);
    });
  }
});

test("verifier_revoked is an active 409, distinct from root_revoked, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool, { verifierRevoked: true });
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const res = await post(base, "/v1/identity/recovery/verify", body);
      assert.equal(res.status, 409);
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, "verifier_revoked");
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// duplicate_active_root is NOT reachable from the read-only route; the happy
// path over an active root returns 200 (and never the 409 duplicate_active_root).
// ---------------------------------------------------------------------------
test("an active single root verifies successfully (duplicate_active_root unreachable)", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const res = await post(base, "/v1/identity/recovery/verify", body);
      assert.equal(res.status, 200);
      assert.equal(((await res.json()) as { status: string }).status, "verified");
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Availability: the verify route is unavailable (transport 503, no requestId)
// when there is no migrated/ready database path. It never parses or evaluates.
// ---------------------------------------------------------------------------
test("a failed readiness probe makes verify 503 not_ready with no requestId, zero mutation", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(
      pool,
      async (base) => {
        const res = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(res.status, 503);
        const json = (await res.json()) as { status: string; requestId?: unknown };
        assert.equal(json.status, "not_ready");
        assert.equal(json.requestId, undefined);
      },
      undefined,
      async () => false,
    );
    await assertZeroMutation(pool, before);
  });
});

test("verify with no configured database returns 503 not_ready", async () => {
  const server = createWeaveServer({});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  try {
    const res = await post(`http://127.0.0.1:${port}`, "/v1/identity/recovery/verify", {});
    assert.equal(res.status, 503);
    assert.equal(((await res.json()) as { status: string }).status, "not_ready");
  } finally {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
});

// ---------------------------------------------------------------------------
// Admission control: an in-flight cap + absolute raw-body deadline bound body
// reads. A saturated request performs NO ready()/DB call and NO crypto (no
// requestId), and every granted slot is released on completion/error/abort.
// ---------------------------------------------------------------------------
test("capacity-saturated ninth request returns transport 503 with no ready()/DB call and no crypto produce; the slot then releases", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    let readyCalls = 0;
    const countingReadiness = async () => {
      readyCalls++;
      return true;
    };
    await withServer(
      pool,
      async (base) => {
        // Claim the single slot with a request whose body we never finish.
        const held = openPartialRequest(base);
        // The held request's `response` will reject when we destroy it below; its
        // being an expected client-side abort must not surface as a test failure.
        void held.response.catch(() => {});
        // The held request has already passed readiness (slot granted) and is now
        // in its bounded body read. Give it time to reach saturation.
        await sleep(100);
        const saturatedCalls = readyCalls;
        assert.ok(saturatedCalls >= 1, "the held request should have probed readiness");

        const res = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(res.status, 503, "saturated request must be refused before any evaluation");
        const json = (await res.json()) as { status: string; requestId?: unknown };
        assert.equal(json.status, "not_ready");
        assert.equal(json.requestId, undefined, "saturation 503 must not emit a requestId");
        assert.equal(readyCalls, saturatedCalls, "saturation must not probe ready()/DB");

        // Release the slot: abort the held request, then a fresh request must be served.
        held.req.destroy();
        await sleep(150);
        const freed = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(freed.status, 200, "released slot must serve a normal verification");
        assert.equal(((await freed.json()) as { status: string }).status, "verified");
      },
      { maxInFlight: 1, bodyDeadlineMs: 60_000 },
      countingReadiness,
    );
    await assertZeroMutation(pool, before);
  });
});

// The frozen production admission contract is specifically the DEFAULT 8
// in-flight slots (10s raw-body deadline). This holds eight default-admission
// requests and proves the ninth is refused with no readiness call and no
// requestId, then proves the slots release.
test("default admission (8 in-flight): the ninth request is 503 with no ready()/requestId and the slots release", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    let readyCalls = 0;
    const countingReadiness = async () => {
      readyCalls++;
      return true;
    };
    await withServer(pool, async (base) => {
      const held: Array<{ req: ClientRequest; response: Promise<{ status: number; body: string }> }> = [];
      for (let i = 0; i < 8; i++) {
        const h = openPartialRequest(base);
        void h.response.catch(() => {});
        held.push(h);
      }
      // Wait until all eight held requests have probed readiness and hold a slot.
      for (let i = 0; i < 100 && readyCalls < 8; i++) await sleep(20);
      assert.equal(readyCalls, 8, `expected all 8 held requests to probe readiness, got ${readyCalls}`);

      const ninth = await post(base, "/v1/identity/recovery/verify", body);
      assert.equal(ninth.status, 503, "the ninth in-flight request must be refused");
      const json = (await ninth.json()) as { status: string; requestId?: unknown };
      assert.equal(json.status, "not_ready");
      assert.equal(json.requestId, undefined, "saturation 503 must not emit a requestId");
      assert.equal(readyCalls, 8, "the ninth request must not probe ready()/DB");

      // Release every held slot, then a fresh request must be served.
      for (const h of held) h.req.destroy();
      await sleep(400);
      const freed = await post(base, "/v1/identity/recovery/verify", body);
      assert.equal(freed.status, 200, "released slots must serve a normal verification");
      assert.equal(((await freed.json()) as { status: string }).status, "verified");
    }, undefined, countingReadiness);
    await assertZeroMutation(pool, before);
  });
});

test("raw-body absolute deadline returns transport 503 and releases the slot", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(
      pool,
      async (base) => {
        // Hold a body open past the (short) deadline; the server must time out.
        const held = openPartialRequest(base);
        const res = await held.response;
        const json = JSON.parse(res.body) as { status: string; requestId?: unknown };
        assert.equal(res.status, 503);
        assert.equal(json.status, "not_ready");
        assert.equal(json.requestId, undefined, "deadline 503 is a transport shape with no requestId");

        // The timed-out request released its slot: a normal request must succeed.
        const freed = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(freed.status, 200, "deadline-released slot must serve a normal verification");
        assert.equal(((await freed.json()) as { status: string }).status, "verified");
      },
      { maxInFlight: 8, bodyDeadlineMs: 100 },
    );
    await assertZeroMutation(pool, before);
  });
});

// An early refusal that never reaches the bounded body read must still drop the
// connection once its response flushes; otherwise a wrong-method/media slow body
// that never ends would hold the socket and bypass the 10-second body bound.
test("wrong-media POST with a never-ending body responds 400 immediately and the connection is dropped", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    await seedSetup(pool);
    const before = await snapshot(pool);
    await withServer(pool, async (base) => {
      const { req, response } = openRawRequest(base, { method: "POST", contentType: "text/plain" });
      let closed = false;
      req.on("close", () => {
        closed = true;
      });
      // The response must arrive immediately — NOT after the 10s body deadline —
      // proving no bounded body read was reached on a wrong-media request.
      const res = await response;
      const json = JSON.parse(res.body) as { error: { code: string } };
      assert.equal(res.status, 400);
      assert.equal(json.error.code, "bad_request");
      // The connection must be dropped by the server after the flush so the
      // still-open body cannot retain the socket.
      await sleep(200);
      assert.ok(closed, "server must drop the connection after the early-refusal response");
      req.destroy();
    });
    await assertZeroMutation(pool, before);
  });
});

// ---------------------------------------------------------------------------
// Shared HTTP hardening regressions, first observed RED before the boundary
// owned terminal outcome logging and transport retry signaling.
// ---------------------------------------------------------------------------
test("S8 refusal and generic unknown /v1 each emit one correlated redacted outcome", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    await seedSetup(pool);
    const sentinel = "body-header-query-sentinel";
    const { value, logs } = await captureLogs(async () =>
      await withServer(pool, async (base) => {
        const refusal = await post(
          base,
          "/v1/identity/recovery/verify",
          { sentinel },
          { "content-type": "text/plain", authorization: `Bearer ${sentinel}` },
        );
        const unknown = await fetch(`${base}/v1/private-${sentinel}?q=${sentinel}`);
        return { refusal, unknown };
      }),
    );

    const refusalBody = (await value.refusal.json()) as { error: { requestId: string } };
    const unknownBody = (await value.unknown.json()) as { error: { requestId: string } };
    const outcomeEvents = events(logs, "http.outcome");
    assert.equal(outcomeEvents.length, 2, "every S8 terminal response must log once");
    assert.deepEqual(
      outcomeEvents.map((event) => event.requestId).sort(),
      [refusalBody.error.requestId, unknownBody.error.requestId].sort(),
      "each S8 log must use the returned requestId as its correlation",
    );
    assert.ok(logs.every((event) => !JSON.stringify(event).includes(sentinel)), "request material must never be logged");
  });
});

test("each transport 503 has a retry hint and one server-only correlated outcome", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    await seedSetup(pool);
    const { value, logs } = await captureLogs(async () =>
      await withServer(
        pool,
        async (base) => await post(base, "/v1/identity/recovery/verify", {}),
        undefined,
        async () => false,
      ),
    );
    assert.equal(value.status, 503);
    assert.ok(value.headers.get("retry-after"), "transport 503 must give bounded retry guidance");
    const body = (await value.json()) as { status: string; requestId?: unknown; error?: unknown };
    assert.deepEqual(body, { status: "not_ready" });
    const transportEvents = events(logs, "http.transport_503");
    assert.equal(transportEvents.length, 1, "transport refusal must log exactly once");
    assert.equal(transportEvents[0].status, 503);
    assert.ok(typeof transportEvents[0].correlationId === "string" && transportEvents[0].correlationId.length > 0);
    assert.equal(body.requestId, undefined, "server-only correlation must not appear on the wire");
  });
});

test("catch-all is one redacted transport 503 and releases its admission slot", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    await seedSetup(pool);
    const exceptionSentinel = "catch-all-exception-sentinel";
    let calls = 0;
    const { value, logs } = await captureLogs(async () =>
      await withServer(
        pool,
        async (base) => {
          const first = await post(base, "/v1/identity/recovery/verify", {});
          const second = await post(base, "/v1/identity/recovery/verify", {});
          return { first, second };
        },
        { maxInFlight: 1, bodyDeadlineMs: 100 },
        async () => {
          calls++;
          throw new Error(exceptionSentinel);
        },
      ),
    );
    assert.equal(value.first.status, 503);
    assert.equal(value.second.status, 503, "a catch-all must release its admission slot");
    assert.equal(calls, 2, "the second request must reach readiness after release");
    const transportEvents = events(logs, "http.transport_503");
    assert.equal(transportEvents.length, 2, "each catch-all must emit exactly one terminal log");
    assert.ok(logs.every((event) => !JSON.stringify(event).includes(exceptionSentinel)));
  });
});

test("all S8 terminal families use one allowlisted requestId-correlated outcome", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);
    const logs: CapturedLog[] = [];
    await withServer(
      pool,
      async (base) => {
        const cases: Array<() => Promise<Response>> = [
          async () => await fetch(`${base}/v1/identity/recovery/verify`, { method: "GET" }),
          async () => await post(base, "/v1/identity/recovery/verify", "redaction-body-sentinel", { "content-type": "text/plain" }),
          async () => await post(base, "/v1/identity/recovery/verify", JSON.stringify({ padding: "x".repeat(9_000) })),
          async () => await post(base, "/v1/identity/recovery/verify", Buffer.from([0xc3, 0x28])),
          async () => await post(base, "/v1/identity/recovery/verify", "{"),
          async () => await post(base, "/v1/identity/recovery/verify", {}),
          async () => await post(base, "/v1/identity/recovery/verify", { ...body, challengeId: randomUUID() }),
          async () => await post(base, "/v1/identity/recovery/verify", body),
        ];
        const expectedStatuses = [400, 400, 400, 400, 400, 400, 404, 200];
        for (let index = 0; index < cases.length; index++) {
          const response = await cases[index]();
          assert.equal(response.status, expectedStatuses[index]);
          assert.equal(response.headers.get("retry-after"), null, "S8 outcomes must not carry transport retry guidance");
          const json = (await response.json()) as { error?: { requestId: string }; requestId?: string };
          const requestId = json.error?.requestId ?? json.requestId;
          assert.ok(requestId, "every S8 response and verified success has its requestId");
          const event = logs[index];
          assertS8LogShape(event, requestId as string);
        }
      },
      { maxInFlight: 1, bodyDeadlineMs: 1_000 },
      undefined,
      { outcomeLogger: recordOutcomes(logs) },
    );
    assert.equal(logs.length, 8);
    assert.ok(logs.every((event) => !JSON.stringify(event).includes("redaction-body-sentinel")));
    await assertZeroMutation(pool, before);
  });
});

test("capacity, readiness, deadline, and catch-all each use the one transport-503 writer", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const { body } = await seedSetup(pool);
    const before = await snapshot(pool);

    const readinessLogs: CapturedLog[] = [];
    await withServer(
      pool,
      async (base) => {
        const response = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(response.status, 503);
        assert.equal(response.headers.get("retry-after"), "1");
        assert.deepEqual(await response.json(), { status: "not_ready" });
      },
      undefined,
      async () => false,
      { outcomeLogger: recordOutcomes(readinessLogs) },
    );
    assert.equal(readinessLogs.length, 1);
    assertTransportLogShape(readinessLogs[0]);
    assert.equal(readinessLogs[0].outcome, "not_ready");

    const capacityLogs: CapturedLog[] = [];
    await withServer(
      pool,
      async (base) => {
        const held = openPartialRequest(base);
        void held.response.catch(() => {});
        await sleep(100);
        const saturated = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(saturated.status, 503);
        assert.equal(saturated.headers.get("retry-after"), "1");
        assert.deepEqual(await saturated.json(), { status: "not_ready" });
        held.req.destroy();
        await sleep(100);
      },
      { maxInFlight: 1, bodyDeadlineMs: 1_000 },
      undefined,
      { outcomeLogger: recordOutcomes(capacityLogs) },
    );
    assert.equal(events(capacityLogs, "http.transport_503").length, 1);
    assertTransportLogShape(capacityLogs[0]);
    assert.equal(capacityLogs[0].outcome, "capacity");

    const deadlineLogs: CapturedLog[] = [];
    await withServer(
      pool,
      async (base) => {
        const held = openPartialRequest(base);
        const response = await held.response;
        assert.equal(response.status, 503);
        assert.equal(response.headers["retry-after"], "1");
        assert.deepEqual(JSON.parse(response.body), { status: "not_ready" });
      },
      { maxInFlight: 1, bodyDeadlineMs: 50 },
      undefined,
      { outcomeLogger: recordOutcomes(deadlineLogs) },
    );
    assert.equal(deadlineLogs.length, 1);
    assertTransportLogShape(deadlineLogs[0]);
    assert.equal(deadlineLogs[0].outcome, "deadline");

    const catchLogs: CapturedLog[] = [];
    const exceptionSentinel = "transport-catchall-sentinel";
    await withServer(
      pool,
      async (base) => {
        const response = await post(base, "/v1/identity/recovery/verify", body);
        assert.equal(response.status, 503);
        assert.equal(response.headers.get("retry-after"), "1");
        assert.deepEqual(await response.json(), { status: "not_ready" });
      },
      undefined,
      async () => {
        throw new Error(exceptionSentinel);
      },
      { outcomeLogger: recordOutcomes(catchLogs) },
    );
    assert.equal(catchLogs.length, 1);
    assertTransportLogShape(catchLogs[0]);
    assert.equal(catchLogs[0].outcome, "catch_all");
    assert.ok(catchLogs.every((event) => !JSON.stringify(event).includes(exceptionSentinel)));
    await assertZeroMutation(pool, before);
  });
});

test("two test-only operations share one server boundary while another server stays isolated", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const logs: CapturedLog[] = [];
    let releaseFirst: (() => void) | undefined;
    const firstReleased = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstStarted: (() => void) | undefined;
    const firstAdmitted = new Promise<void>((resolve) => {
      firstStarted = resolve;
    });
    const operations = new Map<string, TestOnlyV1Operation>([
      [
        "/v1/__test/first",
        {
          route: "test.first",
          handle: async (operation) => {
            firstStarted?.();
            await firstReleased;
            operation.success(200, { status: "ok" }, "ok");
          },
        },
      ],
      [
        "/v1/__test/second",
        {
          route: "test.second",
          handle: async (operation) => operation.success(200, { status: "ok" }, "ok"),
        },
      ],
    ]);
    await withServer(
      pool,
      async (base) => {
        const first = fetch(`${base}/v1/__test/first`);
        await firstAdmitted;
        const saturated = await fetch(`${base}/v1/__test/second`);
        assert.equal(saturated.status, 503, "second operation must share the first operation's limit");
        assert.equal(saturated.headers.get("retry-after"), "1");
        const unknown = await fetch(`${base}/v1/unknown-path-with-secret?query=secret`);
        assert.equal(unknown.status, 404, "generic unknown /v1 must not consume an admission slot");
        releaseFirst?.();
        assert.equal((await first).status, 200);
        assert.equal((await fetch(`${base}/v1/__test/second`)).status, 200);

        const isolated = createWeaveServer({
          pool,
          readiness: async () => true,
          admission: { maxInFlight: 1, bodyDeadlineMs: 1_000 },
          testOnlyV1Operations: operations,
          outcomeLogger: recordOutcomes(logs),
        });
        await new Promise<void>((resolve) => isolated.listen(0, "127.0.0.1", resolve));
        const address = isolated.address();
        const port = typeof address === "object" && address !== null ? address.port : 0;
        try {
          assert.equal((await fetch(`http://127.0.0.1:${port}/v1/__test/second`)).status, 200);
        } finally {
          await new Promise<void>((resolve, reject) => isolated.close((error) => (error ? reject(error) : resolve())));
        }
      },
      { maxInFlight: 1, bodyDeadlineMs: 1_000 },
      undefined,
      { outcomeLogger: recordOutcomes(logs), testOnlyV1Operations: operations },
    );
    assert.equal(events(logs, "http.transport_503").length, 1);
    const unknownEvents = events(logs, "http.outcome").filter((event) => event.route === "v1.unknown");
    assert.equal(unknownEvents.length, 1);
    assertS8LogShape(unknownEvents[0], String(unknownEvents[0].requestId));
    assert.ok(logs.every((event) => !JSON.stringify(event).includes("unknown-path-with-secret")));
    assert.ok(logs.every((event) => !JSON.stringify(event).includes("query=secret")));
  });
});

test("buildRecoveryTranscript accepts only integer environment codes 1..4", () => {
  const base = {
    domain: DOMAIN,
    protocolVersion: 1,
    schemeVersion: 1,
    signatureAlgorithmCode: 1,
    tlsOrigin: FIXED.tlsOrigin,
    personId: FIXED.person,
    recoveryVerifierId: FIXED.verifier,
    communityId: FIXED.community,
    challengeId: FIXED.challenge,
    nonce: decodeLowerHexEd25519Key(FIXED.nonceHex) as Uint8Array,
    intendedDevicePublicKey: decodeLowerHexEd25519Key(FIXED.deviceHex) as Uint8Array,
    expiryUnixMs: FIXED.expiry,
  };
  for (const env of [0, 5, 255, -1, 1.5, Number.NaN, "4" as unknown, null as unknown]) {
    assert.throws(
      () => buildRecoveryTranscript({ ...base, environmentCode: env as number }),
      /environment code to be an integer 1\.\.4/,
      `environmentCode ${String(env)} must be rejected`,
    );
  }
  for (const env of [1, 2, 3, 4]) {
    const out = buildRecoveryTranscript({ ...base, environmentCode: env });
    assert.ok(Buffer.isBuffer(out) && out.length > 0, `environmentCode ${env} must be accepted`);
  }
});
