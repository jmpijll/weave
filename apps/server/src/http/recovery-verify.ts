/**
 * Weave M1.3.2 — the read-only `POST /v1/identity/recovery/verify` route.
 *
 * This is a proof-evaluation endpoint, not a recovery operation. It performs
 * only the challenge / verifier / human-root reads needed to evaluate the
 * submitted proofs: it never consumes a challenge, creates or revokes a
 * credential or verifier, writes an audit event, or issues an authorization
 * artifact (ADR §M1.3.2 verification-only wire endpoint). Every outcome —
 * success and every refusal — leaves the database unchanged.
 *
 * The fixed S8 evaluation precedence is preserved verbatim (see
 * `PLANS/WEAVE_M13_IMPLEMENTATION_SEQUENCE_SKELETON.md` §M1.3.2 and the
 * amended contract in the M1.3.2 review thread):
 *
 *   1. format guards (version / algorithm / environment + `schemeVersion`);
 *   2. structural validation of every non-proof field;
 *   3. signature presence (absent -> `proof_missing`) versus form
 *      (present-but-null-or-not-exact-lower-hex -> `bad_request`);
 *  4. challenge lookup (absent -> `not_found`, N4);
 *  5. load the STORED verifier / human-root keys by the challenge row's
 *      `verifier_id` / `person_id` (never client-supplied IDs), then verify BOTH
 *      proofs over the strict-decoded supplied `canonicalTranscript` — no
 *      binding result is ever emitted before authentication. A verification
 *      failure (including an unloadable verifier key or no verifiable human
 *      root) -> `proof_invalid`;
 *  6. collapsed binding comparison (any mismatch -> `binding_mismatch`) — only
 *      an authenticated submission reaches this binding result;
 *  7. rebuild S9 from the stored matching challenge and byte-compare to the
 *      supplied transcript (unequal -> `transcript_invalid`);
 *  8. state / revocation (consumed / expired / root-revoked /
 *      verifier-revoked -> each 409) only after both proofs verify.
 *
 * M1.3.2 performs no private-resource authorization decision, so it never
 * emits `permission_denied` (the N4 absent-vs-forbidden equality is the
 * M1.3.4 `identity.recover` evidence).
 *
 * The route is gated on a migrated, ready database path: with no DB or a
 * readiness probe that fails, the endpoint is unavailable (503) and never
 * parses or evaluates a request. A bounded in-process admission control (max
 * in-flight + absolute raw-body deadline) keeps a single process from being
 * exhausted by unauthenticated body reads.
 *
 * The admission CAPACITY check runs first — before `ready()` and before any
 * `requestId` is generated — so a saturated request performs no DB and no
 * crypto work. A slot is acquired, then readiness and body handling run inside
 * it. A `requestId` exists only for SLOT-GRANTED requests; the transport-503
 * shapes (capacity-saturated, not-ready, raw-body deadline) carry no
 * `requestId` by design. The slot is released on every completion / error /
 * aborted request, and a bounded raw-body read never leaves an unconsumed body
 * holding the connection: on oversize / deadline the request is destroyed.
 */

import { createPublicKey, randomUUID } from "node:crypto";
import { verify as verifySignature } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  buildRecoveryTranscript,
  decodeLowerHexEd25519Key,
  decodeLowerHexEd25519Signature,
  isLowerHexEd25519PublicKey,
  isLowerHexEd25519Signature,
  resolveRecoveryError,
} from "@weave/protocol";
import type { RecoveryErrorCode, RecoveryVerifyRequest } from "@weave/protocol";

/** The minimal database surface this route needs: parameterized reads only. */
export type Queryable = {
  query: (text: string, params: unknown[]) => Promise<{ rows: Array<Record<string, unknown>> }>;
};

const MAX_BODY_BYTES = 8 * 1024;
const DOMAIN = "weave/recovery/proof";
const SIGNATURE_ALGORITHM_CODE = 1;
const SUPPORTED_ENVIRONMENT_CODES = Object.freeze([1, 2, 3, 4]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TRANSCRIPT_HEX_RE = /^(?:[0-9a-f]{2})+$/;

/** Legible, fixed message per code; N4-generic where the spec says so. */
const MESSAGE: Record<RecoveryErrorCode, string> = {
  bad_request: "request is malformed",
  proof_missing: "required signature is missing",
  proof_invalid: "signature verification failed",
  binding_mismatch: "challenge does not match its bound values",
  transcript_invalid: "transcript does not match the reconstructed bytes",
  challenge_consumed: "challenge has already been consumed",
  challenge_expired: "challenge has expired",
  duplicate_active_root: "resource already has an active root",
  root_revoked: "root credential is revoked",
  verifier_revoked: "recovery verifier is revoked",
  permission_denied: "not permitted",
  not_found: "resource not found",
  unsupported_protocol_version: "unsupported protocol version",
  unsupported_algorithm: "unsupported algorithm",
  unsupported_environment: "unsupported environment",
  concurrent_failure: "concurrent operation failed",
};

export type VerifyOutcome =
  | { ok: true; requestId: string }
  | { ok: false; code: RecoveryErrorCode; message: string; requestId: string };

export type VerifiedRequest = RecoveryVerifyRequest;

export function parseRecoveryVerifyRequest(raw: unknown): { ok: true; value: RecoveryVerifyRequest } | { ok: false; code: RecoveryErrorCode; message: string } {
  const fail = (code: RecoveryErrorCode) => ({ ok: false as const, code, message: MESSAGE[code] });
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return fail("bad_request");
  const body = raw as Record<string, unknown>;
  const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);

  // 1. format guards (F6) — before any structural text validation.
  if (!isInt(body.protocolVersion)) return fail("bad_request");
  if (body.protocolVersion !== 1) return fail("unsupported_protocol_version");
  if (!isInt(body.algorithmCode)) return fail("bad_request");
  if (body.algorithmCode !== 1) return fail("unsupported_algorithm");
  if (!isInt(body.environmentCode)) return fail("bad_request");
  if (!SUPPORTED_ENVIRONMENT_CODES.includes(body.environmentCode)) return fail("unsupported_environment");
  if (body.schemeVersion !== 1) return fail("bad_request");

  // 2. structural validation of every non-proof field.
  for (const field of ["challengeId", "personId", "recoveryVerifierId", "communityId"] as const) {
    const value = body[field];
    if (typeof value !== "string" || !UUID_RE.test(value)) return fail("bad_request");
  }
  if (typeof body.tlsOrigin !== "string" || !isCanonicalWssOrigin(body.tlsOrigin)) return fail("bad_request");
  if (typeof body.nonce !== "string" || !isLowerHexEd25519PublicKey(body.nonce)) return fail("bad_request");
  if (typeof body.intendedDevicePublicKey !== "string" || !isLowerHexEd25519PublicKey(body.intendedDevicePublicKey)) {
    return fail("bad_request");
  }
  const transcript = body.canonicalTranscript;
  if (
    typeof transcript !== "string" ||
    transcript.length === 0 ||
    transcript.length > 842 ||
    !TRANSCRIPT_HEX_RE.test(transcript)
  ) {
    return fail("bad_request");
  }

  // 3. signature presence / form — deliberately distinct from structural text.
  //    Absent (key not present) -> proof_missing; present-but-null or not
  //    exact lower-hex -> bad_request.
  if (body.rootSignature === undefined || body.recoveryProofSignature === undefined) return fail("proof_missing");
  if (
    body.rootSignature === null ||
    typeof body.rootSignature !== "string" ||
    !isLowerHexEd25519Signature(body.rootSignature)
  ) {
    return fail("bad_request");
  }
  if (
    body.recoveryProofSignature === null ||
    typeof body.recoveryProofSignature !== "string" ||
    !isLowerHexEd25519Signature(body.recoveryProofSignature)
  ) {
    return fail("bad_request");
  }

  return {
    ok: true,
    value: {
      challengeId: body.challengeId as string,
      personId: body.personId as string,
      recoveryVerifierId: body.recoveryVerifierId as string,
      communityId: body.communityId as string,
      protocolVersion: body.protocolVersion,
      schemeVersion: body.schemeVersion,
      algorithmCode: body.algorithmCode,
      environmentCode: body.environmentCode,
      tlsOrigin: body.tlsOrigin as string,
      nonce: body.nonce as string,
      intendedDevicePublicKey: body.intendedDevicePublicKey as string,
      canonicalTranscript: transcript as string,
      rootSignature: body.rootSignature as string,
      recoveryProofSignature: body.recoveryProofSignature as string,
    },
  };
}

function isCanonicalWssOrigin(value: string): boolean {
  const byteLength = Buffer.byteLength(value, "utf8");
  if (byteLength === 0 || byteLength > 255) return false;
  if (!/^wss:\/\/[A-Za-z0-9\[]/.test(value)) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "wss:" && url.origin === value && url.hostname.length > 0;
}

/** Run the fixed evaluation precedence against a parsed, well-formed request. */
export async function evaluateRecoveryRequest(
  value: RecoveryVerifyRequest,
  db: Queryable,
  requestId: string,
): Promise<VerifyOutcome> {
  const refuse = (code: RecoveryErrorCode): VerifyOutcome => ({ ok: false, code, message: MESSAGE[code], requestId });

  // 4. challenge lookup; absent -> not_found (N4).
  const challenge = await db.query(SELECT_CHALLENGE, [value.challengeId]);
  if (challenge.rows.length === 0) return refuse("not_found");
  const row = challenge.rows[0];

  // 5. load the STORED verifier + human-root keys by the challenge row's own
  //    `verifier_id` / `person_id` — NEVER the client-supplied `value.*` IDs,
  //    which would make binding substitutions `proof_invalid` and violate
  //    "stored keys before binding". A proof cannot be verified until its key
  //    is loaded, so an unloadable verifier key or no verifiable human root is
  //    `proof_invalid`.
  const verifier = await db.query(SELECT_VERIFIER, [row.verifier_id]);
  if (verifier.rows.length === 0 || verifier.rows[0].public_key == null) return refuse("proof_invalid");
  const verifierRow = verifier.rows[0];

  // Human-root lookup INCLUDES a revoked row so `root_revoked` is reachable
  // after proof verification (ADR §M1.3.2); no `revoked_at` filter.
  const roots = await db.query(SELECT_HUMAN_ROOT, [row.person_id]);
  if (roots.rows.length === 0) return refuse("proof_invalid");

  // Fail closed on persisted verifier/challenge metadata disagreement (M1.3.1).
  if (
    verifierRow.protocol_version !== row.protocol_version ||
    verifierRow.scheme_version !== row.scheme_version ||
    verifierRow.algorithm_code !== row.algorithm_code ||
    verifierRow.environment_code !== row.environment_code
  ) {
    return refuse("bad_request");
  }

  // 6. verify BOTH proofs over the strict-decoded supplied canonicalTranscript.
  //    No binding result is emitted until authentication succeeds, so a
  //    mismatch is only ever reported for a proof-authenticated ceremony.
  const suppliedBytes = Buffer.from(value.canonicalTranscript, "hex");
  if (!verifyEd25519(String(verifierRow.public_key), suppliedBytes, value.recoveryProofSignature)) {
    return refuse("proof_invalid");
  }
  let matchingRoot: Record<string, unknown> | null = null;
  for (const rootRow of roots.rows) {
    if (verifyEd25519(String(rootRow.public_key), suppliedBytes, value.rootSignature)) {
      matchingRoot = rootRow;
      break;
    }
  }
  if (matchingRoot === null) return refuse("proof_invalid");

  // 7. collapsed binding comparison — only an authenticated submission reaches
  //    a binding result (any mismatch -> collapsed `binding_mismatch`).
  if (!bindingsMatch(value, row)) return refuse("binding_mismatch");

  // 8. rebuild S9 from the stored matching challenge and byte-compare to the
  //    supplied transcript (unequal -> `transcript_invalid`).
  const expiryMs = toMillis(row.expires_at);
  const nonceBytes = decodeLowerHexEd25519Key(value.nonce);
  const deviceBytes = decodeLowerHexEd25519Key(value.intendedDevicePublicKey);
  let reconstructed: Buffer;
  try {
    reconstructed = buildRecoveryTranscript({
      domain: DOMAIN,
      protocolVersion: value.protocolVersion,
      schemeVersion: value.schemeVersion,
      environmentCode: value.environmentCode,
      signatureAlgorithmCode: SIGNATURE_ALGORITHM_CODE,
      tlsOrigin: value.tlsOrigin,
      personId: value.personId,
      recoveryVerifierId: value.recoveryVerifierId,
      communityId: value.communityId,
      challengeId: value.challengeId,
      nonce: nonceBytes as Uint8Array,
      intendedDevicePublicKey: deviceBytes as Uint8Array,
      expiryUnixMs: expiryMs,
    });
  } catch {
    return refuse("bad_request");
  }
  if (!suppliedBytes.equals(reconstructed)) return refuse("transcript_invalid");

  // 9. state / revocation — only after both proofs verify, zero mutation.
  if (row.consumed_at != null) return refuse("challenge_consumed");
  if (expiryMs <= Date.now()) return refuse("challenge_expired");
  if (matchingRoot.revoked_at != null) return refuse("root_revoked");
  if (verifierRow.revoked_at != null) return refuse("verifier_revoked");

  return { ok: true, requestId };
}

const SELECT_CHALLENGE =
  `SELECT id, verifier_id, person_id, community_id, canonical_tls_origin, nonce, ` +
  `intended_device_public_key, protocol_version, scheme_version, algorithm_code, ` +
  `environment_code, expires_at, consumed_at FROM recovery_challenge WHERE id = $1`;

const SELECT_VERIFIER =
  `SELECT public_key, revoked_at, protocol_version, scheme_version, algorithm_code, ` +
  `environment_code FROM recovery_verifier WHERE id = $1`;

const SELECT_HUMAN_ROOT =
  `SELECT public_key, revoked_at FROM credential WHERE person_id = $1 AND kind = 'human' ` +
  `AND parent_credential_id IS NULL AND algorithm = 'ed25519'`;

function bindingsMatch(value: RecoveryVerifyRequest, row: Record<string, unknown>): boolean {
  if (value.personId !== String(row.person_id)) return false;
  if (value.recoveryVerifierId !== String(row.verifier_id)) return false;
  if (value.communityId !== String(row.community_id)) return false;
  if (value.tlsOrigin !== String(row.canonical_tls_origin)) return false;
  if (value.intendedDevicePublicKey !== String(row.intended_device_public_key)) return false;
  if (value.protocolVersion !== Number(row.protocol_version)) return false;
  if (value.schemeVersion !== Number(row.scheme_version)) return false;
  if (value.algorithmCode !== Number(row.algorithm_code)) return false;
  if (value.environmentCode !== Number(row.environment_code)) return false;
  const nonceBytes = decodeLowerHexEd25519Key(value.nonce);
  if (nonceBytes === null || !Buffer.isBuffer(row.nonce) || !Buffer.from(nonceBytes).equals(row.nonce)) return false;
  return true;
}

function toMillis(value: unknown): number {
  const date = value instanceof Date ? value : new Date(value as string | number);
  return date.getTime();
}

function verifyEd25519(publicKeyHex: string, data: Buffer, signatureHex: string): boolean {
  const rawKey = decodeLowerHexEd25519Key(publicKeyHex);
  const signature = decodeLowerHexEd25519Signature(signatureHex);
  if (rawKey === null || signature === null) return false;
  let key: ReturnType<typeof createPublicKey>;
  try {
    key = createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, Buffer.from(rawKey)]),
      format: "der",
      type: "spki",
    });
  } catch {
    return false;
  }
  try {
    return verifySignature(null, data, key, signature);
  } catch {
    return false;
  }
}

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface RecoveryVerifyContext {
  db?: Queryable;
  ready?: () => Promise<boolean>;
  /**
   * Bounded in-process admission control. Defaults are the OWASP-tensioned
   * values: at most 8 in-flight verifications per process (leaving capacity
   * under a 10-connection pool) and a 10-second absolute raw-body deadline.
   */
  admission?: { maxInFlight: number; bodyDeadlineMs: number };
}

/** Bounded in-process admission control (see `RecoveryVerifyContext`). */
const DEFAULT_ADMISSION = Object.freeze({ maxInFlight: 8, bodyDeadlineMs: 10_000 });
let inFlight = 0;

type RawBody = Buffer | "oversize" | "timeout";

/** Wire the route into a `node:http` request/response pair. */
export async function handleRecoveryVerify(
  request: IncomingMessage,
  response: ServerResponse,
  ctx: RecoveryVerifyContext,
): Promise<void> {
  const admission = ctx.admission ?? DEFAULT_ADMISSION;

  // Admission CAPACITY check runs FIRST — before `ready()` and before any
  // `requestId` is generated. A saturated request performs no DB and no crypto
  // work and returns the transport not-ready 503 (no requestId by design).
  if (inFlight >= admission.maxInFlight) {
    // A saturated request is refused without reading its body; destroy the
    // connection once the transport 503 flushes so the unconsumed body can
    // never retain or reset the connection.
    dropAfterFlush(request, response);
    writeNotReady(response);
    return;
  }
  inFlight++;
  try {
    // Availability gate: no DB/migrations or a failed readiness probe means the
    // endpoint is unavailable (503, transport, no requestId) and never parses or
    // evaluates a request. Runs inside the granted slot. The request body may
    // still be open, so the connection is dropped after the transport flush.
    if (!ctx.db || !ctx.ready || !(await ctx.ready())) {
      dropAfterFlush(request, response);
      writeNotReady(response);
      return;
    }

    // A slot is granted and the DB is ready: now a requestId may be generated.
    // It is a diagnostic correlation id only and is never emitted on the
    // transport-503 paths above.
    const requestId = randomUUID();

    // S8 method / media-type guards. A wrong-method or wrong-media request may
    // still carry an unread body; drop the connection after the flush so a slow
    // body cannot hold the socket past the bounded-read path.
    if (request.method !== "POST") {
      dropAfterFlush(request, response);
      writeEnvelope(response, "bad_request", requestId);
      return;
    }
    const contentType = request.headers["content-type"];
    const mediaType = typeof contentType === "string" ? contentType.split(";")[0].trim().toLowerCase() : "";
    if (mediaType !== "application/json") {
      dropAfterFlush(request, response);
      writeEnvelope(response, "bad_request", requestId);
      return;
    }

    // Bounded raw-body read. The slot is released on every completion/error/
    // abort via `finally`, and an unconsumed body never retains the connection.
    const raw = await readBody(request, MAX_BODY_BYTES, admission.bodyDeadlineMs);
    if (raw === "oversize") {
      // Destroy the dropped connection after the transport response flushes so
      // the unconsumed remainder can never hold the connection.
      dropAfterFlush(request, response);
      writeEnvelope(response, "bad_request", requestId);
      return;
    }
    if (raw === "timeout") {
      dropAfterFlush(request, response);
      writeNotReady(response);
      return;
    }
    let text: string;
    try {
      // Fatal decode: any invalid UTF-8 byte sequence rejects the raw body.
      text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch {
      writeEnvelope(response, "bad_request", requestId);
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      writeEnvelope(response, "bad_request", requestId);
      return;
    }
    const parsedRequest = parseRecoveryVerifyRequest(parsed);
    if (!parsedRequest.ok) {
      writeEnvelope(response, parsedRequest.code, requestId);
      return;
    }
    const outcome = await evaluateRecoveryRequest(parsedRequest.value, ctx.db, requestId);
    if (!outcome.ok) {
      writeEnvelope(response, outcome.code, requestId);
      return;
    }
    writeJson(response, 200, { status: "verified", requestId });
  } catch {
    // Any abort (including a client reset during the body read) is a harmless
    // not-ready transport response; slot release is guaranteed by `finally`.
    writeNotReady(response);
    if (!request.destroyed) request.destroy();
  } finally {
    inFlight--;
  }
}

/**
 * Ensure a bounded raw-body read never leaves an unconsumed body holding the
 * connection. Called only on the oversize / deadline paths, AFTER the transport
 * response is written: the shared request socket is destroyed once the response
 * has flushed, so the connection is released instead of being retained by an
 * unread body.
 */
function dropAfterFlush(request: IncomingMessage, response: ServerResponse): void {
  if (request.destroyed || response.writableEnded) {
    if (!request.destroyed) request.destroy();
    return;
  }
  response.once("finish", () => {
    if (!request.destroyed) request.destroy();
  });
}

function readBody(request: IncomingMessage, max: number, deadlineMs: number): Promise<RawBody> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      request.removeListener("data", onData);
      request.removeListener("end", onEnd);
      request.removeListener("error", onError);
      request.removeListener("aborted", onAborted);
    };
    const finish = (value: RawBody): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };
    const onData = (chunk: Buffer | string): void => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      total += buffer.length;
      if (total > max) {
        finish("oversize");
        return;
      }
      chunks.push(buffer);
    };
    const onEnd = (): void => finish(Buffer.concat(chunks));
    const onError = (): void => finish("timeout");
    const onAborted = (): void => finish("timeout");
    timer = setTimeout(() => finish("timeout"), deadlineMs);
    request.on("data", onData);
    request.on("end", onEnd);
    request.on("error", onError);
    request.on("aborted", onAborted);
  });
}

/** Generic S8 `not_found` envelope for an unknown `/v1/*` path (ADR §M1.3.2). */
export function sendRecoveryV1Unknown(response: ServerResponse): void {
  writeEnvelope(response, "not_found", randomUUID());
}

function writeJson(response: ServerResponse, status: number, body: Record<string, unknown>): void {
  if (response.writableEnded) return;
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

function writeEnvelope(response: ServerResponse, code: RecoveryErrorCode, requestId: string): void {
  const { status } = resolveRecoveryError(code);
  writeJson(response, status, { error: { code, message: MESSAGE[code], requestId } });
}

function writeNotReady(response: ServerResponse): void {
  writeJson(response, 503, { status: "not_ready" });
}
