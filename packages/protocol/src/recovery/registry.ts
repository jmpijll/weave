/**
 * Weave M1.3.2 — versioned S8 public refusal-code registry.
 *
 * This is the application/protocol-boundary refusal vocabulary (ADR §S8). It
 * is NOT a database table: error codes are versioned protocol data, resolved
 * from the code by clients. Every value here is fixed for v1; a change is a
 * new protocol version, never a silent v1 patch.
 *
 * The registry carries two load-bearing facts per code for the v1 wire:
 *   - `status`: the exact HTTP status the code maps to;
 *   - `retryable`: a static property (never a wire field). A retry is the same
 *     logical operation with the same still-unconsumed challenge after
 *     correcting client-supplied input; starting a fresh challenge is a new
 *     operation.
 *
 * The `family` is a grouping aid for the app boundary; it is not on the wire.
 *
 * Two distinct surfaces exist and must never be conflated:
 *   - the FULL v1 vocabulary below (`RecoveryErrorCode` /
 *     `RECOVERY_ERROR_REGISTRY`), which is every code a client may encounter
 *     at any versioned surface; and
 *   - the codes a specific endpoint may actually emit
 *     (`RECOVERY_VERIFY_REACHABLE_REFUSAL_CODES`). A code can live in the full
 *     registry yet never be emitted by a given read-only endpoint.
 */
export type RecoveryErrorCode =
  | "bad_request"
  | "proof_missing"
  | "proof_invalid"
  | "binding_mismatch"
  | "transcript_invalid"
  | "challenge_consumed"
  | "challenge_expired"
  | "duplicate_active_root"
  | "root_revoked"
  | "verifier_revoked"
  | "permission_denied"
  | "not_found"
  | "unsupported_protocol_version"
  | "unsupported_algorithm"
  | "unsupported_environment"
  | "concurrent_failure";

export type RecoveryErrorFamily =
  | "validation"
  | "proof"
  | "challenge_state"
  | "authorization"
  | "non_disclosure"
  | "format_guard";

export interface RecoveryErrorDescriptor {
  readonly code: RecoveryErrorCode;
  readonly status: 400 | 401 | 403 | 404 | 409;
  readonly retryable: boolean;
  readonly family: RecoveryErrorFamily;
}

export const RECOVERY_ERROR_REGISTRY: Readonly<
  Record<RecoveryErrorCode, Readonly<{ status: 400 | 401 | 403 | 404 | 409; retryable: boolean; family: RecoveryErrorFamily }>>
> = {
  bad_request: { status: 400, retryable: true, family: "validation" },
  proof_missing: { status: 401, retryable: true, family: "proof" },
  proof_invalid: { status: 401, retryable: true, family: "proof" },
  binding_mismatch: { status: 401, retryable: true, family: "proof" },
  transcript_invalid: { status: 401, retryable: true, family: "proof" },
  challenge_consumed: { status: 409, retryable: false, family: "challenge_state" },
  challenge_expired: { status: 409, retryable: false, family: "challenge_state" },
  duplicate_active_root: { status: 409, retryable: false, family: "challenge_state" },
  root_revoked: { status: 409, retryable: false, family: "challenge_state" },
  verifier_revoked: { status: 409, retryable: false, family: "challenge_state" },
  permission_denied: { status: 403, retryable: false, family: "authorization" },
  not_found: { status: 404, retryable: false, family: "non_disclosure" },
  unsupported_protocol_version: { status: 400, retryable: true, family: "format_guard" },
  unsupported_algorithm: { status: 400, retryable: true, family: "format_guard" },
  unsupported_environment: { status: 400, retryable: true, family: "format_guard" },
  concurrent_failure: { status: 409, retryable: false, family: "challenge_state" },
} as const;

/** The S8 requestId map: the wire error envelope carries this code verbatim. */
export type RecoveryErrorCodeField = RecoveryErrorCode;

/**
 * Every refusal that the read-only M1.3.2 `POST /v1/identity/recovery/verify`
 * endpoint may actually emit, in its fixed evaluation precedence.
 *
 * The following full-vocabulary codes are deliberately NOT reachable from this
 * endpoint and must never be emitted or tested here:
 *   - `duplicate_active_root`: a credential-INSERT invariant (migration 0001);
 *     only the M1.3.4 rebind mutation can exercise it.
 *   - `concurrent_failure`: registered for v1 completeness only; a concurrent
 *     race resolves as one accepted request and `challenge_consumed` for every
 *     losing submit (ADR §S8), so no production path emits it.
 *   - `permission_denied`: M1.3.2 performs no private-resource authorization
 *     decision. The N4 absent-vs-forbidden equality belongs to the M1.3.4
 *     `identity.recover` evidence, so this read-only route never emits 403.
 */
export const RECOVERY_VERIFY_REACHABLE_REFUSAL_CODES: readonly RecoveryErrorCode[] = [
  "bad_request",
  "proof_missing",
  "proof_invalid",
  "binding_mismatch",
  "transcript_invalid",
  "challenge_consumed",
  "challenge_expired",
  "root_revoked",
  "verifier_revoked",
  "not_found",
  "unsupported_protocol_version",
  "unsupported_algorithm",
  "unsupported_environment",
];

export function resolveRecoveryError(code: RecoveryErrorCode): RecoveryErrorDescriptor {
  const entry = RECOVERY_ERROR_REGISTRY[code];
  return { code, status: entry.status, retryable: entry.retryable, family: entry.family };
}
