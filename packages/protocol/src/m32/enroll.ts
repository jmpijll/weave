/**
 * Weave M3.2 I4.2 — HTTP-only enroll request/error types for `POST /v1/hosts/enroll`.
 *
 * Portable: no Node imports. The request body is exactly the existing
 * `ConsumeCarrier` member set; the error registry is route-specific and
 * versioned, and must not extend `RecoveryErrorCode` or the issue registry.
 * P1 structural failures map to `bad_request` (400); every expected post-P1
 * failure collapses to the single `enroll_rejected` (404) relation.
 */
import type { ConsumeCarrier } from "./carrier.ts";

export type PairingEnrollRequest = ConsumeCarrier;

export const PAIRING_ENROLL_ROUTE = "/v1/hosts/enroll" as const;

export type EnrollErrorCode = "bad_request" | "enroll_rejected";

export interface EnrollErrorDescriptor {
  status: 400 | 404;
  message: string;
  retryable: boolean;
  family: "structural" | "authorization";
}

const ENROLL_ERRORS: Record<EnrollErrorCode, EnrollErrorDescriptor> = {
  bad_request: {
    status: 400,
    message: "request is malformed",
    retryable: true,
    family: "structural",
  },
  enroll_rejected: {
    status: 404,
    message: "enrollment was not accepted",
    retryable: false,
    family: "authorization",
  },
};

export function resolveEnrollError(code: EnrollErrorCode): EnrollErrorDescriptor {
  return ENROLL_ERRORS[code];
}

export const ENROLL_ERROR_MESSAGE: Record<EnrollErrorCode, string> = {
  bad_request: ENROLL_ERRORS.bad_request.message,
  enroll_rejected: ENROLL_ERRORS.enroll_rejected.message,
};
