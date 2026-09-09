/**
 * Weave M3.2 I4.1 — HTTP-only issue request/error types for `POST /v1/pairing-tokens`.
 *
 * Portable: no Node imports. The request body is exactly the existing
 * `IssuanceCarrier` member set; the error registry is route-specific and
 * versioned, and must not extend `RecoveryErrorCode`.
 */
import type { IssuanceCarrier } from "./carrier.ts";

export type PairingIssueRequest = IssuanceCarrier;

export const PAIRING_ISSUE_ROUTE = "/v1/pairing-tokens" as const;

export type IssueErrorCode = "bad_request" | "issuance_rejected";

export interface IssueErrorDescriptor {
  status: 400 | 401;
  message: string;
  retryable: boolean;
  family: "structural" | "authorization";
}

const ISSUE_ERRORS: Record<IssueErrorCode, IssueErrorDescriptor> = {
  bad_request: {
    status: 400,
    message: "request is malformed",
    retryable: true,
    family: "structural",
  },
  issuance_rejected: {
    status: 401,
    message: "issuance was not accepted",
    retryable: false,
    family: "authorization",
  },
};

export function resolveIssueError(code: IssueErrorCode): IssueErrorDescriptor {
  return ISSUE_ERRORS[code];
}

export const ISSUE_ERROR_MESSAGE: Record<IssueErrorCode, string> = {
  bad_request: ISSUE_ERRORS.bad_request.message,
  issuance_rejected: ISSUE_ERRORS.issuance_rejected.message,
};
