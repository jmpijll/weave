/**
 * Weave M3.2 I4.1 — `POST /v1/pairing-tokens` route parser and S8 mapping.
 *
 * HTTP-only: bounded strict JSON, exact `IssuanceCarrier` shape, then the
 * locked domain command. Public responses are deliberately small:
 * `200 {status:"accepted",requestId}` for first issue and exact retry,
 * `400 bad_request` for P1 structural failure, `401 issuance_rejected` for
 * any P2-P5 refusal, and the existing redacted transport-503 otherwise.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Pool } from "pg";
import { validateIssuanceCarrier } from "@weave/protocol";
import { ISSUE_ERROR_MESSAGE, resolveIssueError } from "@weave/protocol";
import type { IssueErrorCode } from "@weave/protocol";
import type { V1BoundaryController, V1Operation } from "./boundary.ts";
import { readStrictJsonBody } from "./json-body.ts";
import { issuePairingToken } from "../domain/pairing-issue.ts";

export const PAIRING_ISSUE_ROUTE = "/v1/pairing-tokens" as const;

const REQUIRED_KEYS = [
  "stableId",
  "hostPublic",
  "community",
  "device",
  "issuedAt",
  "proof",
] as const;

export interface PairingIssueContext {
  db?: Pool;
  ready?: () => Promise<boolean>;
  boundary: V1BoundaryController;
}

function writeIssueEnvelope(operation: V1Operation, code: IssueErrorCode): void {
  const { status } = resolveIssueError(code);
  operation.s8(status, code, ISSUE_ERROR_MESSAGE[code]);
}

export async function handlePairingIssue(
  request: IncomingMessage,
  response: ServerResponse,
  ctx: PairingIssueContext,
): Promise<void> {
  await ctx.boundary.execute(request, response, "pairing.issue", async (operation) => {
    if (!ctx.db || !ctx.ready || !(await ctx.ready())) {
      operation.transport503("not_ready");
      return;
    }
    if (request.method !== "POST") {
      operation.dropAfterFlush();
      writeIssueEnvelope(operation, "bad_request");
      return;
    }
    const contentType = request.headers["content-type"];
    const mediaType =
      typeof contentType === "string" ? contentType.split(";")[0].trim().toLowerCase() : "";
    if (mediaType !== "application/json") {
      operation.dropAfterFlush();
      writeIssueEnvelope(operation, "bad_request");
      return;
    }
    const body = await readStrictJsonBody(request, operation, { requiredKeys: REQUIRED_KEYS });
    if (!body.ok) {
      if (body.outcome === "aborted") return;
      if (body.outcome === "deadline") {
        operation.transport503("deadline");
        return;
      }
      operation.dropAfterFlush();
      writeIssueEnvelope(operation, "bad_request");
      return;
    }
    let carrier: {
      stableId: string;
      hostPublic: string;
      community: string;
      device: string;
      issuedAt: string;
      proof: string;
    };
    try {
      validateIssuanceCarrier(body.value);
      carrier = body.value as typeof carrier;
    } catch {
      writeIssueEnvelope(operation, "bad_request");
      return;
    }
    let result: { ok: boolean };
    try {
      result = await issuePairingToken(ctx.db, carrier, operation.requestId);
    } catch {
      operation.transport503("catch_all");
      return;
    }
    if (!result.ok) {
      writeIssueEnvelope(operation, "issuance_rejected");
      return;
    }
    operation.success(200, { status: "accepted", requestId: operation.requestId }, "accepted");
  });
}
