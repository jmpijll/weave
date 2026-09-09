/**
 * Weave M3.2 I4.2 — `POST /v1/hosts/enroll` route parser and S8 mapping.
 *
 * HTTP-only: bounded strict JSON, exact `ConsumeCarrier` shape, then the
 * locked domain command. Public responses are deliberately small:
 * `200 {status:"accepted",requestId}` for an accepted enroll,
 * `400 bad_request` for P1 structural failure, `404 enroll_rejected` for any
 * expected post-P1 refusal, and the existing redacted transport-503 otherwise
 * (including injected audit failure, which rolls back and never collapses).
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Pool } from "pg";
import { validateConsumeCarrier } from "@weave/protocol";
import { ENROLL_ERROR_MESSAGE, resolveEnrollError } from "@weave/protocol";
import type { EnrollErrorCode } from "@weave/protocol";
import type { V1BoundaryController, V1Operation } from "./boundary.ts";
import { readStrictJsonBody } from "./json-body.ts";
import { consumePairingToken } from "../domain/pairing-consume.ts";

export const PAIRING_ENROLL_ROUTE = "/v1/hosts/enroll" as const;

const REQUIRED_KEYS = [
  "stableId",
  "hostPublic",
  "community",
  "device",
  "issuedAt",
  "consumeFreshness",
  "ownerProof",
  "hostProof",
] as const;

export interface PairingEnrollContext {
  db?: Pool;
  ready?: () => Promise<boolean>;
  boundary: V1BoundaryController;
}

function writeEnrollEnvelope(operation: V1Operation, code: EnrollErrorCode): void {
  const { status } = resolveEnrollError(code);
  operation.s8(status, code, ENROLL_ERROR_MESSAGE[code]);
}

export async function handlePairingEnroll(
  request: IncomingMessage,
  response: ServerResponse,
  ctx: PairingEnrollContext,
): Promise<void> {
  await ctx.boundary.execute(request, response, "pairing.enroll", async (operation) => {
    if (!ctx.db || !ctx.ready || !(await ctx.ready())) {
      operation.transport503("not_ready");
      return;
    }
    if (request.method !== "POST") {
      operation.dropAfterFlush();
      writeEnrollEnvelope(operation, "bad_request");
      return;
    }
    const contentType = request.headers["content-type"];
    const mediaType =
      typeof contentType === "string" ? contentType.split(";")[0].trim().toLowerCase() : "";
    if (mediaType !== "application/json") {
      operation.dropAfterFlush();
      writeEnrollEnvelope(operation, "bad_request");
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
      writeEnrollEnvelope(operation, "bad_request");
      return;
    }
    let carrier: {
      stableId: string;
      hostPublic: string;
      community: string;
      device: string;
      issuedAt: string;
      consumeFreshness: string;
      ownerProof: string;
      hostProof: string;
    };
    try {
      validateConsumeCarrier(body.value);
      carrier = body.value as typeof carrier;
    } catch {
      writeEnrollEnvelope(operation, "bad_request");
      return;
    }
    let result: { ok: boolean };
    try {
      result = await consumePairingToken(ctx.db, carrier, operation.requestId);
    } catch {
      operation.transport503("catch_all");
      return;
    }
    if (!result.ok) {
      writeEnrollEnvelope(operation, "enroll_rejected");
      return;
    }
    operation.success(200, { status: "accepted", requestId: operation.requestId }, "accepted");
  });
}
