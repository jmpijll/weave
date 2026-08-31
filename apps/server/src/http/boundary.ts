import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { logEvent } from "../log.ts";
import type { LogFields } from "../log.ts";

export interface AdmissionConfig {
  maxInFlight: number;
  bodyDeadlineMs: number;
}

export const DEFAULT_ADMISSION: Readonly<AdmissionConfig> = Object.freeze({
  maxInFlight: 8,
  bodyDeadlineMs: 10_000,
});

export type OutcomeLogger = (event: "http.outcome" | "http.transport_503", fields: LogFields) => void;

export interface V1Operation {
  requestId: string;
  admission: Readonly<AdmissionConfig>;
  dropAfterFlush: () => void;
  success: (status: number, body: Record<string, unknown>, outcome: string) => void;
  s8: (status: number, code: string, message: string) => void;
  transport503: (outcome: "capacity" | "not_ready" | "deadline" | "catch_all") => void;
}

export interface V1BoundaryController {
  execute: (
    request: IncomingMessage,
    response: ServerResponse,
    route: string,
    handler: (operation: V1Operation) => Promise<void>,
  ) => Promise<void>;
  unknown: (response: ServerResponse) => void;
}

export interface V1BoundaryOptions {
  admission?: AdmissionConfig;
  /** Narrow test/embedding seam; production defaults to the redacted logger. */
  outcomeLogger?: OutcomeLogger;
}

const RETRY_AFTER_SECONDS = "1";

/**
 * Creates one `/v1` admission and terminal-outcome boundary for one server.
 * It owns no persistence and logs only an allowlisted outcome record.
 */
export function createV1Boundary(options: V1BoundaryOptions = {}): V1BoundaryController {
  const admission = options.admission ?? DEFAULT_ADMISSION;
  const outcomeLogger = options.outcomeLogger ?? logEvent;
  let inFlight = 0;

  const writeJson = (response: ServerResponse, status: number, body: Record<string, unknown>, headers: Record<string, string> = {}): void => {
    if (response.writableEnded) return;
    response.writeHead(status, { "content-type": "application/json; charset=utf-8", ...headers });
    response.end(JSON.stringify(body));
  };

  const duration = (startedAt: number): number => Math.max(0, Date.now() - startedAt);

  const writeS8 = (
    response: ServerResponse,
    route: string,
    startedAt: number,
    requestId: string,
    status: number,
    code: string,
    message: string,
  ): void => {
    writeJson(response, status, { error: { code, message, requestId } });
    outcomeLogger("http.outcome", { route, status, outcome: code, durationMs: duration(startedAt), requestId });
  };

  const writeSuccess = (
    response: ServerResponse,
    route: string,
    startedAt: number,
    requestId: string,
    status: number,
    body: Record<string, unknown>,
    outcome: string,
  ): void => {
    writeJson(response, status, body);
    outcomeLogger("http.outcome", { route, status, outcome, durationMs: duration(startedAt), requestId });
  };

  const writeTransport503 = (
    request: IncomingMessage,
    response: ServerResponse,
    route: string,
    startedAt: number,
    outcome: "capacity" | "not_ready" | "deadline" | "catch_all",
  ): void => {
    dropAfterFlush(request, response);
    writeJson(response, 503, { status: "not_ready" }, { "retry-after": RETRY_AFTER_SECONDS });
    outcomeLogger("http.transport_503", {
      route,
      status: 503,
      outcome,
      durationMs: duration(startedAt),
      retryAfter: RETRY_AFTER_SECONDS,
      correlationId: randomUUID(),
    });
  };

  return {
    async execute(request, response, route, handler): Promise<void> {
      const startedAt = Date.now();
      if (inFlight >= admission.maxInFlight) {
        writeTransport503(request, response, route, startedAt, "capacity");
        return;
      }

      inFlight++;
      let terminal = false;
      const requestId = randomUUID();
      const operation: V1Operation = {
        requestId,
        admission,
        dropAfterFlush: () => dropAfterFlush(request, response),
        success: (status, body, outcome) => {
          if (terminal) return;
          terminal = true;
          writeSuccess(response, route, startedAt, requestId, status, body, outcome);
        },
        s8: (status, code, message) => {
          if (terminal) return;
          terminal = true;
          writeS8(response, route, startedAt, requestId, status, code, message);
        },
        transport503: (outcome) => {
          if (terminal) return;
          terminal = true;
          writeTransport503(request, response, route, startedAt, outcome);
        },
      };

      try {
        await handler(operation);
      } catch {
        operation.transport503("catch_all");
      } finally {
        inFlight--;
      }
    },
    unknown(response): void {
      const startedAt = Date.now();
      const requestId = randomUUID();
      writeS8(response, "v1.unknown", startedAt, requestId, 404, "not_found", "resource not found");
    },
  };
}

/** Drop an unread request body only after the response has had a chance to flush. */
export function dropAfterFlush(request: IncomingMessage, response: ServerResponse): void {
  if (request.destroyed || response.writableEnded) {
    if (!request.destroyed) request.destroy();
    return;
  }
  response.once("finish", () => {
    if (!request.destroyed) request.destroy();
  });
}
