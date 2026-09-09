import { createServer } from "node:http";
import type { Server } from "node:http";
import { PROTOCOL_NAME, PROTOCOL_VERSION } from "@weave/protocol";
import type { WireMessage } from "@weave/protocol";
import type { Pool } from "pg";
import { createDatabaseConfig, createDatabasePool, databaseUrlFromEnv } from "./db/pool.ts";
import { runMigrations } from "./db/migrate.ts";
import { logEvent } from "./log.ts";
import { handleRecoveryVerify, sendRecoveryV1Unknown } from "./http/recovery-verify.ts";
import { createV1Boundary } from "./http/boundary.ts";
import type { AdmissionConfig, OutcomeLogger, V1Operation } from "./http/boundary.ts";

export const component = {
  name: "server",
  protocol: `${PROTOCOL_NAME}/v${PROTOCOL_VERSION}`,
} as const;

export type ServerMessage = WireMessage;

export const DEFAULT_PORT = 8080;

/** Probes database readiness without exposing any connection detail. */
export type ReadinessCheck = () => Promise<boolean>;

/** Test-only registration seam for proving one boundary serves multiple `/v1` operations. */
export interface TestOnlyV1Operation {
  route: string;
  handle: (operation: V1Operation) => Promise<void>;
}

export interface ServerOptions {
  /** When absent, the server runs liveness-only (never ready). */
  readiness?: ReadinessCheck;
  /** Database pool to drain on shutdown, when one is configured. */
  pool?: Pool;
  /** M1.3.2 bounded admission control (in-flight limit + raw-body deadline). */
  admission?: AdmissionConfig;
  /** Narrow test/embedding seam for redacted terminal outcome capture. */
  outcomeLogger?: OutcomeLogger;
  /** Never configured by product startup; permits boundary integration tests without a public route. */
  testOnlyV1Operations?: ReadonlyMap<string, TestOnlyV1Operation>;
}

function sendJson(
  response: import("node:http").ServerResponse,
  status: number,
  body: Record<string, unknown>,
): void {
  if (response.writableEnded) return;
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

export function createWeaveServer(options: ServerOptions = {}): Server {
  const { readiness, admission } = options;
  const boundary = createV1Boundary({ admission, outcomeLogger: options.outcomeLogger });
  return createServer((request, response) => {
    const url = request.url ?? "";

    if (url === "/health") {
      sendJson(response, 200, { status: "ok", service: component.name });
      return;
    }

    if (url === "/ready") {
      if (!readiness) {
        sendJson(response, 503, { status: "not_ready", reason: "no_database_configured" });
        return;
      }
      readiness()
        .then((ok) => sendJson(response, ok ? 200 : 503, { status: ok ? "ready" : "not_ready" }))
        .catch(() => sendJson(response, 503, { status: "not_ready" }));
      return;
    }

    // M1.3.2 — the read-only recovery verification endpoint lives under /v1.
    // Any other /v1 path is the generic S8 not_found; /health, /ready, and the
    // legacy non-/v1 404 shape are unchanged.
    if (url.startsWith("/v1/")) {
      if (url === "/v1/identity/recovery/verify") {
        void handleRecoveryVerify(request, response, { db: options.pool, ready: readiness, boundary });
        return;
      }
      const testOperation = options.testOnlyV1Operations?.get(url);
      if (testOperation) {
        void boundary.execute(request, response, testOperation.route, testOperation.handle);
        return;
      }
      sendRecoveryV1Unknown(response, boundary);
      return;
    }

    sendJson(response, 404, { status: "not_found" });
  });
}

export interface StartedServer {
  server: Server;
  /** Present only when a database was configured. */
  pool?: Pool;
}

export function startWeaveServer(port: number = DEFAULT_PORT, options: ServerOptions = {}): StartedServer {
  const server = createWeaveServer(options);
  server.listen(port, () => {
    const address = server.address();
    const bound =
      typeof address === "object" && address !== null ? address.port : port;
    logEvent("http.listening", { host: "127.0.0.1", port: bound });
  });
  return { server, pool: options.pool };
}

if (import.meta.main) {
  const port = Number(process.env.PORT ?? DEFAULT_PORT);

  const connectionString = databaseUrlFromEnv();
  const pool = connectionString ? createDatabasePool(createDatabaseConfig(connectionString)) : undefined;

  let readiness: ReadinessCheck | undefined;
  if (pool) {
    const started = Date.now();
    try {
      const result = await runMigrations(pool);
      logEvent("migrations.complete", {
        applied: result.applied.length,
        skipped: result.skipped,
        durationMs: Date.now() - started,
      });
      readiness = async () => {
        await pool.query("SELECT 1");
        return true;
      };
    } catch (error) {
      logEvent("migrations.failed", {
        reason: error instanceof Error ? error.message : "unknown",
        durationMs: Date.now() - started,
      });
    }
  }

  const { server } = startWeaveServer(port, { readiness, pool });

  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    logEvent("shutdown.signal", { reason: "closing" });
    server.closeIdleConnections?.();
    server.close(async () => {
      await pool?.end();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 1500).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
