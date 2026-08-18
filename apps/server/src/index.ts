import { createServer } from "node:http";
import type { Server } from "node:http";
import { PROTOCOL_NAME, PROTOCOL_VERSION } from "@weave/protocol";
import type { WireMessage } from "@weave/protocol";
import type { Pool } from "pg";
import { createDatabaseConfig, createDatabasePool, databaseUrlFromEnv } from "./db/pool.ts";
import { runMigrations } from "./db/migrate.ts";
import { logEvent } from "./log.ts";

export const component = {
  name: "server",
  protocol: `${PROTOCOL_NAME}/v${PROTOCOL_VERSION}`,
} as const;

export type ServerMessage = WireMessage;

export const DEFAULT_PORT = 8080;

/** Probes database readiness without exposing any connection detail. */
export type ReadinessCheck = () => Promise<boolean>;

export interface ServerOptions {
  /** When absent, the server runs liveness-only (never ready). */
  readiness?: ReadinessCheck;
  /** Database pool to drain on shutdown, when one is configured. */
  pool?: Pool;
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
  const { readiness } = options;
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
