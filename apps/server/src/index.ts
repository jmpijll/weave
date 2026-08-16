import { createServer } from "node:http";
import type { Server } from "node:http";
import { PROTOCOL_NAME, PROTOCOL_VERSION } from "@weave/protocol";
import type { WireMessage } from "@weave/protocol";

export const component = {
  name: "server",
  protocol: `${PROTOCOL_NAME}/v${PROTOCOL_VERSION}`,
} as const;

export type ServerMessage = WireMessage;

export const DEFAULT_PORT = 8080;

export function createWeaveServer(): Server {
  return createServer((request, response) => {
    if (request.url !== "/health") {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ status: "not_found" }));
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "ok", service: component.name }));
  });
}

export function startWeaveServer(port: number = DEFAULT_PORT): Server {
  const server = createWeaveServer();
  server.listen(port, () => {
    const address = server.address();
    const bound =
      typeof address === "object" && address !== null ? address.port : port;
    console.log(`[weave-server] health endpoint listening at http://127.0.0.1:${bound}`);
  });
  return server;
}

if (import.meta.main) {
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  const server = startWeaveServer(port);

  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    console.log("[weave-server] received shutdown signal, closing");
    server.closeIdleConnections?.();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1500).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
