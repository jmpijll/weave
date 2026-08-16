import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const runtimeApplications = ["server", "daemon"];
const rawPackages = [
  { name: "protocol", packageRoot: resolve(root, "packages/protocol") },
  ...runtimeApplications.map((name) => ({
    name,
    packageRoot: resolve(root, "apps", name),
  })),
];
const clientEntry = resolve(root, "apps/client/src/index.ts");
const serverEntry = resolve(root, "apps/server/src/index.ts");

for (const application of runtimeApplications) {
  const entry = resolve(root, "apps", application, "src/index.ts");
  const source = await readFile(entry, "utf8");
  assert.match(source, /import type .* from ["']@weave\/protocol["']/s);
  const module = await import(pathToFileURL(entry).href);
  assert.deepEqual(module.component, {
    name: application,
    protocol: "weave/v1",
  });
}

const clientSource = await readFile(clientEntry, "utf8");
assert.match(clientSource, /import type .* from ["']@weave\/protocol["']/s);
assert.match(clientSource, /export type ClientMessage/);

for (const { name, packageRoot } of rawPackages) {
  const fixture = resolve(packageRoot, "fixtures/non-erasable-enum.ts");

  if (runtimeApplications.includes(name)) {
    const enumCheck = spawnSync(process.execPath, [fixture], { encoding: "utf8" });
    assert.notEqual(enumCheck.status, 0, `${name} must reject non-erasable enum syntax`);
    assert.match(enumCheck.stderr, /ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX/);
  }

  const fixtureSource = await readFile(fixture, "utf8");
  assert.match(fixtureSource, /^enum /m);
  assert.match(fixtureSource, /^namespace /m);
  assert.match(fixtureSource, /constructor\(private readonly value: string\)/);

  const tsc = resolve(
    root,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "tsc.cmd" : "tsc",
  );
  const compileCheck = spawnSync(
    tsc,
    ["--noEmit", "--pretty", "false", "-p", resolve(packageRoot, "fixtures/tsconfig.json")],
    { encoding: "utf8" },
  );
  const diagnostics = `${compileCheck.stdout}\n${compileCheck.stderr}`;
  assert.notEqual(
    compileCheck.status,
    0,
    `${name} fixture must fail compilation with erasableSyntaxOnly enabled`,
  );
  assert.ok(
    (diagnostics.match(/TS1294/g) ?? []).length >= 3,
    `${name} fixture must report enum, namespace, and parameter-property diagnostics`,
  );
}

console.log("runtime imports verified: server, daemon; client type import verified");
console.log("raw server and daemon entry points reject enum syntax as expected");

// Long-running entry point: start on an ephemeral port, verify /health, then
// terminate cleanly via SIGTERM. The server exposes only a liveness endpoint.
const server = spawn(process.execPath, [serverEntry], {
  env: { ...process.env, PORT: "0" },
  stdio: ["ignore", "pipe", "pipe"],
});

let exited = false;
const exitCode = new Promise((resolveExit, rejectExit) => {
  server.on("exit", (code, signal) => {
    exited = true;
    resolveExit({ code, signal });
  });
  server.on("error", rejectExit);
});

let output = "";
const listening = new Promise((resolveListening, rejectListening) => {
  const timer = setTimeout(() => {
    server.kill("SIGKILL");
    rejectListening(new Error(`server did not report a listening address:\n${output}`));
  }, 15_000);
  const onData = (chunk) => {
    output += chunk.toString();
    const match = output.match(/health endpoint listening at http:\/\/127\.0\.0\.1:(\d+)/);
    if (match) {
      clearTimeout(timer);
      resolveListening(Number(match[1]));
    }
  };
  server.stdout.on("data", onData);
  server.stderr.on("data", onData);
});

try {
  const port = await listening;
  const response = await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(response.status, 200);
  const health = await response.json();
  assert.deepEqual(health, { status: "ok", service: "server" });
  console.log(`server /health verified on ephemeral port ${port}: ${JSON.stringify(health)}`);

  assert.equal(exited, false, "server must still be running before termination");
  server.kill("SIGTERM");
  const result = await exitCode;
  assert.equal(result.signal, null, "server must exit via its graceful shutdown path, not a signal kill");
  assert.equal(result.code, 0, "server must terminate cleanly with exit code 0");
  assert.ok(exited, "server process must terminate after SIGTERM");
  console.log("server entry point terminated cleanly after SIGTERM");
} finally {
  if (!exited) server.kill("SIGKILL");
}
