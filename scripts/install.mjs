import { spawnSync } from "node:child_process";

const OFFLINE_MSG =
  "Offline installation is not supported by this release path.";

function fail(prerequisite, detail) {
  console.error(`[weave-install] prerequisite failed: ${prerequisite}`);
  if (detail) console.error(`[weave-install] ${detail}`);
  console.error(`[weave-install] ${OFFLINE_MSG}`);
  process.exit(1);
}

function run(command, args, { stdio = "inherit" } = {}) {
  return spawnSync(command, args, { stdio });
}

// 1. Node floor (numeric >=24.12.0; never lexical, never engines-reliant).
const [maj, min, patch] = process.versions.node.split(".").map(Number);
const nodeOk =
  maj > 24 || (maj === 24 && min > 12) || (maj === 24 && min === 12 && patch >= 0);
if (!nodeOk) {
  fail("node version", `Node >=24.12.0 required; found ${process.versions.node}`);
}
console.log(`[weave-install] node ${process.versions.node} ok`);

// 2. npm present.
const npmCheck = run("npm", ["--version"], { stdio: "pipe" });
if (npmCheck.status !== 0) {
  fail("npm", "npm was not found or not executable");
}
console.log(`[weave-install] npm ${npmCheck.stdout.toString().trim()} ok`);

// 3. Docker Compose v2 (client-side, daemon-independent).
const composeCheck = run("docker", ["compose", "version"], { stdio: "pipe" });
if (composeCheck.status !== 0) {
  fail("docker compose v2", composeCheck.stderr?.toString()?.trim());
}
console.log("[weave-install] docker compose v2 ok");

// 4. Docker daemon reachable.
const daemonCheck = run("docker", ["info"], { stdio: "pipe" });
if (daemonCheck.status !== 0) {
  const firstLine = daemonCheck.stderr?.toString()?.trim()?.split("\n")?.[0];
  fail("docker daemon", firstLine);
}
console.log("[weave-install] docker daemon ok");

// 5. Pinned pnpm bootstrap (registry required). Fails closed when the npm
//    registry is unreachable, before any container, volume, or database state.
const bootstrap = run("npm", [
  "exec",
  "--yes",
  "--package=pnpm@10.13.1",
  "--",
  "pnpm",
  "install",
]);
if (bootstrap.status !== 0) {
  fail(
    "pnpm bootstrap",
    "npm exec --package=pnpm@10.13.1 failed; the npm registry is likely unreachable",
  );
}
console.log("[weave-install] pnpm bootstrap ok");

// 6. OCI image pull reachability, before any container is started.
const pull = run("docker", ["compose", "pull"]);
if (pull.status !== 0) {
  fail("oci image pull", "docker compose pull failed; the OCI registry is unreachable");
}
console.log("[weave-install] oci image pull ok");

// 7. Only now start the stack.
const up = run("docker", ["compose", "up", "-d"]);
if (up.status !== 0) {
  console.error("[weave-install] docker compose up -d failed");
  process.exit(up.status ?? 1);
}
console.log(
  "[weave-install] Compose startup completed. The server is currently a " +
    "non-listening protocol stub (exits by design until M1+); postgres is the " +
    "running empty Weave state.",
);
