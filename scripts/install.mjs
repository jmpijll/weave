import { spawnSync } from "node:child_process";

const OFFLINE_MSG =
  "Offline installation is not supported by this release path.";
const PINNED_PNPM = ["npm", "exec", "--yes", "--package=pnpm@10.13.1", "--", "pnpm"];
// Bounded health wait: `docker compose up --wait` must observe both services
// healthy within this many seconds or the install fails and rolls back. At
// least ~2x the composed worst-case healthcheck budget (db ~100s, then server
// ~110s after the db-healthy dependency) plus headroom.
const HEALTH_WAIT_SECONDS = 300;

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
const bootstrap = run(PINNED_PNPM[0], [...PINNED_PNPM.slice(1), "install"]);
if (bootstrap.status !== 0) {
  fail(
    "pnpm bootstrap",
    "npm exec --package=pnpm@10.13.1 -- pnpm install failed; the npm registry is likely unreachable",
  );
}
console.log("[weave-install] pnpm bootstrap ok");

// 6. Repository verification gate: the canonical pinned `pnpm verify` command
//    (CONTRIBUTING.md / README). Runs after bootstrap, before any image pull,
//    so a failing or offline verification stops before Compose state exists.
const verify = run(PINNED_PNPM[0], [...PINNED_PNPM.slice(1), "verify"]);
if (verify.status !== 0) {
  fail(
    "pnpm verify",
    "npm exec --package=pnpm@10.13.1 -- pnpm verify failed; repository checks did not pass",
  );
}
console.log("[weave-install] pnpm verify ok");

// 7. OCI image pull reachability, before any container is started.
const pull = run("docker", ["compose", "pull"]);
if (pull.status !== 0) {
  fail("oci image pull", "docker compose pull failed; the OCI registry is unreachable");
}
console.log("[weave-install] oci image pull ok");

// 8. Fresh-project preflight: this installer only starts an empty Weave and
//    must never tear down an existing deployment. Resolve the Compose project
//    name, then refuse loudly if any container or volume already exists for it.
//    Containers are queried by the Compose project label directly so
//    orphan/project-labelled state is found regardless of declared services.
//    Both queries are status-checked; a failed query fails closed before any
//    mutation.
const projectName = resolveProjectName();
const preflightContainers = run(
  "docker",
  [
    "ps",
    "-a",
    "--filter",
    `label=com.docker.compose.project=${projectName}`,
    "--format",
    "{{.Names}}",
  ],
  { stdio: "pipe" },
);
if (preflightContainers.status !== 0) {
  fail(
    "project preflight",
    `docker ps -a (project label ${projectName}) failed; cannot verify a fresh project`,
  );
}
const preflightVolumes = run(
  "docker",
  [
    "volume",
    "ls",
    "--filter",
    `label=com.docker.compose.project=${projectName}`,
    "--format",
    "{{.Name}}",
  ],
  { stdio: "pipe" },
);
if (preflightVolumes.status !== 0) {
  fail(
    "project preflight",
    `docker volume ls (project label ${projectName}) failed; cannot verify a fresh project`,
  );
}
const containers = preflightContainers.stdout.toString().trim().split("\n").filter(Boolean);
const volumes = preflightVolumes.stdout.toString().trim().split("\n").filter(Boolean);
if (containers.length > 0 || volumes.length > 0) {
  console.error(
    `[weave-install] refusing to start: Compose project "${projectName}" already has state`,
  );
  if (containers.length > 0) {
    console.error(`[weave-install]   existing containers: ${containers.join(", ")}`);
  }
  if (volumes.length > 0) {
    console.error(`[weave-install]   existing volumes: ${volumes.join(", ")}`);
  }
  console.error(
    "[weave-install] the installer never tears down an existing deployment; use a fresh project",
  );
  process.exit(1);
}
console.log(`[weave-install] project "${projectName}" preflight clean: no containers or volumes`);

// 9. Health-wait capability gate (client-side, before any mutation). Success
//    below depends on `docker compose up --wait`; validate the installed
//    Compose client advertises it rather than silently relying on an arbitrary
//    Compose-v2 version.
const waitHelp = run("docker", ["compose", "up", "--help"], { stdio: "pipe" });
if (waitHelp.status !== 0) {
  fail(
    "compose up --wait capability",
    "docker compose up --help failed; cannot verify health-wait support",
  );
}
const helpText = `${waitHelp.stdout ?? ""}${waitHelp.stderr ?? ""}`;
if (!helpText.includes("--wait") || !helpText.includes("--wait-timeout")) {
  fail(
    "compose up --wait capability",
    "installed Compose does not advertise `up --wait --wait-timeout`; health-qualified startup is not possible",
  );
}
console.log("[weave-install] docker compose up --wait --wait-timeout capability confirmed");

// 10. Start the stack and wait for BOTH Compose health checks under the bounded
//     timeout above. Detached `up` alone only starts containers; `--wait`
//     makes it exit 0 only after db and server have passed their health checks,
//     so a crashed or unhealthy service (or a timeout) exits non-zero here and
//     never reports false success. If up/build/health-wait fails after the clean
//     preflight, roll back exactly this project (containers, volumes, orphans)
//     and preserve the original failure; if the rollback itself fails, fail
//     loudly. Success is claimed only when the health wait succeeds.
const up = run("docker", [
  "compose",
  "up",
  "-d",
  "--wait",
  "--wait-timeout",
  String(HEALTH_WAIT_SECONDS),
]);
if (up.status !== 0) {
  console.error(
    `[weave-install] docker compose up -d --wait --wait-timeout ${HEALTH_WAIT_SECONDS} failed (build, start, or health-wait timeout); rolling back this fresh project`,
  );
  const rollback = run("docker", [
    "compose",
    "down",
    "--volumes",
    "--remove-orphans",
  ]);
  if (rollback.status !== 0) {
    console.error(
      `[weave-install] rollback FAILED: docker compose down --volumes --remove-orphans exited ${rollback.status}`,
    );
    process.exit(rollback.status ?? 1);
  }
  console.error(
    "[weave-install] rollback complete: project containers, volumes, and database state removed",
  );
  process.exit(up.status ?? 1);
}
console.log(
  "[weave-install] Compose startup completed: db and the empty Weave server passed " +
    `their health checks within ${HEALTH_WAIT_SECONDS}s (liveness only, no product API).`,
);

function resolveProjectName() {
  const config = run("docker", ["compose", "config", "--format", "json"], { stdio: "pipe" });
  if (config.status !== 0) {
    fail("compose project name", "docker compose config failed");
  }
  try {
    const parsed = JSON.parse(config.stdout.toString());
    if (typeof parsed.name === "string" && parsed.name.length > 0) {
      return parsed.name;
    }
    fail("compose project name", "docker compose config returned no name");
  } catch {
    fail("compose project name", "docker compose config output was not parseable JSON");
  }
}
