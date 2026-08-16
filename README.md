# weave
Weave — a self-hosted collaboration community where humans and AI agents are both first-class members, each running on infrastructure and credentials their own owner controls.

## Repository layout

- `apps/server` — the server/relay entry point
- `apps/daemon` — the host daemon entry point
- `apps/client` — the human client entry point
- `packages/protocol` — the shared TypeScript protocol contract

The three applications import `@weave/protocol` directly from its workspace
source. The protocol is intentionally erasable TypeScript: Node 24.12.0 or
newer can run the server and daemon without a generated JavaScript build, and CI
type-checks every consumer with `erasableSyntaxOnly` enabled. The client is an
unopinionated type-checking stub until its browser/Tauri boundary is selected.

## Development

Requirements: Node `24.12.0` or newer. The repository records pnpm `10.13.1`
in `packageManager`; use npm's pinned execution path rather than a globally
installed package manager.

```sh
npm exec --yes --package=pnpm@10.13.1 -- pnpm install
npm exec --yes --package=pnpm@10.13.1 -- pnpm check
npm exec --yes --package=pnpm@10.13.1 -- pnpm test
```

The stable verification command used by the deployment installer is:

```sh
npm exec --yes --package=pnpm@10.13.1 -- pnpm verify
```

## One-command installer and Compose skeleton

The deployment foundation ships a strict, ordered-gate installer and a minimal
Compose skeleton so a fresh machine can stand up an empty Weave:

```sh
node scripts/install.mjs
```

The installer is online-first and fail-closed. It runs, in order: a numeric
Node `>=24.12.0` check, `npm` presence, `docker compose version`, `docker info`,
the `docker compose up --wait` capability check (the installed client must
advertise the standalone `--wait` and `--wait-timeout` options before any
mutation), the pinned bootstrap
`npm exec --yes --package=pnpm@10.13.1 -- pnpm install`, the pinned
verification gate `npm exec --yes --package=pnpm@10.13.1 -- pnpm verify`,
`docker compose pull`, a fresh-project preflight, and only then
`docker compose up -d --wait --wait-timeout 300`. Every failure before
`up -d` names its failing prerequisite and states that offline installation is
unsupported. A client that does not advertise health-wait support fails closed
before the bootstrap, verify, pull, or preflight steps run, so no registry,
image, container, or volume state is touched. It never depends on a system
pnpm or Corepack.

Startup is health-qualified and transactional for a fresh project. The
capability gate runs before any mutation, then the installer resolves the
Compose project name and refuses if any containers or volumes already exist
for it — it never tears down an existing deployment. It starts the stack with
`docker compose up -d --wait --wait-timeout 300` and claims success only after
**both** `db` and `server` have passed their Compose health checks under the
300-second bounded timeout; a detached `up` that merely starts the containers
is never treated as success. If `up`, the image build, or the health wait
fails after a clean preflight, it rolls back exactly the project with
`docker compose down --volumes --remove-orphans`, preserves the original
failure, and fails loudly if the rollback itself fails.

The Compose skeleton starts a `postgres:16-alpine` database (the Weave backing
store) with a named `weave-data` volume and a `server` service built from the
`Dockerfile`. The server is a minimal long-running entry point exposing only a
`/health` liveness endpoint (no product API, auth, or persistence), with a
Compose healthcheck and `restart: unless-stopped`.

For this repository foundation, a clean clone can import and run the Node
server entry point immediately after installation:

```sh
git clone https://github.com/jmpijll/weave.git
cd weave
npm exec --yes --package=pnpm@10.13.1 -- pnpm install && node apps/server/src/index.ts
```
