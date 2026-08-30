#!/usr/bin/env node
/**
 * Single reviewed test inventory for Weave.
 *
 * The package `test` command invokes exactly this module once. It is the sole
 * place that names the eight existing test layers, so the T4 and T9 command
 * strings can no longer drift apart:
 *
 *   1. verify-workspaces.mjs            workspace wiring (protocol dependency,
 *                                        erasableSyntaxOnly)
 *   2. smoke.mjs                        runtime entry points + /health
 *   3. verify-evidence.mjs              evidence/ retention policy + reports
 *   4. evidence-contract.test.mjs       evidence contract regression (script)
 *   5. node-runtime-regression.test.mjs installer Node floor regression (script)
 *   6. t4-codex-delivery-contract.test.mjs T4 delivery contract (node:test)
 *   7. m1-1-migrations.test.mts        M1.1 PostgreSQL migration + credential-tree
 *                                      integration (node:test; needs DATABASE_URL)
 *   8. m1-2-membership-access.test.mts M1.2 membership/role/space-access PostgreSQL
 *                                      integration (node:test; needs DATABASE_URL)
 *   9. m1-3-recovery-schema.test.mts   M1.3.1 recovery verifier/challenge schema +
 *                                      persisted v1 version metadata (node:test;
 *                                      needs DATABASE_URL)
 *  10. m1-3-2-recovery-verify.test.mts  M1.3.2 read-only POST /v1/identity/recovery/verify
 *                                      app-boundary negative + conformance suite
 *                                      (node:test; needs DATABASE_URL)
 *
 * Each layer runs as its own child process with the pinned `node` binary
 * (process.execPath), so a failure is isolated and attributable. A non-zero
 * exit from any layer fails the run.
 */
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const INVENTORY = [
  { name: "verify-workspaces.mjs", args: ["scripts/verify-workspaces.mjs"] },
  { name: "smoke.mjs", args: ["scripts/smoke.mjs"] },
  { name: "verify-evidence.mjs", args: ["scripts/verify-evidence.mjs"] },
  { name: "evidence-contract.test.mjs", args: ["scripts/evidence-contract.test.mjs"] },
  { name: "node-runtime-regression.test.mjs", args: ["scripts/node-runtime-regression.test.mjs"] },
  { name: "t4-codex-delivery-contract.test.mjs", args: ["--test", "scripts/t4-codex-delivery-contract.test.mjs"] },
  { name: "m1-1-migrations.test.mts", args: ["--experimental-strip-types", "--test", "apps/server/test/m1-1-migrations.test.mts"] },
  { name: "m1-2-membership-access.test.mts", args: ["--experimental-strip-types", "--test", "apps/server/test/m1-2-membership-access.test.mts"] },
  { name: "m1-3-recovery-schema.test.mts", args: ["--experimental-strip-types", "--test", "apps/server/test/m1-3-recovery-schema.test.mts"] },
  { name: "m1-3-2-recovery-verify.test.mts", args: ["--experimental-strip-types", "--test", "apps/server/test/m1-3-2-recovery-verify.test.mts"] },
];

let failed = 0;
for (const entry of INVENTORY) {
  const result = spawnSync(process.execPath, entry.args, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env },
  });
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  if (result.status === 0) {
    console.log(`ok - ${entry.name}`);
  } else {
    failed += 1;
    console.error(`not ok - ${entry.name} (exit ${result.status})`);
  }
}

console.log(`test inventory: ${INVENTORY.length - failed}/${INVENTORY.length} layers passed`);
if (failed > 0) process.exitCode = 1;
