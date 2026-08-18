#!/usr/bin/env node
/**
 * Subprocess-only Node runtime pinning for the installer.
 *
 * The installer is launched with a node binary that already satisfies the exact
 * pinned version gate (`process.versions.node`). Its children — bare `npm`,
 * `npm exec --package=pnpm@10.13.1 -- pnpm`, and every nested package lifecycle
 * script — are shell-style commands whose shebangs re-resolve `node` from
 * PATH. On a host whose ambient PATH holds an older node, an unchecked child
 * would silently run bootstrap and verify under that older node, which cannot
 * reproduce the pinned, engine-matched run we claim.
 *
 * To close that gap this module builds a child-only environment that prepends a
 * tiny shim directory whose `node` entry resolves to `process.execPath` — the
 * exact binary that launched the installer — so `#!/usr/bin/env node` and any
 * direct `node` invocation inside a child re-resolve to the same pinned binary.
 * The parent process environment is not mutated, and no global `pnpm` install
 * is introduced.
 */
import { mkdtempSync, symlinkSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";

const pathDelimiter = process.platform === "win32" ? ";" : ":";

let shimDir = null;

/**
 * Create (once) a subprocess-only bin directory whose `node` entry resolves to
 * `process.execPath`. Returns its absolute path.
 */
export function nodeShimDir() {
  if (shimDir) return shimDir;
  shimDir = mkdtempSync(join(tmpdir(), "weave-node-shim-"));
  const nodeTarget = join(shimDir, process.platform === "win32" ? "node.exe" : "node");
  try {
    symlinkSync(process.execPath, nodeTarget);
  } catch {
    copyFileSync(process.execPath, nodeTarget);
  }
  return shimDir;
}

/**
 * Build a child-only environment that resolves `node` to `process.execPath`.
 * The parent's `process.env` is spread as the base; only the returned object is
 * handed to child processes, so the parent environment is never changed.
 */
export function subprocessEnv() {
  const shim = nodeShimDir();
  const previous = process.env.PATH ?? "";
  return {
    ...process.env,
    PATH: [shim, previous].filter(Boolean).join(pathDelimiter),
  };
}
