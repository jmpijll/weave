#!/usr/bin/env node
/**
 * Focused regression for the installer Node-runtime pinning fix (T9).
 *
 * On a host whose ambient PATH holds an older `node`, a child spawned by the
 * installer could silently re-resolve `node` (via `#!/usr/bin/env node`) to
 * that older binary, so bootstrap and verify would NOT run under the Node
 * binary the parent launched with. This regression proves `subprocessEnv()`
 * prepends a shim that resolves `node` to `process.execPath`, regardless of
 * what the ambient PATH would have selected first.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, delimiter } from "node:path";
import { subprocessEnv } from "./node-runtime-env.mjs";

// Documented Node floor (numeric >=24.12.0), consistent with scripts/install.mjs.
const NODE_FLOOR = [24, 12, 0];

// Numeric >= floor comparison (never lexical), mirroring the install gate.
// Returns true for the floor and every floor-permitted newer runtime.
function atLeastFloor(nodeVersion) {
  const v = String(nodeVersion).replace(/^v/, "").split(".").map(Number);
  for (let i = 0; i < NODE_FLOOR.length; i++) {
    if (v[i] > NODE_FLOOR[i]) return true;
    if (v[i] < NODE_FLOOR[i]) return false;
  }
  return true;
}

// A floor-permitted newer version must never be rejected (the regression is
// a floor gate, not a patch-exact pin).
function testFloorGate() {
  const cases = [
    ["22.22.3", false],
    ["24.11.9", false],
    ["24.12.0", true],
    ["24.12.1", true],
    ["24.13.0", true],
    ["25.0.0", true],
    ["26.1.0", true],
  ];
  for (const [ver, expected] of cases) {
    assert.equal(atLeastFloor(ver), expected, `floor gate for ${ver}`);
  }
}

testFloorGate();

const originalPath = process.env.PATH;

async function testAmbientOldNodeCannotWin() {
  const dir = await mkdtemp(join(tmpdir(), "weave-node-regress-"));
  try {
    // A fake, older-looking `node` that, if selected, would run under a
    // different runtime. It prints a sentinel only when it is the resolved
    // executable, so any selection of it is observable.
    const fakeNode = join(dir, "node");
    await writeFile(fakeNode, "#!/bin/sh\necho FAKE_NODE_PICKED\n", "utf8");
    await chmod(fakeNode, 0o755);

    // Model the vulnerable ambient PATH: the fake/old node comes FIRST.
    process.env.PATH = `${dir}${delimiter}${originalPath}`;

    // Prove the bug precondition: with the raw ambient PATH, `node` resolves
    // to the old/fake binary (this is what an unfixed child would inherit).
    const ambientSelection = execFileSync("node", ["-e", "1"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    assert.match(ambientSelection, /FAKE_NODE_PICKED/, "ambient PATH must select the old node");

    // Prove the fix: the subprocess-only env prepends a shim whose `node`
    // resolves to process.execPath, so a child launched under it runs the
    // pinned binary, never the older PATH node.
    const childEnv = subprocessEnv();
    assert.ok(String(childEnv.PATH).startsWith(`${process.execPath}`) === false, "PATH is shim-dir prefixed, not a literal execPath");
    const resolved = execFileSync("node", ["-e", "console.log(process.execPath)"], {
      encoding: "utf8",
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    assert.equal(resolved, process.execPath, "child node must resolve to process.execPath (pinned binary)");

    // This regression itself must run under the documented Node floor (numeric
    // >=24.12.0), never a patch-exact pin: a floor-permitted newer runtime is
    // accepted, exactly as in scripts/install.mjs.
    assert.ok(
      atLeastFloor(process.version.slice(1)),
      `this regression must run under Node >=24.12.0 (running ${process.version})`
    );
  } finally {
    process.env.PATH = originalPath;
    await rm(dir, { recursive: true, force: true });
  }
}

await testAmbientOldNodeCannotWin();
console.log(
  `ok - child node resolves to process.execPath (floor Node >=24.12.0, running ${process.version}) even when ambient PATH holds an older node`
);
