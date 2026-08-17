import assert from "node:assert/strict";
import test from "node:test";
import { access, lstat, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assertArtifactAggregateBinding,
  assertRunnerEnvironment,
  assertPrivacySafeEvidence,
  assertSupportedHarnessVersions,
  computeArtifactsSha256,
  environmentEvidence,
  mergedPrompt,
  nativeSteerAdvertised,
  selectDeliveryPath,
  typedConfigTreeDiff,
} from "./t4-codex-delivery-contract.mjs";
import { adapterInvocation, resolveArtifactsDir } from "./t4-codex-delivery.mjs";
import { renderReport, T4_RESULT_KEYS, validateSummary } from "./evidence-contract.mjs";

const ranges = {
  codexCli: { minInclusive: "0.145.0", maxExclusive: "0.146.0" },
  acpAdapter: { minInclusive: "1.1.7", maxExclusive: "1.2.0" },
};

function validT4Summary(overrides = {}) {
  const results = Object.fromEntries(T4_RESULT_KEYS.map((key) => [key, "PASS"]));
  return {
    schemaVersion: "1.0.0",
    spike: "t4-codex",
    capturedAt: "2026-08-17T16:06:15Z",
    publicProvenance: { integrationCommit: "0".repeat(40) },
    localProvenance: {
      visibility: "not-published",
      runnerSha: "1".repeat(40),
      captureSha256: "2".repeat(64),
      recordId: "accepted-local-record",
    },
    environment: {
      os: "macos",
      osVersion: "25.5.0",
      harness: "codex",
      harnessVersion: "0.145.0",
      adapterName: "@agentclientprotocol/codex-acp",
      adapterVersion: "1.1.7",
      nodePinned: "24.12.0",
      platform: "darwin-arm64",
      nodePinnedMatched: true,
    },
    results,
    ...overrides,
  };
}

async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

test("accepts exactly the reviewed T4 result key set", () => {
  const summary = validT4Summary();
  assert.deepEqual(Object.keys(summary.results), T4_RESULT_KEYS);
  assert.deepEqual(validateSummary(summary), []);
});

test("rejects unknown or missing T4 result keys", () => {
  const unknown = validT4Summary();
  unknown.results.unreviewedCriterion = "PASS";
  assert.ok(validateSummary(unknown).some((error) => error.includes("unreviewedCriterion")));

  const missing = validT4Summary();
  delete missing.results.nativeSteeringAdvertised;
  assert.ok(validateSummary(missing).some((error) => error.includes("nativeSteeringAdvertised") && error.includes("missing")));
});

test("rejects unsafe T4 values and non-status results", () => {
  const unsafe = validT4Summary();
  unsafe.environment.platform = "runner-hostname";
  unsafe.environment.nodePinned = `24.12.0 ${join(tmpdir(), "synthetic-path")}`;
  unsafe.localProvenance.recordId = "synthetic-run-record";
  unsafe.results.midTurnDelivery = join(tmpdir(), "synthetic-capture");
  const errors = validateSummary(unsafe);
  assert.ok(errors.some((error) => error.includes("environment.platform")));
  assert.ok(errors.some((error) => error.includes("environment.nodePinned")));
  assert.ok(errors.some((error) => error.includes("localProvenance.recordId")));
  assert.ok(errors.some((error) => error.includes("results.midTurnDelivery")));
});

test("round-trips the fixed T4 summary into a deterministic report", () => {
  const summary = validT4Summary();
  const first = renderReport(summary);
  assert.equal(first, renderReport(summary));
  assert.equal(first, renderReport(JSON.parse(JSON.stringify(summary))));
  assert.match(first, /T4 — Codex Mid-Turn Delivery Spike/);
  assert.match(first, /nativeSteeringAdvertised|Native steering advertised/);
  assert.doesNotMatch(first, /gpt-|sessionId|hostname/i);
});

test("rejects public T4 artifact destinations before filesystem mutation", async () => {
  const root = await mkdtemp(join(tmpdir(), "weave-t4-artifacts-test-"));
  try {
    const evidenceRoot = join(root, "evidence");
    const defaultTarget = resolveArtifactsDir(undefined, { root });
    assert.ok(defaultTarget.startsWith(join(root, ".scratch", "t4-codex") + "/"));
    assert.equal(await pathExists(defaultTarget), false);

    const forbidden = [
      evidenceRoot,
      join(evidenceRoot, "t4-codex"),
      join(evidenceRoot, "t4-codex", "accepted-local-record"),
      join(evidenceRoot, "t4-codex", "..", "t4-codex"),
    ];
    for (const target of forbidden) {
      assert.throws(() => resolveArtifactsDir(target, { root }), /public evidence tree/);
      assert.equal(await pathExists(target), false);
      assert.equal(await pathExists(join(root, ".scratch")), false);
    }

    const sibling = join(root, "evidence-backup", "raw");
    assert.equal(resolveArtifactsDir(sibling, { root }), sibling);
    assert.equal(await pathExists(sibling), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a symlink that redirects raw captures into evidence without creating a target", async () => {
  const root = await mkdtemp(join(tmpdir(), "weave-t4-symlink-test-"));
  try {
    const scratch = join(root, ".scratch");
    const evidence = join(root, "evidence");
    await mkdir(scratch);
    await mkdir(evidence);
    await symlink("../evidence", join(scratch, "link"));

    assert.throws(
      () => resolveArtifactsDir(join(".scratch", "link", "t4"), { root }),
      /public evidence tree/,
    );
    assert.equal(await pathExists(join(evidence, "t4")), false);
    assert.equal(await pathExists(join(scratch, "link", "t4")), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("refuses a DANGLING symlink (intermediate component) into evidence before any mkdir", async () => {
  const root = await mkdtemp(join(tmpdir(), "weave-t4-dangling-intermediate-"));
  try {
    const scratch = join(root, ".scratch");
    await mkdir(scratch);
    // Target `evidence/newdir` does not yet exist: the link is dangling.
    await symlink("../evidence/newdir", join(scratch, "link"));

    assert.throws(
      () => resolveArtifactsDir(join(".scratch", "link", "t4"), { root }),
      /public evidence tree/,
      "dangling intermediate-component link must be refused by the guard itself",
    );
    let linkStat = null;
    try {
      linkStat = await lstat(join(scratch, "link"));
    } catch {
      // link fixture absent
    }
    assert.ok(linkStat, "the link fixture itself may exist");
    assert.equal(await pathExists(join(root, "evidence")), false, "no evidence tree may be created");
    assert.equal(await pathExists(join(scratch, "link", "t4")), false, "no artifact may be created");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("refuses a DANGLING symlink (final component) into evidence before any mkdir", async () => {
  const root = await mkdtemp(join(tmpdir(), "weave-t4-dangling-final-"));
  try {
    const scratch = join(root, ".scratch");
    await mkdir(scratch);
    await symlink("../evidence/newdir", join(scratch, "link"));

    assert.throws(
      () => resolveArtifactsDir(join(".scratch", "link"), { root }),
      /public evidence tree/,
      "dangling final-component link must be refused by the guard itself",
    );
    assert.equal(await pathExists(join(root, "evidence")), false, "no evidence tree may be created");
    assert.equal(await pathExists(join(scratch, "link", "newdir")), false, "no link target may be created");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("resolves ACP through a portable command unless explicitly configured", () => {
  assert.deepEqual(adapterInvocation(undefined), {
    command: "codex-acp",
    args: [],
    executable: "codex-acp",
  });
  const configured = join(tmpdir(), "synthetic-codex-acp.mjs");
  assert.deepEqual(adapterInvocation(configured), {
    command: process.execPath,
    args: [configured],
    executable: configured,
  });
});

test("accepts the reviewed Codex and ACP compatibility range", () => {
  assert.deepEqual(assertSupportedHarnessVersions({ codexCli: "0.145.0", acpAdapter: "1.1.7", ranges }), {
    codexCli: "0.145.0",
    acpAdapter: "1.1.7",
  });
});

test("refuses an out-of-range harness without fallback", () => {
  assert.throws(
    () => assertSupportedHarnessVersions({ codexCli: "0.146.0", acpAdapter: "1.1.7", ranges }),
    /UNSUPPORTED_HARNESS_VERSION: codex-cli@0\.146\.0; no fallback/,
  );
});

const allowlist = {
  configRoots: { codexHome: { allowedPrefixes: ["sessions/", "models_cache.json", "state_*.sqlite"] } },
};

test("types every changed config path and rejects an unallowlisted path", () => {
  assert.deepEqual(
    typedConfigTreeDiff(
      {
        "<CODEX_HOME>/sessions/old.jsonl": { type: "file", size: 1, sha256: "old" },
        "<CODEX_HOME>/config.toml": { type: "file", size: 1, sha256: "old" },
      },
      {
        "<CODEX_HOME>/sessions/old.jsonl": { type: "file", size: 1, sha256: "new" },
        "<CODEX_HOME>/state_1.sqlite": { type: "file", size: 2, sha256: "new" },
        "<CODEX_HOME>/config.toml": { type: "file", size: 1, sha256: "new" },
      },
      allowlist,
    ),
    {
      entries: [
        {
          path: "<CODEX_HOME>/config.toml",
          change: "content-changed",
          before: { type: "file", size: 1, sha256: "old" },
          after: { type: "file", size: 1, sha256: "new" },
          allowlistMatch: null,
        },
        {
          path: "<CODEX_HOME>/sessions/old.jsonl",
          change: "content-changed",
          before: { type: "file", size: 1, sha256: "old" },
          after: { type: "file", size: 1, sha256: "new" },
          allowlistMatch: "sessions/",
        },
        {
          path: "<CODEX_HOME>/state_1.sqlite",
          change: "added",
          before: null,
          after: { type: "file", size: 2, sha256: "new" },
          allowlistMatch: "state_*.sqlite",
        },
      ],
      checks: {
        changedPathsInsideJournalAllowlist: false,
        changedPathsOutsideJournalAllowlist: [{ path: "<CODEX_HOME>/config.toml", change: "content-changed" }],
      },
    },
  );
});

test("reads native steering only from initialize-level metadata", () => {
  assert.equal(nativeSteerAdvertised({ agentCapabilities: { _meta: { steering: { supported: true } } } }), false);
  assert.equal(nativeSteerAdvertised({ _meta: { steering: { supported: true } } }), true);
});

test("falls back when native steering is absent, failed, or unknown", () => {
  assert.equal(selectDeliveryPath({ nativeAdvertised: false, outcome: undefined }), "fallback-cancel-merged-reprompt");
  assert.equal(selectDeliveryPath({ nativeAdvertised: true, outcome: "failed" }), "fallback-cancel-merged-reprompt");
  assert.equal(selectDeliveryPath({ nativeAdvertised: true, outcome: "unknown" }), "fallback-cancel-merged-reprompt");
  assert.equal(selectDeliveryPath({ nativeAdvertised: true, outcome: "injected" }), "native");
});

test("merged fallback preserves the complete original and event", () => {
  const original = "ORIGINAL TASK\nwith multiple lines";
  const event = "EVENT-STEER-1: include this marker";
  const prompt = mergedPrompt(original, event);
  assert.ok(prompt.includes(original));
  assert.ok(prompt.includes(event));
});

test("rejects a non-pinned runtime or forbidden override", () => {
  assert.throws(
    () => assertRunnerEnvironment({
      node: "v24.18.0",
      environment: {
        homeInherited: true,
        homeOverrideRequested: false,
        forbiddenOverridePresent: { CODEX_HOME: false, CLAUDE_CONFIG_DIR: false },
      },
    }),
    /PINNED_NODE_REQUIRED/,
  );
  assert.throws(
    () => assertRunnerEnvironment({
      node: "v24.12.0",
      environment: {
        homeInherited: true,
        homeOverrideRequested: false,
        forbiddenOverridePresent: { CODEX_HOME: true, CLAUDE_CONFIG_DIR: false },
      },
    }),
    /CODEX_HOME override is forbidden/,
  );
});

test("rejects absolute executable paths from privacy-safe evidence", () => {
  const syntheticExecutable = join(tmpdir(), "codex");
  assert.throws(
    () => assertPrivacySafeEvidence({ codexExecutable: syntheticExecutable }),
    /PRIVACY_PATH_LEAK/,
  );
  assert.throws(
    () => environmentEvidence({
      node: "v24.12.0",
      codexCli: syntheticExecutable,
      acpAdapter: "1.1.7",
      host: {},
      homeInherited: true,
      homeOverrideRequested: false,
      forbiddenOverridePresent: {},
    }),
    /PRIVACY_PATH_LEAK/,
  );
});

test("returns privacy-safe environment provenance after validation", () => {
  const host = {
    platform: "darwin",
    release: "25.5.0",
    version: "Darwin Kernel Version 25.5.0",
    arch: "arm64",
    uname: "Darwin FixtureHost arm64",
    hostname: "FixtureHost",
    extra: "must not be emitted",
  };
  const evidence = environmentEvidence({
    node: "v24.12.0",
    codexCli: "0.145.0",
    acpAdapter: "1.1.7",
    host,
    homeInherited: true,
    homeOverrideRequested: false,
    forbiddenOverridePresent: { CODEX_HOME: false, CLAUDE_CONFIG_DIR: false },
  });
  assert.deepEqual(evidence, {
    node: "v24.12.0",
    nodeRequired: "v24.12.0",
    codexCli: "0.145.0",
    acpAdapter: "1.1.7",
    toolIdentity: {
      codexCli: "codex-cli",
      acpAdapter: "@agentclientprotocol/codex-acp",
    },
    home: "<HOME>",
    homeInherited: true,
    homeOverrideRequested: false,
    forbiddenOverridePresent: { CODEX_HOME: false, CLAUDE_CONFIG_DIR: false },
    host: {
      platform: "darwin",
      release: "25.5.0",
      version: "Darwin Kernel Version 25.5.0",
      arch: "arm64",
    },
  });
  assert.equal("uname" in evidence.host, false);
  assert.equal("hostname" in evidence.host, false);
  assert.equal(JSON.stringify(evidence).includes("FixtureHost"), false);
});

test("binds the deterministic artifact aggregate and rejects absent or mismatched values", () => {
  const entries = [
    { name: "b.txt", bytes: Buffer.from("B") },
    { name: "assertions.json", bytes: Buffer.from("excluded") },
    { name: "a.txt", bytes: Buffer.from("A") },
  ];
  const digest = computeArtifactsSha256(entries);
  assert.equal(assertArtifactAggregateBinding({ entries, expected: digest }), digest);
  assert.throws(
    () => assertArtifactAggregateBinding({ entries, expected: undefined }),
    /ARTIFACT_AGGREGATE_MISSING/,
  );
  assert.throws(
    () => assertArtifactAggregateBinding({ entries, expected: "0".repeat(64) }),
    /ARTIFACT_AGGREGATE_MISMATCH/,
  );
});
