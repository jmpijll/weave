#!/usr/bin/env node
/**
 * Regression tests for the M0 Option A evidence retention contract.
 *
 * Covered failure shapes:
 *   1. An unexpected file inside a spike evidence directory.
 *   2. An unexpected nested directory / symbolic link / non-regular entry.
 *   3. An unknown key inside a validated summary.
 *   4. An omitted required result key from the fixed reviewed set.
 *   5. An anchored-version bypass (arbitrary unsafe trailing payload).
 *   6. An unsafe free-form value shape (host path / hostname / username /
 *      temp identifier / raw environment content) in a summary field.
 *   7. A spike directory not bound to its registered summary.spike.
 *   8. A publicProvenance.integrationCommit that is not an ancestor of HEAD.
 *
 * All invalid fixtures are invented and non-identifying: they never mirror
 * real host, path, temp, username or environment bytes from the raw captures.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { resolveArtifactsDir } from "./t3-codex-materializer.mjs";
import { validateSummary, RESULT_KEYS, T9_RESULT_KEYS } from "./evidence-contract.mjs";
import { verifyTree, verifyIntegrationCommitAncestors } from "./verify-evidence.mjs";

const execFileAsync = promisify(execFile);

async function pathExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function validSummary(overrides = {}) {
  const results = {};
  for (const key of RESULT_KEYS) results[key] = "PASS";
  results.globalCollisionFixture = "NEGATIVE";
  results.projectSkillBeatsGlobal = "NEGATIVE";
  return {
    schemaVersion: "1.0.0",
    spike: "t3-codex",
    capturedAt: "2026-08-16T20:40:00Z",
    publicProvenance: { integrationCommit: "0".repeat(40) },
    localProvenance: {
      visibility: "not-published",
      runnerSha: "1".repeat(40),
      captureSha256: "2".repeat(64),
      recordId: "weave-t3-codex-senior-review-2026-08-16",
    },
    environment: {
      os: "macos",
      osVersion: "26.5.2",
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

async function withSpikeTree(directory, setup) {
  const spikeDir = join(directory, "evidence", "t3-codex");
  await mkdir(spikeDir, { recursive: true });
  await setup(spikeDir, directory);
}

async function testUnexpectedFile() {
  const dir = await mkdtemp(join(tmpdir(), "weave-evidence-test-"));
  try {
    await withSpikeTree(dir, async (spikeDir) => {
      await writeFile(join(spikeDir, "summary.json"), JSON.stringify(validSummary()), "utf8");
      await writeFile(join(spikeDir, "report.md"), "# stray\n", "utf8");
    });
    const result = await verifyTree(join(dir, "evidence"));
    assert.equal(result.conformat, false, "unexpected lowercase report file must fail");
    assert.ok(
      result.violations.some((v) => v.includes('unexpected file "report.md"')),
      `expected unexpected-file violation, got: ${result.violations.join(" | ")}`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function testUnexpectedDirectory() {
  const dir = await mkdtemp(join(tmpdir(), "weave-evidence-test-"));
  try {
    await withSpikeTree(dir, async (spikeDir) => {
      await mkdir(join(spikeDir, "run-0001"), { recursive: true });
      await writeFile(join(spikeDir, "summary.json"), JSON.stringify(validSummary()), "utf8");
    });
    const result = await verifyTree(join(dir, "evidence"));
    assert.equal(result.conformat, false, "nested raw-capture directory must fail closed");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function testSymbolicLinkRejected() {
  const dir = await mkdtemp(join(tmpdir(), "weave-evidence-test-"));
  try {
    await withSpikeTree(dir, async (spikeDir) => {
      await writeFile(join(spikeDir, "summary.json"), JSON.stringify(validSummary()), "utf8");
      await symlink(join(spikeDir, "summary.json"), join(spikeDir, "alias.json"));
    });
    const result = await verifyTree(join(dir, "evidence"));
    assert.equal(result.conformat, false, "symbolic link inside spike directory must fail closed");
    assert.ok(
      result.violations.some((v) => v.includes("symbolic link")),
      `expected symbolic-link violation, got: ${result.violations.join(" | ")}`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function testSpikeDirectoryBoundToSummary() {
  const dir = await mkdtemp(join(tmpdir(), "weave-evidence-test-"));
  try {
    // Directory name does not match the registered summary.spike.
    const mismatchedDir = join(dir, "evidence", "mismatched-spike");
    await mkdir(mismatchedDir, { recursive: true });
    await writeFile(join(mismatchedDir, "summary.json"), JSON.stringify(validSummary()), "utf8");
    const mismatched = await verifyTree(join(dir, "evidence"));
    assert.equal(mismatched.conformat, false, "spike directory name must match summary.spike");
    assert.ok(
      mismatched.violations.some((v) => v.includes("does not match validated summary.spike")),
      `expected spike-binding violation, got: ${mismatched.violations.join(" | ")}`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function testUnregisteredSpikeRejected() {
  const dir = await mkdtemp(join(tmpdir(), "weave-evidence-test-"));
  try {
    const unknownDir = join(dir, "evidence", "t3-codex");
    await mkdir(unknownDir, { recursive: true });
    const summary = validSummary({ spike: "t9-realhost" });
    await writeFile(join(unknownDir, "summary.json"), JSON.stringify(summary), "utf8");
    const result = await verifyTree(join(dir, "evidence"));
    assert.equal(result.conformat, false, "unregistered spike must fail closed");
    assert.ok(
      result.violations.some((v) => v.includes("not a registered spike")),
      `expected unregistered-spike violation, got: ${result.violations.join(" | ")}`,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function testUnknownKey() {
  const summary = validSummary({ unexpectedField: "surprise" });
  const errors = validateSummary(summary);
  assert.ok(errors.length > 0, "unknown top-level key must be rejected");
  assert.ok(errors.some((e) => e.includes("unexpectedField")), errors.join(" | "));
}

async function testUnknownResultKey() {
  const summary = validSummary();
  summary.results.madeUpCriterion = "PASS";
  const errors = validateSummary(summary);
  assert.ok(errors.some((e) => e.includes("madeUpCriterion")), errors.join(" | "));
}

async function testMissingResultKey() {
  const summary = validSummary();
  delete summary.results.globalCollisionFixture;
  const errors = validateSummary(summary);
  assert.ok(errors.length > 0, "omitting a fixed required result key must be rejected");
  assert.ok(
    errors.some((e) => e.includes("globalCollisionFixture") && e.includes("missing")),
    `expected missing-result-key violation, got: ${errors.join(" | ")}`,
  );
}

async function testVersionBypassRejected() {
  // Anchored version grammar: any trailing payload after patch must be a valid
  // semver pre-release/build. Invented, unsafe trailing payloads must fail.
  const bypasses = [
    "24.12.0-custom /opt/example/sandbox",
    "24.12.0-injected/../../etc/passwd",
    "1.0.0..;echo injected",
    "1.0.0@build 3",
  ];
  for (const payload of bypasses) {
    const bad = validSummary();
    bad.environment.nodePinned = payload;
    const errors = validateSummary(bad);
    assert.ok(
      errors.length > 0,
      `anchored version must reject trailing payload: ${JSON.stringify(payload)}`,
    );
    assert.ok(errors.some((e) => e.includes("nodePinned")), errors.join(" | "));

    const badVersion = validSummary();
    badVersion.schemaVersion = payload;
    const versionErrors = validateSummary(badVersion);
    assert.ok(
      versionErrors.length > 0,
      `anchored version must reject trailing payload in schemaVersion: ${JSON.stringify(payload)}`,
    );
  }
}

async function testUnsafeFreeFormValue() {
  // Invented, non-identifying free-form shapes. They prove rejection of host
  // path / hostname / username / temp identifier / raw environment content
  // without mirroring any real host bytes.
  const unsafeValues = [
    { path: "/opt/example-org/sandbox/work", label: "absolute sandbox path" },
    { path: "/var/tmp/instance-1eaf3c", label: "per-instance temp id" },
    { path: "SI_ROOT=/opt/example-org/sandbox", label: "raw environment assignment" },
  ];
  for (const { path, label } of unsafeValues) {
    // recordId must reject any value that is not a single opaque token (paths,
    // env assignments, and anything else with separators are unsafe).
    const bad = validSummary();
    bad.localProvenance.recordId = path;
    const withPath = validateSummary(bad);
    assert.ok(withPath.length > 0, `recordId must reject free-form value for: ${label}`);
    assert.ok(withPath.some((e) => e.includes("recordId")), withPath.join(" | "));

    // Enum-constrained fields must reject any free-form value, including a
    // bare hostname which is not an allowed enum member.
    const badEnv = validSummary();
    badEnv.environment.os = path;
    badEnv.environment.platform = "demo-runner-host";
    const withEnv = validateSummary(badEnv);
    assert.ok(withEnv.length > 0, `environment must reject free-form value for: ${label}`);
    assert.ok(withEnv.some((e) => e.includes("environment.os") || e.includes("environment.platform")), withEnv.join(" | "));

    const badResult = validSummary();
    badResult.results.projectInstructionsLoad = path;
    const withResult = validateSummary(badResult);
    assert.ok(withResult.length > 0, `result status must reject free-form value for: ${label}`);
  }
}

async function testConformantSummaryAccepted() {
  const summary = validSummary();
  const errors = validateSummary(summary);
  assert.deepEqual(errors, [], "conformant summary must validate clean");
}

async function testReportRoundTripStable() {
  const { renderReport } = await import("./evidence-contract.mjs");
  const summary = validSummary();
  const first = renderReport(summary);
  const second = renderReport(summary);
  assert.equal(first, second, "report rendering must be deterministic");
  assert.ok(first.includes("publicProvenance.integrationCommit"), "report must label public provenance");
  assert.ok(first.includes("not-published"), "report must label local provenance visibility");
}

async function makeGitRepo() {
  const dir = await mkdtemp(join(tmpdir(), "weave-git-test-"));
  await execFileAsync("git", ["init", "-q"], { cwd: dir });
  await execFileAsync("git", ["config", "user.name", "Test Operator"], { cwd: dir });
  await execFileAsync("git", ["config", "user.email", "test@example.invalid"], { cwd: dir });
  return dir;
}

async function gitCommit(repoDir, message) {
  await execFileAsync("git", ["add", "-A"], { cwd: repoDir });
  const { stdout } = await execFileAsync("git", ["commit", "-q", "-m", message], { cwd: repoDir });
  const { stdout: sha } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: repoDir });
  return sha.trim();
}

async function testIntegrationCommitAncestor() {
  const repoDir = await makeGitRepo();
  try {
    await writeFile(join(repoDir, "a.txt"), "one\n", "utf8");
    await execFileAsync("git", ["add", "-A"], { cwd: repoDir });
    const firstSha = await gitCommit(repoDir, "contract base");

    // Ancestor case: summary references the first commit, which is an ancestor of HEAD.
    const evidenceDir = join(repoDir, "evidence", "t3-codex");
    await mkdir(evidenceDir, { recursive: true });
    const summary = validSummary();
    summary.publicProvenance.integrationCommit = firstSha;
    await writeFile(join(evidenceDir, "summary.json"), JSON.stringify(summary), "utf8");
    const headSha = await gitCommit(repoDir, "summary commit");
    assert.notEqual(headSha, firstSha, "setup must have HEAD as a descendant of the first commit");

    const ok = await verifyIntegrationCommitAncestors(join(repoDir, "evidence"), repoDir);
    assert.equal(ok.conformat, true, `ancestor integrationCommit must resolve; got ${ok.violations.join(" | ")}`);

    // Non-ancestor case: an invented/unreachable SHA must fail.
    const summaryBad = validSummary();
    summaryBad.publicProvenance.integrationCommit = "0".repeat(40);
    await writeFile(join(evidenceDir, "summary.json"), JSON.stringify(summaryBad), "utf8");
    await gitCommit(repoDir, "bad summary commit");
    const bad = await verifyIntegrationCommitAncestors(join(repoDir, "evidence"), repoDir);
    assert.equal(bad.conformat, false, "non-ancestor integrationCommit must fail");
    assert.ok(
      bad.violations.some((v) => v.includes("does not resolve to an ancestor of HEAD")),
      `expected ancestor violation, got: ${bad.violations.join(" | ")}`,
    );
  } finally {
    await rm(repoDir, { recursive: true, force: true });
  }
}

async function testSemverPrereleaseLeadingZeroRejected() {
  // SemVer 2.0.0 forbids numeric pre-release identifiers with leading zeroes.
  const invalid = ["1.2.3-01", "1.2.3-00", "1.2.3-000.1", "1.2.3-alpha.01"];
  for (const value of invalid) {
    const summary = validSummary();
    summary.environment.nodePinned = value;
    const errors = validateSummary(summary);
    assert.ok(
      errors.some((e) => e.includes("nodePinned")),
      `SemVer pre-release must reject leading-zero numeric identifier: ${JSON.stringify(value)}; got ${errors.join(" | ")}`,
    );
  }
  // Correct SemVer 2.0.0 forms (including numeric "0", hybrid and alphanumeric
  // identifiers) must still validate; the leading-zero rule applies only to
  // purely numeric identifiers.
  const valid = [
    "24.12.0",
    "1.2.3-0",
    "1.2.3-0.1.2",
    "1.2.3-alpha",
    "1.2.3-alpha.1",
    "1.2.3-alpha.beta.2",
    "1.0.0-rc.1+build.5",
    "1.0.0+build.5",
    "1.2.3-01b",
  ];
  for (const value of valid) {
    const summary = validSummary();
    summary.environment.nodePinned = value;
    assert.deepEqual(validateSummary(summary), [], `must accept valid SemVer: ${JSON.stringify(value)}`);
  }
}

async function testArtifactsDirRejectsPublicEvidence() {
  // Guard: the raw-capture runner must refuse to target the public evidence tree.
  // Rejection is a pure, synchronous fail-closed check: it must fire before any
  // directory is created, must not invoke Codex, and must not mutate host state.
  const dir = await mkdtemp(join(tmpdir(), "weave-artifacts-test-"));
  try {
    const evidenceRoot = join(dir, "evidence");
    const opts = { root: dir };

    // Default (no --artifacts) resolves to a Git-ignored local-only .scratch path.
    const def = resolveArtifactsDir(undefined, opts);
    assert.ok(
      def.startsWith(join(dir, ".scratch", "t3-codex") + "/"),
      `default must be under .scratch/t3-codex, got ${def}`,
    );
    assert.equal(await pathExists(def), false, "default target must not be created eagerly");

    // Any explicit --artifacts resolving to the evidence root or a descendant is
    // rejected, including boundary-normalised ("..") forms.
    const forbidden = [
      evidenceRoot,
      join(evidenceRoot, "t3-codex"),
      join(evidenceRoot, "t3-codex", "20260816T0000Z"),
      join(evidenceRoot, "t3-codex", "..", "t3-codex"),
    ];
    for (const target of forbidden) {
      assert.throws(
        () => resolveArtifactsDir(target, opts),
        /public evidence tree/,
        `--artifacts must reject an evidence-resident path: ${target}`,
      );
      // Nothing is created on rejection and no host bytes are mutated.
      assert.equal(await pathExists(target), false, `must not create ${target} on rejection`);
      assert.equal(await pathExists(join(dir, ".scratch")), false, "no .scratch tree may be created on rejection");
    }

    // A local-only target outside the evidence tree is accepted unchanged.
    const ok = join(dir, ".scratch", "t3-codex", "run-0001");
    assert.equal(resolveArtifactsDir(ok, opts), ok);
    assert.equal(await pathExists(ok), false, "accepted target is not created eagerly");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function validT9Summary(overrides = {}) {
  const results = {};
  for (const key of T9_RESULT_KEYS) results[key] = "PASS";
  return {
    schemaVersion: "1.0.0",
    spike: "t9-installer",
    capturedAt: "2026-08-17T20:40:00Z",
    publicProvenance: { integrationCommit: "0".repeat(40) },
    localProvenance: {
      visibility: "not-published",
      runnerSha: "1".repeat(40),
      captureSha256: "2".repeat(64),
      recordId: "weave-t9-installer-docker-desktop-2026-08-17",
    },
    environment: {
      os: "macos",
      osVersion: "26.5.2",
      arch: "arm64",
      containerRuntime: "docker-desktop",
      dockerVersion: "29.6.2",
      dockerDaemonVersion: "29.6.2",
      composeVersion: "5.3.1",
      nodePinned: "24.12.0",
      platform: "darwin-arm64",
      nodePinnedMatched: true,
    },
    results,
    ...overrides,
  };
}

async function testT9ConformantSummaryAccepted() {
  const errors = validateSummary(validT9Summary());
  assert.deepEqual(errors, [], "conformant t9-installer summary must validate clean");
}

async function testT9EnvironmentEnumerated() {
  // t9-installer environment is fixed and enumerated: a foreign host path,
  // context name, or free-form value must fail closed in any field.
  const badContext = validT9Summary();
  badContext.environment.containerRuntime = "my-custom-host";
  assert.ok(
    validateSummary(badContext).some((e) => e.includes("containerRuntime")),
    "t9-installer containerRuntime must reject free-form value",
  );

  const badArch = validT9Summary();
  badArch.environment.arch = "custom-arch";
  assert.ok(
    validateSummary(badArch).some((e) => e.includes("environment.arch")),
    "t9-installer arch must reject unenumerated value",
  );

  const badNode = validT9Summary();
  badNode.environment.nodePinned = "24.12.0-injected/../../etc/passwd";
  assert.ok(
    validateSummary(badNode).some((e) => e.includes("nodePinned")),
    "t9-installer nodePinned must reject anchored-version bypass",
  );

  const badOs = validT9Summary();
  badOs.environment.os = "/opt/weave/sandbox";
  assert.ok(
    validateSummary(badOs).some((e) => e.includes("environment.os")),
    "t9-installer os must reject free-form value",
  );
}

async function testT9ResultKeysFixed() {
  // The exact reviewed result-key set is required; unknown or missing keys fail.
  const unknown = validT9Summary();
  unknown.results.madeUpInstallerResult = "PASS";
  assert.ok(
    validateSummary(unknown).some((e) => e.includes("madeUpInstallerResult")),
    "t9-installer must reject an unknown result key",
  );

  const missing = validT9Summary();
  delete missing.results.dbServerHealth;
  assert.ok(
    validateSummary(missing).some((e) => e.includes("dbServerHealth") && e.includes("missing")),
    "t9-installer must reject a missing reviewed result key",
  );

  // A t3 result key must not be accepted inside a t9 summary and vice-versa.
  const crossT3 = validT9Summary();
  crossT3.results.nodePinExact = "PASS";
  assert.ok(
    validateSummary(crossT3).some((e) => e.includes("nodePinExact")),
    "t9-installer must not accept t3-only result keys",
  );
}

const tests = [
  testConformantSummaryAccepted,
  testUnexpectedDirectory,
  testSymbolicLinkRejected,
  testSpikeDirectoryBoundToSummary,
  testUnregisteredSpikeRejected,
  testUnknownKey,
  testUnknownResultKey,
  testMissingResultKey,
  testVersionBypassRejected,
  testSemverPrereleaseLeadingZeroRejected,
  testArtifactsDirRejectsPublicEvidence,
  testUnsafeFreeFormValue,
  testReportRoundTripStable,
  testIntegrationCommitAncestor,
  testT9ConformantSummaryAccepted,
  testT9EnvironmentEnumerated,
  testT9ResultKeysFixed,
];

for (const test of tests) {
  await test();
  console.log(`ok - ${test.name}`);
}
console.log(`evidence contract tests passed (${tests.length})`);
