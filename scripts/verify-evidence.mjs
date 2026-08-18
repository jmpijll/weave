#!/usr/bin/env node
/**
 * Verifies the public `evidence/` tree against the M0 Option A retention policy:
 *
 * - Under each `evidence/<spike>/` directory exactly `summary.json` and its
 *   generated `REPORT.md` (regular files) are permitted; no other files, no
 *   nested directories, no symbolic links, and no non-regular entries.
 * - The top level `evidence/` contains only regular directories; symbolic
 *   links, files and non-regular entries are rejected.
 * - Every `summary.json` passes the strict schema (no unknown keys, no omitted
 *   required keys, no free-form host/path/environment values, anchored versions).
 * - Each evidence directory name is bound to the validated `summary.spike`, and
 *   that spike must be a registered spike.
 * - Every `REPORT.md` is regenerated from its `summary.json` and byte-identical
 *   (prose cannot drift from data).
 * - Every `publicProvenance.integrationCommit` resolves to an ancestor of the
 *   repository HEAD (verified with git history, not just SHA shape).
 *
 * Any violation fails with a non-zero exit code. Raw host-specific captures
 * are expected to be absent.
 */
import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { isRegisteredSpike, renderReport, validateSummary } from "./evidence-contract.mjs";

const execFileAsync = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function readdirSafe(dir) {
  try {
    return await readdir(dir, { withFileTypes: true });
  } catch {
    return null;
  }
}

function describeEntry(entry) {
  if (entry.isSymbolicLink()) return "symbolic link";
  if (entry.isDirectory()) return "directory";
  if (entry.isFile()) return "file";
  return "non-regular entry";
}

/**
 * Verify an evidence tree rooted at `evidenceRoot`, returning
 * `{ conformat, violations }`. Raises neither errors (beyond I/O) nor process
 * exit; callers decide how to fail.
 */
export async function verifyTree(evidenceRoot) {
  const violations = [];
  const rootEntries = await readdirSafe(evidenceRoot);
  if (rootEntries === null) {
    return { conformat: true, violations, absent: true };
  }

  for (const entry of rootEntries) {
    if (entry.isSymbolicLink()) {
      violations.push(`evidence/: unexpected symbolic link "${entry.name}" (only spike directories allowed)`);
      continue;
    }
    if (!entry.isDirectory()) {
      violations.push(`evidence/: unexpected ${describeEntry(entry)} "${entry.name}" (only spike directories allowed)`);
      continue;
    }
    const spikeDir = join(evidenceRoot, entry.name);
    const spikeFiles = await readdirSafe(spikeDir);
    if (spikeFiles === null) {
      violations.push(`evidence/${entry.name}: unreadable directory`);
      continue;
    }
    for (const file of spikeFiles) {
      if (file.isSymbolicLink()) {
        violations.push(`evidence/${entry.name}/: unexpected symbolic link "${file.name}" (regular files only)`);
        continue;
      }
      if (file.isDirectory()) {
        violations.push(`evidence/${entry.name}/: unexpected nested ${describeEntry(file)} "${file.name}"`);
        continue;
      }
      if (!file.isFile()) {
        violations.push(`evidence/${entry.name}/: unexpected ${describeEntry(file)} "${file.name}"`);
        continue;
      }
      if (file.name !== "summary.json" && file.name !== "REPORT.md") {
        violations.push(`evidence/${entry.name}/: unexpected file "${file.name}" (only summary.json and REPORT.md allowed)`);
      }
    }
    for (const required of ["summary.json", "REPORT.md"]) {
      if (!spikeFiles.some((entry2) => entry2.isFile() && entry2.name === required)) {
        violations.push(`evidence/${entry.name}/: missing required file "${required}"`);
      }
    }
    if (spikeFiles.some((file) => file.isFile() && file.name === "summary.json")) {
      const summaryPath = join(spikeDir, "summary.json");
      let raw;
      try {
        raw = await readFile(summaryPath, "utf8");
      } catch (error) {
        violations.push(`evidence/${entry.name}/summary.json: unreadable (${error?.message ?? error})`);
        continue;
      }
      let summary;
      try {
        summary = JSON.parse(raw);
      } catch (error) {
        violations.push(`evidence/${entry.name}/summary.json: invalid JSON (${error?.message ?? error})`);
        continue;
      }
      const schemaErrors = validateSummary(summary);
      for (const schemaError of schemaErrors) {
        violations.push(`evidence/${entry.name}/summary.json: ${schemaError}`);
      }
      if (typeof summary.spike !== "string" || summary.spike !== entry.name) {
        violations.push(
          `evidence/${entry.name}/summary.json: spike "${entry.name}" does not match validated summary.spike "${summary.spike}"`,
        );
      }
      if (typeof summary.spike !== "string" || !isRegisteredSpike(summary.spike)) {
        violations.push(
          `evidence/${entry.name}/summary.json: spike "${summary.spike}" is not a registered spike (fails closed)`,
        );
      }
      if (spikeFiles.some((file) => file.isFile() && file.name === "REPORT.md")) {
        let current;
        try {
          current = await readFile(join(spikeDir, "REPORT.md"), "utf8");
        } catch (error) {
          violations.push(`evidence/${entry.name}/REPORT.md: unreadable (${error?.message ?? error})`);
          current = null;
        }
        if (current !== null) {
          let rendered;
          try {
            rendered = renderReport(summary);
          } catch (error) {
            violations.push(`evidence/${entry.name}/REPORT.md: generation failed (${error?.message ?? error})`);
            rendered = null;
          }
          if (rendered !== null && rendered !== current) {
            violations.push(
              `evidence/${entry.name}/REPORT.md: drift — does not match byte-for-byte regeneration from summary.json; run ` +
                `node scripts/evidence-report.mjs --spike ${entry.name} --write`,
            );
          }
        }
      }
    }
  }

  const result = { conformat: violations.length === 0, violations };
  return result;
}

/**
 * Check that every evidence summary's `publicProvenance.integrationCommit`
 * is an ancestor of the current HEAD in the git repository at `repoRoot`.
 * Returns `{ conformat, violations }`. Uses git history, so it resolves rather
 * than validating only the SHA shape.
 */
export async function verifyIntegrationCommitAncestors(evidenceRoot, repoRoot) {
  const violations = [];
  const rootEntries = await readdirSafe(evidenceRoot);
  if (rootEntries === null) return { conformat: true, violations };

  for (const entry of rootEntries) {
    if (entry.isSymbolicLink() || !entry.isDirectory()) continue;
    const summaryPath = join(evidenceRoot, entry.name, "summary.json");
    let raw;
    try {
      raw = await readFile(summaryPath, "utf8");
    } catch {
      continue;
    }
    let summary;
    try {
      summary = JSON.parse(raw);
    } catch {
      continue;
    }
    const integrationCommit = summary?.publicProvenance?.integrationCommit;
    if (typeof integrationCommit !== "string" || !/^[0-9a-f]{40}$/i.test(integrationCommit)) {
      continue; // schema validation reports malformed SHAs
    }
    let code = 1;
    let stderr = "";
    try {
      const result = await execFileAsync(
        "git",
        ["merge-base", "--is-ancestor", integrationCommit, "HEAD"],
        { cwd: repoRoot },
      );
      code = 0;
      stderr = result.stderr?.trim?.() ?? "";
    } catch (error) {
      code = error?.code ?? 1;
      stderr = (error?.stderr ?? error?.message ?? "").trim();
    }
    if (code !== 0) {
      violations.push(
        `evidence/${entry.name}/summary.json: publicProvenance.integrationCommit ${integrationCommit} does not resolve to an ancestor of HEAD (${stderr || "not an ancestor"})`,
      );
    }
  }

  return { conformat: violations.length === 0, violations };
}

const EVIDENCE = join(ROOT, "evidence");

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const tree = await verifyTree(EVIDENCE);
  const ancestors = await verifyIntegrationCommitAncestors(EVIDENCE, ROOT);
  const violations = [...tree.violations, ...ancestors.violations];
  if (violations.length === 0) {
    console.log("evidence policy: conformant");
    console.log("evidence policy: integrationCommits resolve to ancestors of HEAD");
  } else {
    for (const violation of violations) {
      console.error(`evidence policy violation: ${violation}`);
    }
    console.error(`evidence policy: ${violations.length} violation(s)`);
    process.exitCode = 1;
  }
}
