#!/usr/bin/env node
/**
 * Regenerates `evidence/<spike>/REPORT.md` from the validated `summary.json`.
 *
 * Usage:
 *   node scripts/evidence-report.mjs --spike t3-codex            # print to stdout
 *   node scripts/evidence-report.mjs --spike t3-codex --write    # rewrite REPORT.md
 *
 * `verify-evidence.mjs` uses the same renderer to byte-compare, so a regenerated
 * report is guaranteed identical to what CI accepts.
 */
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { renderReport, validateSummary } from "./evidence-contract.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      throw new Error(`Unexpected argument: ${token}`);
    }
    const key = token.slice(2);
    if (key === "help" || key === "write") {
      args[key] = true;
      continue;
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for --${key}`);
    }
    args[key] = value;
    index += 1;
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
const spike = args.spike;
assert.ok(spike, "--spike <name> is required");
assert.match(spike, /^[a-z0-9][a-z0-9-]{0,63}$/, "--spike must be a slug");

const spikeDir = join(ROOT, "evidence", spike);
const summaryPath = join(spikeDir, "summary.json");
const reportPath = join(spikeDir, "REPORT.md");

const summary = JSON.parse(await readFile(summaryPath, "utf8"));
const schemaErrors = validateSummary(summary);
assert.equal(schemaErrors.length, 0, schemaErrors.join("\n"));
const report = renderReport(summary);

if (args.write) {
  await writeFile(reportPath, report, "utf8");
  console.log(`wrote ${reportPath}`);
} else {
  process.stdout.write(report);
}
