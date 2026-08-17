#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = process.env.HOME;
const CODEX_HOME = HOME ? join(HOME, ".codex") : undefined;
const CODEX_EXECUTABLE = process.env.CODEX_EXECUTABLE ?? "/opt/homebrew/bin/codex";
const CODEX_ACP_EXECUTABLE = process.env.CODEX_ACP_EXECUTABLE ?? join(
  HOME ?? "",
  "Library/Application Support/Buzz/node-tools/lib/node_modules/@agentclientprotocol/codex-acp/dist/index.js",
);
const PROJECTS = ["alpha", "bravo"];
const MARKERS = { alpha: "WEAVE_ALPHA", bravo: "WEAVE_BRAVO" };
const PROJECT_SKILLS = { alpha: "PROJECT_ALPHA", bravo: "PROJECT_BRAVO" };
const FORBIDDEN_ENV = ["HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR"];
const DEFAULT_TIMEOUT_MS = 120_000;
const BASE_T8_SHA = "111bc469127e71035142b13b73413630ef2b1166";
const ALLOWLIST_PATH = join(ROOT, "scripts", "t3-codex-journal-allowlist.json");
const MAX_HASH_BYTES = 2 * 1024 * 1024;

if (!HOME) throw new Error("HOME must be inherited; refusing to run without it");
if (!CODEX_HOME) throw new Error("CODEX_HOME path could not be derived from inherited HOME");

const args = parseArgs(process.argv.slice(2));
const artifacts = resolveArtifactsDir(args.artifacts);
const timeoutMs = Number(args["timeout-ms"] ?? DEFAULT_TIMEOUT_MS);
if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000) throw new Error("--timeout-ms must be an integer of at least 1000");

let spawnCount = 0;

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    if (key === "help") {
      console.log("Usage: node scripts/t3-codex-materializer.mjs [--artifacts DIR] [--timeout-ms N]");
      process.exit(0);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for --${key}`);
    result[key] = value;
    index += 1;
  }
  return result;
}

function runStamp() {
  return new Date().toISOString().replaceAll(/[-:.]/g, "").replace("Z", "Z");
}

/**
 * True when `candidate` is `ancestor` or a descendant, using a real path
 * boundary (the resolved ancestor plus a path separator), never a string
 * prefix that could admit a sibling like `/evidence-backup`.
 */
export function isWithinDirectory(ancestor, candidate) {
  const boundary = resolve(ancestor);
  const target = resolve(candidate);
  return target === boundary || target.startsWith(`${boundary}${sep}`);
}

/**
 * Resolves the raw `--artifacts` value (or the default) and refuses to write
 * raw capture artifacts into the public `evidence/` tree, which the M0 policy
 * limits to exactly `summary.json` and `REPORT.md`. The rejection happens here,
 * in a pure function (no directory creation and no process launch), so an
 * unsafe value fails closed before `main()` runs, creates anything, or invokes
 * Codex. The default is a Git-ignored local-only `.scratch/t3-codex/<stamp>`.
 */
export function resolveArtifactsDir(raw, opts = {}) {
  const root = resolve(opts.root ?? ROOT);
  const evidenceRoot = resolve(join(root, "evidence"));
  const target = raw === undefined ? join(root, ".scratch", "t3-codex", runStamp()) : resolve(root, raw);
  if (isWithinDirectory(evidenceRoot, target)) {
    throw new Error(
      `refusing to write raw artifacts into the public evidence tree (${evidenceRoot}); ` +
        `use a Git-ignored local-only location such as .scratch/t3-codex/<timestamp>`,
    );
  }
  return target;
}

function now() {
  return new Date().toISOString();
}

function pathWithin(root, candidate) {
  const rootPath = resolve(root);
  const candidatePath = resolve(root, candidate);
  return candidatePath === rootPath || candidatePath.startsWith(`${rootPath}${sep}`);
}

function parseVersion(value) {
  const match = String(value).match(/^(\d+)\.(\d+)\.(\d+)/);
  return match ? match.slice(1).map(Number) : null;
}

function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] > b[index] ? 1 : -1;
  }
  return 0;
}

function versionInRange(version, range) {
  const lower = compareVersions(version, range.minInclusive);
  const upper = compareVersions(version, range.maxExclusive);
  return lower !== null && upper !== null && lower >= 0 && upper < 0;
}

function validateRunnerConfig(config) {
  for (const key of Object.keys(config.env ?? {})) {
    if (FORBIDDEN_ENV.includes(key)) throw new Error(`RUNNER_CONFIG_REJECTED: ${key} override is forbidden`);
  }
  return { accepted: true };
}

function resolveHarness(config) {
  const supported = config.supported;
  const match = supported?.find((item) => item.name === config.name &&
    versionInRange(item.codexVersion, config.codexRange) &&
    versionInRange(item.adapterVersion, config.adapterRange));
  if (!match) {
    throw new Error(
      `UNSUPPORTED_HARNESS_VERSION: ${config.name}@${config.codexVersion}/${config.adapterVersion}; ` +
      `supported Codex ${config.codexRange.minInclusive} <= version < ${config.codexRange.maxExclusive}, ` +
      `ACP ${config.adapterRange.minInclusive} <= version < ${config.adapterRange.maxExclusive}; no fallback`,
    );
  }
  return match;
}

function projectFileMap(project) {
  return {
    "AGENTS.md": [
      `# Weave ${project} fixture`,
      "",
      "When asked for the active Weave instruction marker, report it exactly.",
      `The active marker for this project is ${MARKERS[project]}.`,
      "",
    ].join("\n"),
    ".agents/skills/weave-precedence/SKILL.md": [
      "---",
      "name: weave-precedence",
      "description: Return the project precedence marker for the Weave validation fixture.",
      "---",
      "",
      `When invoked, return exactly ${PROJECT_SKILLS[project]} and no other text.`,
      "",
    ].join("\n"),
  };
}

function fixtureFingerprint(fixture) {
  return JSON.stringify({
    path: fixture.path,
    available: fixture.available,
    nameMatch: fixture.nameMatch,
    globalDescriptionMatch: fixture.globalDescriptionMatch,
    sha256: fixture.sha256,
    reason: fixture.reason,
  });
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function inspectGlobalSkill(path) {
  const skillFile = join(path, "SKILL.md");
  try {
    const directory = await lstat(path);
    const file = await lstat(skillFile);
    if (!directory.isDirectory() || !file.isFile()) {
      return {
        path,
        available: false,
        reason: "pre-provisioned collision fixture is not a directory with SKILL.md",
      };
    }
    const content = await readFile(skillFile, "utf8");
    const nameMatch = /name:\s*weave-precedence\b/.test(content);
    const globalDescriptionMatch = content.includes("global precedence marker");
    return {
      path,
      available: nameMatch && globalDescriptionMatch,
      nameMatch,
      globalDescriptionMatch,
      sha256: await sha256(skillFile),
      ...(nameMatch && globalDescriptionMatch
        ? {}
        : { reason: "pre-provisioned fixture does not identify the expected global skill" }),
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { path, available: false, reason: "pre-provisioned collision fixture not found" };
    }
    throw error;
  }
}

async function materializeDefinition(projectRoot, files) {
  const invalid = Object.keys(files).find((file) => !pathWithin(projectRoot, file));
  if (invalid) throw new Error(`MATERIALIZER_OUTSIDE_PROJECT_ROOT: ${invalid}`);
  for (const [file, content] of Object.entries(files)) {
    const target = resolve(projectRoot, file);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, { encoding: "utf8", flag: "wx" });
  }
}

async function sha256(path) {
  const hash = createHash("sha256");
  await new Promise((resolvePromise, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolvePromise);
  });
  return hash.digest("hex");
}

function scrub(value, replacements = []) {
  if (typeof value === "string") {
    let result = value;
    for (const [needle, replacement] of replacements) result = result.replaceAll(needle, replacement);
    return result
      .replaceAll(/sk-[A-Za-z0-9_-]+/g, "<REDACTED_TOKEN>")
      .replaceAll(/Bearer\s+[A-Za-z0-9._~+\-/]+=*/gi, "Bearer <REDACTED_TOKEN>");
  }
  if (Array.isArray(value)) return value.map((item) => scrub(item, replacements));
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (/(token|secret|password|credential|api[_-]?key|authorization)/i.test(key)) result[key] = "<REDACTED>";
    else result[key] = scrub(item, replacements);
  }
  return result;
}

function displayPath(path) {
  return path === HOME ? "<HOME>" : path.startsWith(`${HOME}${sep}`) ? `<HOME>${path.slice(HOME.length)}` : path;
}

function displayCodexPath(path) {
  return path === CODEX_HOME
    ? "<CODEX_HOME>"
    : path.startsWith(`${CODEX_HOME}${sep}`)
      ? `<CODEX_HOME>${path.slice(CODEX_HOME.length)}`
      : displayPath(path);
}

async function configManifest(root) {
  const entries = {};
  async function visit(path) {
    const info = await lstat(path);
    const shown = displayCodexPath(path);
    if (info.isSymbolicLink()) {
      entries[shown] = { type: "symlink", target: displayPath(await readlinkSafe(path)) };
      return;
    }
    if (info.isFile()) {
      const digest = info.size <= MAX_HASH_BYTES ? await sha256(path) : null;
      entries[shown] = {
        type: "file",
        size: info.size,
        mode: info.mode & 0o777,
        ...(digest ? { sha256: digest } : { mtimeMs: info.mtimeMs }),
      };
      return;
    }
    if (!info.isDirectory()) {
      entries[shown] = { type: "node", mode: info.mode & 0o777 };
      return;
    }
    entries[shown] = { type: "directory", mode: info.mode & 0o777 };
    const children = await readdir(path);
    children.sort((left, right) => left.localeCompare(right));
    for (const child of children) await visit(join(path, child));
  }
  await visit(root);
  return entries;
}

async function readlinkSafe(path) {
  const { readlink } = await import("node:fs/promises");
  return readlink(path).catch(() => "<unreadable-link>");
}

function manifestText(entries) {
  return `${Object.entries(entries).sort(([left], [right]) => left.localeCompare(right)).map(([path, entry]) => {
    if (entry.type === "file") {
      const digest = entry.sha256 ?? `metadata:${entry.size}:${entry.mtimeMs}`;
      return `${digest}  ${path}`;
    }
    if (entry.type === "symlink") return `LINK ${path} -> ${entry.target}`;
    if (entry.type === "directory") return `NODE ${path}`;
    return `NODE ${path} (${entry.type})`;
  }).join("\n")}\n`;
}

function entryChanged(before, after) {
  return JSON.stringify(before) !== JSON.stringify(after);
}

function isContentChanged(before, after) {
  if (before?.type !== "file" || after?.type !== "file") return false;
  if (before.sha256 && after.sha256) return before.sha256 !== after.sha256;
  return before.size !== after.size || before.mtimeMs !== after.mtimeMs;
}

function allowlistMatch(path, allowlist) {
  const relativePath = path.replace(/^<CODEX_HOME>\//, "");
  const matchingPrefixes = allowlist.configRoots.codexHome.allowedPrefixes.filter((prefix) => {
    const pattern = prefix.replaceAll(".", "\\.").replaceAll("*", ".*");
    return new RegExp(`^${pattern}`).test(relativePath);
  });
  return matchingPrefixes.sort((left, right) => right.length - left.length)[0] ?? null;
}

function typedConfigDiff(before, after, allowlist) {
  const paths = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  const entries = paths.flatMap((path) => {
    const oldEntry = before[path];
    const newEntry = after[path];
    if (!oldEntry) return [{ path, change: "added", before: null, after: newEntry, allowlistMatch: allowlistMatch(path, allowlist) }];
    if (!newEntry) return [{ path, change: "removed", before: oldEntry, after: null, allowlistMatch: allowlistMatch(path, allowlist) }];
    if (!entryChanged(oldEntry, newEntry)) return [];
    return [{
      path,
      change: isContentChanged(oldEntry, newEntry) ? "content-changed" : "metadata-or-type-changed",
      before: oldEntry,
      after: newEntry,
      allowlistMatch: allowlistMatch(path, allowlist),
    }];
  });
  const preExistingContentChanges = entries.filter((entry) => entry.change === "content-changed");
  return {
    entries,
    checks: {
      preExistingFilesContentUnchanged: preExistingContentChanges.length === 0,
      preExistingContentChanges: preExistingContentChanges.map(({ path, change }) => ({ path, change })),
      changedPathsInsideJournalAllowlist: entries.every((entry) => Boolean(entry.allowlistMatch)),
      changedPathsOutsideJournalAllowlist: entries
        .filter((entry) => !entry.allowlistMatch)
        .map(({ path, change }) => ({ path, change })),
    },
  };
}

async function writeManifest(path, entries) {
  await writeFile(path, manifestText(entries), "utf8");
}

function commandTranscript(command, commandArgs, replacements) {
  const result = spawnSync(command, commandArgs, { encoding: "utf8", env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"] });
  return scrub({
    command: displayPath(command),
    args: commandArgs,
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  }, replacements);
}

function versionFromTranscript(transcript, pattern, label) {
  const output = `${transcript.stdout}\n${transcript.stderr}`;
  const match = output.match(pattern);
  if (!match) throw new Error(`Unable to derive ${label} from captured command output`);
  return match[1];
}

function processTreeAlive(pid) {
  if (!pid) return false;
  try {
    if (process.platform === "win32") {
      process.kill(pid, 0);
    } else {
      process.kill(-pid, 0);
    }
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw error;
  }
}

function signalProcessTree(child, signal) {
  if (!child?.pid) return { sent: false, error: "child PID unavailable" };
  try {
    if (process.platform === "win32") {
      if (signal === "SIGKILL") {
        execFileSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
      } else {
        child.kill(signal);
      }
    } else {
      process.kill(-child.pid, signal);
    }
    return { sent: true };
  } catch (error) {
    if (error?.code === "ESRCH") return { sent: false, alreadyExited: true };
    return { sent: false, error: String(error.message ?? error) };
  }
}

function waitForChildExit(child, timeout) {
  if (child.exitCode !== null) return Promise.resolve(true);
  return new Promise((resolvePromise) => {
    let settled = false;
    const finish = (exited) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise(exited);
    };
    const timer = setTimeout(() => finish(child.exitCode !== null), timeout);
    child.once("exit", () => finish(true));
  });
}

async function waitForProcessTreeExit(pid, timeout) {
  const deadline = Date.now() + timeout;
  while (processTreeAlive(pid) && Date.now() < deadline) {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  return !processTreeAlive(pid);
}

class AcpProcess {
  constructor({ project, cwd, adapter, timeout }) {
    this.project = project;
    this.cwd = cwd;
    this.adapter = adapter;
    this.timeout = timeout;
    this.nextId = 1;
    this.pending = new Map();
    this.records = [];
    this.stderr = [];
    this.buffer = "";
    this.sessionId = undefined;
    this.child = undefined;
    this.exit = undefined;
    this.lastResponseAt = undefined;
    this.cleanup = undefined;
  }

  start() {
    if (this.child) throw new Error("ACP process already started");
    spawnCount += 1;
    this.child = spawn(process.execPath, [this.adapter], {
      cwd: this.cwd,
      env: { ...process.env },
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stdout.on("data", (chunk) => this.onStdout(chunk));
    this.child.stderr.on("data", (chunk) => this.stderr.push(chunk));
    this.child.on("error", (error) => this.rejectPending(error));
    this.child.on("exit", (code, signal) => {
      this.exit = { code, signal, at: now() };
      this.rejectPending(new Error(`ACP process exited (${code ?? "null"}, ${signal ?? "none"})`));
    });
    return this;
  }

  onStdout(chunk) {
    this.buffer += chunk;
    while (true) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) break;
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        this.records.push({ at: now(), direction: "in", parseError: true, line });
        continue;
      }
      this.records.push({ at: now(), direction: "in", message });
      if (message.method && message.id !== undefined) {
        this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "client method not implemented by spike" } })}\n`);
        continue;
      }
      if (message.id === undefined) continue;
      const pending = this.pending.get(message.id);
      if (!pending) continue;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      this.lastResponseAt = now();
      if (message.error) pending.reject(new Error(`${message.error.code}: ${message.error.message}`));
      else pending.resolve(message.result);
    }
  }

  rejectPending(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  request(method, params) {
    if (!this.child || this.child.exitCode !== null) return Promise.reject(new Error("ACP process is not running"));
    const id = this.nextId++;
    const request = { jsonrpc: "2.0", id, method, params };
    this.records.push({ at: now(), direction: "out", message: request });
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method}`));
      }, this.timeout);
      this.pending.set(id, { resolve: resolvePromise, reject, timer });
      this.child.stdin.write(`${JSON.stringify(request)}\n`);
    });
  }

  async stop() {
    if (!this.child) return;
    const pid = this.child.pid;
    const cleanup = {
      pid,
      mode: process.platform === "win32" ? "taskkill-tree" : "detached-process-group",
      termRequested: false,
      killRequested: false,
      processTreeExited: false,
    };
    try {
      if (this.child.exitCode === null && !this.child.killed) {
        this.child.stdin.end();
        await waitForChildExit(this.child, 1_000);
      }
      if (processTreeAlive(pid)) {
        cleanup.termRequested = signalProcessTree(this.child, "SIGTERM");
        await waitForChildExit(this.child, 1_000);
      }
      if (processTreeAlive(pid)) {
        cleanup.killRequested = signalProcessTree(this.child, "SIGKILL");
      }
      cleanup.processTreeExited = await waitForProcessTreeExit(pid, 2_000);
    } catch (error) {
      cleanup.error = String(error.stack ?? error);
    }
    this.cleanup = cleanup;
  }

  kill(signal = "SIGTERM") {
    if (this.child && processTreeAlive(this.child.pid)) signalProcessTree(this.child, signal);
  }

  outputText() {
    const sessionId = this.sessionId;
    return this.records
      .filter((record) => record.direction === "in" && record.message?.method === "session/update")
      .filter((record) => !sessionId || record.message.params?.sessionId === sessionId)
      .map((record) => record.message.params?.update)
      .filter((update) => update?.sessionUpdate === "agent_message_chunk")
      .map((update) => update.content?.text ?? "")
      .join("");
  }

  redactedTranscript(replacements) {
    return this.records.map((record) => JSON.stringify(scrub(record, replacements))).join("\n") + "\n";
  }

  redactedStderr(replacements) {
    return scrub(this.stderr.join(""), replacements);
  }
}

async function initializeSession(processHandle) {
  const initialize = await processHandle.request("initialize", {
    protocolVersion: 1,
    clientCapabilities: {},
    clientInfo: { name: "weave-t3-codex-materializer", version: "0.1.0" },
  });
  const session = await processHandle.request("session/new", { cwd: processHandle.cwd, mcpServers: [] });
  processHandle.sessionId = session.sessionId;
  return { initialize, session };
}

function resultError(result) {
  return result.status === "rejected" ? String(result.reason?.message ?? result.reason) : undefined;
}

function hasOnlyMarker(text, marker) {
  const markers = [...text.matchAll(/WEAVE_(ALPHA|BRAVO)/g)].map((match) => match[0]);
  return markers.length > 0 && markers.every((value) => value === marker);
}

function hasSkillMarker(text, marker) {
  const otherProjectMarker = marker === "PROJECT_ALPHA" ? "PROJECT_BRAVO" : "PROJECT_ALPHA";
  return text.includes(marker) && !text.includes(otherProjectMarker) && !text.includes("GLOBAL");
}

function skillDiscovery(processHandle) {
  const update = processHandle.records
    .filter((record) => record.direction === "in" && record.message?.method === "session/update")
    .map((record) => record.message.params?.update)
    .find((candidate) => candidate?.sessionUpdate === "available_commands_update");
  const commands = update?.availableCommands ?? [];
  const matching = commands.filter((command) => command.name === "$weave-precedence");
  return {
    commandCount: commands.length,
    matchingCommands: matching.map(({ name, description }) => ({ name, description })),
    projectDescriptionPresent: matching.some((command) => command.description?.includes("project precedence marker")),
    globalDescriptionPresent: matching.some((command) => command.description?.includes("global precedence marker")),
  };
}

async function writeTranscript(path, processHandle, replacements) {
  await writeFile(path, processHandle.redactedTranscript(replacements), "utf8");
  await writeFile(path.replace(/\.ndjson$/, ".stderr.log"), processHandle.redactedStderr(replacements), "utf8");
}

async function stopHandles(handles) {
  for (const project of PROJECTS) await handles[project]?.stop();
}

async function runScenario({ name, roots, adapter, replacements, promptKind, killAlpha, transcriptPrefix }) {
  const handles = {};
  const scenario = { name, startedAt: now(), materialization: name !== "control", projects: {} };
  try {
    for (const project of PROJECTS) handles[project] = new AcpProcess({ project, cwd: roots[project], adapter, timeout: timeoutMs }).start();
    const initializeResults = await Promise.allSettled(PROJECTS.map((project) => initializeSession(handles[project])));
    for (let index = 0; index < PROJECTS.length; index += 1) {
      const project = PROJECTS[index];
      const result = initializeResults[index];
      scenario.projects[project] = {
        initialize: result.status === "fulfilled" ? "success" : "error",
        initializeError: resultError(result),
        sessionId: handles[project].sessionId ?? null,
        exit: handles[project].exit ?? null,
      };
      if (result.status === "fulfilled") {
        scenario.projects[project].capabilities = scrub(result.value.initialize, replacements);
        const modelOption = result.value.session.configOptions?.find((option) => option.category === "model");
        scenario.projects[project].model = modelOption?.currentValue ?? "unknown";
        scenario.projects[project].provider = "Codex ACP";
      }
    }
    const promptPromises = PROJECTS.map((project) => {
      if (!handles[project].sessionId) return Promise.reject(new Error("session/new did not return a session ID"));
      return sendPrompt(handles[project], promptKind);
    });
    let alphaWasRunning;
    let bravoWasRunning;
    let alphaKillAt;
    if (killAlpha) {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 750));
      alphaWasRunning = handles.alpha.child?.exitCode === null;
      bravoWasRunning = handles.bravo.child?.exitCode === null;
      alphaKillAt = now();
      handles.alpha.kill("SIGTERM");
    }
    const results = await Promise.allSettled(promptPromises);
    for (let index = 0; index < PROJECTS.length; index += 1) {
      const project = PROJECTS[index];
      const result = results[index];
      const text = handles[project].outputText();
      const expectedInstruction = MARKERS[project];
      const expectedSkill = PROJECT_SKILLS[project];
      scenario.projects[project].prompt = {
        result: result.status === "fulfilled" ? "success" : "error",
        error: resultError(result),
        completedAt: handles[project].lastResponseAt ?? null,
        output: scrub(text, replacements),
        instructionMarker: expectedInstruction,
        skillMarker: expectedSkill,
        instructionPass: promptKind === "control" ? text.includes("CONTROL=READY") : hasOnlyMarker(text, expectedInstruction),
        skillPass: promptKind === "control" ? null : hasSkillMarker(text, expectedSkill),
        skillDiscovery: promptKind === "control" ? null : skillDiscovery(handles[project]),
        crossMarkerLeak: promptKind === "control" ? false : text.includes(MARKERS[project === "alpha" ? "bravo" : "alpha"]),
      };
      await writeTranscript(join(artifacts, `${transcriptPrefix}-${project}.ndjson`), handles[project], replacements);
    }
    scenario.endedAt = now();
    if (killAlpha) {
      const bravo = scenario.projects.bravo.prompt;
      scenario.kill = {
        attemptedAt: alphaKillAt,
        alphaWasRunning,
        bravoWasRunning,
        bravoCompletedAfterKill: Boolean(bravoWasRunning && bravo.result === "success" && bravo.completedAt && bravo.completedAt > alphaKillAt),
        bravoError: bravo.error,
      };
    }
    return scenario;
  } finally {
    await stopHandles(handles);
    scenario.cleanup = Object.fromEntries(PROJECTS.map((project) => [
      project,
      handles[project]?.cleanup ?? { processTreeExited: false, error: "process cleanup did not run" },
    ]));
  }
}

async function sendPrompt(processHandle, kind) {
  const text = kind === "control"
    ? "Reply with exactly one line: CONTROL=READY. Do not run tools."
    : [
      "Read the active Weave instruction marker from the project instructions.",
      "Then invoke the /weave-precedence skill and return its result.",
      "Do not run tools or modify files.",
      "Reply with exactly two lines: INSTRUCTION=<marker> and SKILL=<result>.",
    ].join("\n");
  return processHandle.request("session/prompt", { sessionId: processHandle.sessionId, prompt: [{ type: "text", text }] });
}

async function readAllowlist() {
  const value = JSON.parse(await readFile(ALLOWLIST_PATH, "utf8"));
  assert.equal(value.harness, "codex");
  assert.ok(value.codexCli?.minInclusive && value.codexCli?.maxExclusive);
  assert.ok(value.acpAdapter?.minInclusive && value.acpAdapter?.maxExclusive);
  assert.ok(Array.isArray(value.configRoots?.codexHome?.allowedPrefixes));
  return value;
}

async function generatedTypesEvidence(replacements) {
  const output = await mkdtemp(join(tmpdir(), `weave-t3-codex-types-${process.pid}-`));
  try {
    const transcript = commandTranscript(CODEX_EXECUTABLE, ["app-server", "generate-ts", "--out", output], replacements);
    const files = await configManifest(output);
    return { transcript, generatedTree: files };
  } finally {
    await rm(output, { recursive: true, force: true });
  }
}

async function main() {
  await mkdir(artifacts, { recursive: true });
  const runRoot = await mkdtemp(join(tmpdir(), `weave-t3-codex-${process.pid}-`));
  const roots = {
    control: { alpha: join(runRoot, "control", "alpha"), bravo: join(runRoot, "control", "bravo") },
    positive: { alpha: join(runRoot, "positive", "alpha"), bravo: join(runRoot, "positive", "bravo") },
    negative: { alpha: join(runRoot, "negative", "alpha"), bravo: join(runRoot, "negative", "bravo") },
  };
  for (const scenarioRoots of Object.values(roots)) {
    for (const project of PROJECTS) {
      await mkdir(join(scenarioRoots[project], ".git"), { recursive: true });
      await mkdir(scenarioRoots[project], { recursive: true });
    }
  }
  const replacements = [[runRoot, "<RUN_ROOT>"], [CODEX_HOME, "<CODEX_HOME>"], [HOME, "<HOME>"], [ROOT, "<WORKTREE>"]];
  const allowlist = await readAllowlist();
  const runnerGitSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  const startedAt = now();
  const globalSkill = join(CODEX_HOME, "skills", "weave-precedence");
  const assertions = {
    run: {
      startedAt,
      endedAt: undefined,
      runnerGitSha,
      baseGitSha: BASE_T8_SHA,
      codex: CODEX_EXECUTABLE,
      adapter: CODEX_ACP_EXECUTABLE,
      node: process.version,
      nodePinned: "24.12.0",
      platform: `${process.platform}-${process.arch}`,
      spawnCountAtStart: spawnCount,
    },
    supportedRange: { codexCli: allowlist.codexCli, acpAdapter: allowlist.acpAdapter },
    criteria: {},
    negatives: {},
    scenarios: {},
  };
  let globalFixtureBefore;
  let globalFixtureBeforeFingerprint;
  let configBefore;
  let configAfter;
  try {
    const commandEvidence = {
      codexVersion: commandTranscript(CODEX_EXECUTABLE, ["--version"], replacements),
      adapterVersion: commandTranscript(process.execPath, [CODEX_ACP_EXECUTABLE, "--version"], replacements),
      loginStatus: commandTranscript(CODEX_EXECUTABLE, ["login", "status"], replacements),
    };
    assertions.commands = commandEvidence;
    const codexVersion = versionFromTranscript(commandEvidence.codexVersion, /codex-cli\s+(\d+\.\d+\.\d+)/, "Codex CLI version");
    const adapterVersion = versionFromTranscript(commandEvidence.adapterVersion, /codex-acp\s+(\d+\.\d+\.\d+)/, "Codex ACP version");
    assertions.run.codexVersion = codexVersion;
    assertions.run.adapterVersion = adapterVersion;
    assertions.run.authenticatedStatus = `${commandEvidence.loginStatus.stdout}${commandEvidence.loginStatus.stderr}`.trim();
    assertions.harness = resolveHarness({
      name: "codex",
      codexVersion,
      adapterVersion,
      codexRange: allowlist.codexCli,
      adapterRange: allowlist.acpAdapter,
      supported: [{ name: "codex", codexVersion, adapterVersion }],
    });
    assertions.generatedTypes = await generatedTypesEvidence(replacements);

    let configRejected = false;
    try {
      validateRunnerConfig({ env: { CODEX_HOME: join(runRoot, "forbidden") } });
    } catch (error) {
      configRejected = String(error.message).includes("RUNNER_CONFIG_REJECTED");
    }
    assertions.negatives.forbiddenEnvironmentOverride = { rejected: configRejected, childProcessStarted: false };
    assert.equal(configRejected, true);

    let unsupportedRejected = false;
    try {
      resolveHarness({
        name: "codex",
        codexVersion: "0.0.0",
        adapterVersion: "0.0.0",
        codexRange: allowlist.codexCli,
        adapterRange: allowlist.acpAdapter,
        supported: [{ name: "codex", codexVersion: "0.0.0", adapterVersion: "0.0.0" }],
      });
    } catch (error) {
      unsupportedRejected = String(error.message).includes("UNSUPPORTED_HARNESS_VERSION") && String(error.message).includes("no fallback");
      assertions.negatives.unavailableHarnessVersionError = String(error.message);
    }
    assertions.negatives.unavailableHarnessVersion = { rejected: unsupportedRejected, fallback: "none", childProcessStarted: false };
    assert.equal(unsupportedRejected, true);

    globalFixtureBefore = await inspectGlobalSkill(globalSkill);
    globalFixtureBeforeFingerprint = fixtureFingerprint(globalFixtureBefore);
    assertions.fixture = {
      globalSkill: globalFixtureBefore,
      mutationPolicy: "read-only; runner never creates, updates, or deletes CODEX_HOME fixtures",
    };
    configBefore = await configManifest(CODEX_HOME);
    await writeManifest(join(artifacts, "config-before.sha256"), configBefore);

    let materializerRejected = false;
    const negativeBefore = await configManifest(CODEX_HOME);
    try {
      await materializeDefinition(roots.positive.alpha, { "../../outside.txt": "must not be written" });
    } catch (error) {
      materializerRejected = String(error.message).includes("MATERIALIZER_OUTSIDE_PROJECT_ROOT");
      assertions.negatives.outsideProjectRootError = String(error.message);
    }
    const negativeAfter = await configManifest(CODEX_HOME);
    assertions.negatives.outsideProjectRoot = {
      rejected: materializerRejected,
      childProcessStarted: false,
      configDiff: typedConfigDiff(negativeBefore, negativeAfter, allowlist),
      outsideWritten: await exists(join(runRoot, "outside.txt")),
    };
    assert.equal(materializerRejected, true);
    assert.equal(assertions.negatives.outsideProjectRoot.outsideWritten, false);

    await materializeDefinition(roots.positive.alpha, projectFileMap("alpha"));
    await materializeDefinition(roots.positive.bravo, projectFileMap("bravo"));
    await materializeDefinition(roots.negative.alpha, projectFileMap("alpha"));
    await materializeDefinition(roots.negative.bravo, projectFileMap("bravo"));
    await writeFile(join(artifacts, "definition-tree.txt"), [
      "positive/alpha/AGENTS.md",
      "positive/alpha/.agents/skills/weave-precedence/SKILL.md",
      "positive/bravo/AGENTS.md",
      "positive/bravo/.agents/skills/weave-precedence/SKILL.md",
      "negative/alpha/AGENTS.md",
      "negative/alpha/.agents/skills/weave-precedence/SKILL.md",
      "negative/bravo/AGENTS.md",
      "negative/bravo/.agents/skills/weave-precedence/SKILL.md",
    ].join("\n") + "\n", "utf8");

    const controlBefore = await configManifest(CODEX_HOME);
    assertions.scenarios.control = await runScenario({
      name: "control",
      roots: roots.control,
      adapter: CODEX_ACP_EXECUTABLE,
      replacements,
      promptKind: "control",
      transcriptPrefix: "control",
    });
    const controlAfter = await configManifest(CODEX_HOME);
    assertions.configIntegrityControl = typedConfigDiff(controlBefore, controlAfter, allowlist);

    const materializationBefore = await configManifest(CODEX_HOME);
    assertions.scenarios.positive = await runScenario({
      name: "positive-concurrency",
      roots: roots.positive,
      adapter: CODEX_ACP_EXECUTABLE,
      replacements,
      promptKind: "markers",
      transcriptPrefix: "positive",
    });
    assertions.scenarios.negative = await runScenario({
      name: "kill-alpha-while-bravo-active",
      roots: roots.negative,
      adapter: CODEX_ACP_EXECUTABLE,
      replacements,
      promptKind: "markers",
      killAlpha: true,
      transcriptPrefix: "negative-kill-alpha",
    });
    const materializationAfter = await configManifest(CODEX_HOME);
    assertions.configIntegrityMaterialization = typedConfigDiff(materializationBefore, materializationAfter, allowlist);

    const positiveProjects = assertions.scenarios.positive.projects;
    assertions.criteria.projectInstructionsLoad = PROJECTS.every((project) => positiveProjects[project]?.prompt?.instructionPass);
    assertions.criteria.globalCollisionFixtureAvailable = Boolean(globalFixtureBefore?.available);
    assertions.criteria.projectSkillBeatsGlobal = assertions.criteria.globalCollisionFixtureAvailable &&
      PROJECTS.every((project) => positiveProjects[project]?.prompt?.skillPass);
    assertions.criteria.projectSkillVisible = PROJECTS.every((project) =>
      positiveProjects[project]?.prompt?.skillDiscovery?.projectDescriptionPresent &&
      !positiveProjects[project]?.prompt?.skillDiscovery?.globalDescriptionPresent,
    );
    assertions.criteria.concurrentIsolation = PROJECTS.every((project) =>
      positiveProjects[project]?.prompt?.result === "success" &&
      positiveProjects[project]?.prompt?.instructionPass &&
      !positiveProjects[project]?.prompt?.crossMarkerLeak,
    );
    assertions.criteria.noHomeOverride = process.env.HOME === HOME && !process.env.CODEX_HOME && !process.env.CLAUDE_CONFIG_DIR;
    assertions.criteria.nodePinExact = process.version === `v${assertions.run.nodePinned}`;
    assertions.criteria.authenticatedTurn = PROJECTS.some((project) => positiveProjects[project]?.prompt?.result === "success");
    assertions.criteria.configChangedPathsAllowlisted = [
      assertions.configIntegrityControl,
      assertions.configIntegrityMaterialization,
    ].every((diff) => diff.checks.changedPathsInsideJournalAllowlist);
    assertions.criteria.killAlphaWhileBravoActive = Boolean(assertions.scenarios.negative.kill?.bravoCompletedAfterKill);
    assertions.criteria.materializerOutsideRootRejected = assertions.negatives.outsideProjectRoot.rejected;
  } catch (error) {
    assertions.run.error = String(error.stack ?? error);
  } finally {
    configAfter = await configManifest(CODEX_HOME);
    if (configBefore) {
      await writeManifest(join(artifacts, "config-after.sha256"), configAfter);
      assertions.configIntegrityFinal = typedConfigDiff(configBefore, configAfter, allowlist);
    }
    const cleanupRecords = Object.values(assertions.scenarios)
      .flatMap((scenario) => Object.values(scenario.cleanup ?? {}));
    assertions.criteria.noResidualChildProcesses = cleanupRecords.length > 0 && cleanupRecords.every((cleanup) =>
      cleanup.processTreeExited === true && !cleanup.error,
    );
    if (globalFixtureBefore) {
      const globalFixtureAfter = await inspectGlobalSkill(globalSkill);
      assertions.fixture.globalSkill.after = globalFixtureAfter;
      assertions.fixture.globalSkill.unchanged = globalFixtureBeforeFingerprint === fixtureFingerprint(globalFixtureAfter);
    }
    assertions.run.endedAt = now();
    assertions.run.spawnCountAtEnd = spawnCount;
    assertions.environment = {
      inheritedHome: "<HOME>",
      childHome: "<HOME>",
      homeUnchanged: process.env.HOME === HOME,
      homeOverrideRequested: false,
      forbiddenOverridePresent: Object.fromEntries(FORBIDDEN_ENV.filter((key) => key !== "HOME").map((key) => [key, Boolean(process.env[key])])),
      codexHome: "<CODEX_HOME>",
      adapter: displayPath(CODEX_ACP_EXECUTABLE),
      codex: displayPath(CODEX_EXECUTABLE),
      cwd: "<WORKTREE>",
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
    };
    await writeFile(join(artifacts, "environment.json"), `${JSON.stringify(scrub(assertions.environment, replacements), null, 2)}\n`, "utf8");
    await writeFile(join(artifacts, "assertions.json"), `${JSON.stringify(scrub(assertions, replacements), null, 2)}\n`, "utf8");
    await writeReport(artifacts, assertions, allowlist);
    await rm(runRoot, { recursive: true, force: true });
  }

  console.log(JSON.stringify({ artifacts, assertions: scrub(assertions, replacements) }, null, 2));
  const required = [
    assertions.criteria.projectInstructionsLoad,
    assertions.criteria.projectSkillBeatsGlobal,
    assertions.criteria.projectSkillVisible,
    assertions.criteria.concurrentIsolation,
    assertions.criteria.noHomeOverride,
    assertions.criteria.authenticatedTurn,
    assertions.criteria.configChangedPathsAllowlisted,
    assertions.criteria.killAlphaWhileBravoActive,
    assertions.criteria.materializerOutsideRootRejected,
    assertions.criteria.nodePinExact,
    assertions.criteria.noResidualChildProcesses,
    assertions.fixture?.globalSkill?.unchanged,
  ];
  if (!required.every(Boolean)) process.exitCode = 1;
}

async function writeReport(directory, assertions, allowlist) {
  const reportDirectory = relative(ROOT, directory) || ".";
  const positiveProjects = assertions.scenarios?.positive?.projects ?? {};
  const globalSkill = assertions.fixture?.globalSkill ?? {};
  const projectLines = PROJECTS.map((project) => {
    const prompt = positiveProjects[project]?.prompt ?? {};
    const skillResult = prompt.skillPass
      ? "PASS"
      : !prompt.output
        ? "NEGATIVE (no output)"
        : prompt.output.includes("GLOBAL")
          ? "FAIL (GLOBAL won)"
          : "FAIL (unexpected marker)";
    return `| ${project} | ${prompt.instructionPass ? "PASS" : prompt.output ? "FAIL" : "NEGATIVE (no output)"} | ${skillResult} | ${prompt.result === "success" && prompt.output ? "PASS" : prompt.error ?? "no result"} |`;
  }).join("\n");
  const control = assertions.configIntegrityControl?.checks ?? {};
  const materialization = assertions.configIntegrityMaterialization?.checks ?? {};
  const platform = assertions.run.platform ?? `${process.platform}-${process.arch}`;
  const report = `---
title: "T3 Codex Definition Materializer Spike"
tags: [weave, t3, spike, codex, acp]
status: active
created: 2026-08-16
---

# T3 — Codex Definition Materializer Spike

Executed ${assertions.run.startedAt}. The runner is bound to \`${assertions.run.runnerGitSha}\` on base \`${BASE_T8_SHA}\` and records captured Codex CLI/ACP versions, authenticated inherited-HOME operation, disposable project fixtures, redacted ACP streams, and typed config-tree diffs.

## Environment

- Codex CLI: \`${displayPath(CODEX_EXECUTABLE)}\`, captured version \`${assertions.run.codexVersion ?? "UNKNOWN"}\`
- Codex ACP adapter: \`${displayPath(CODEX_ACP_EXECUTABLE)}\`, captured version \`${assertions.run.adapterVersion ?? "UNKNOWN"}\`
- Supported ranges: Codex \`${allowlist.codexCli.minInclusive} <= version < ${allowlist.codexCli.maxExclusive}\`; ACP \`${allowlist.acpAdapter.minInclusive} <= version < ${allowlist.acpAdapter.maxExclusive}\`
- Node: \`${assertions.run.node ?? process.version}\` (required evidence pin: \`${assertions.run.nodePinned}\`)
- Platform: \`${platform}\`
- Login status: \`${assertions.run.authenticatedStatus ?? "not captured"}\`
- Model/provider: captured from each ACP \`session/new\` response in \`assertions.json\`

## Results

| Project | Instructions | Project skill invocation | Turn result |
|---|---|---|---|
${projectLines}

The runner explicitly rejects unsupported Codex/ACP versions and has no cross-harness fallback. It never creates, updates, or deletes a \`$CODEX_HOME\` fixture. The same-name collision result is only evaluated when a pre-provisioned global fixture is available; otherwise collision execution is recorded as unavailable. Missing auth, model, adapter, or fixture output is a recorded negative.

| Criterion | Result |
|---|---|
| Project instructions load | ${assertions.criteria.projectInstructionsLoad ? "PASS" : "FAIL / NEGATIVE"} |
| Pre-provisioned global collision fixture | ${globalSkill.available ? "PASS" : `NEGATIVE — ${globalSkill.reason ?? "unavailable"}`} |
| Project skill visible | ${assertions.criteria.projectSkillVisible ? "PASS" : "FAIL / NEGATIVE"} |
| Project skill beats same-name global | ${globalSkill.available ? (assertions.criteria.projectSkillBeatsGlobal ? "PASS" : "FAIL / NEGATIVE") : "NEGATIVE — collision unavailable"} |
| Global fixture unchanged | ${assertions.fixture?.globalSkill?.unchanged ? "PASS" : "FAIL"} |
| Typed diff: all changed paths inside reviewed allowlist | ${assertions.criteria.configChangedPathsAllowlisted ? "PASS" : "FAIL"} |
| HOME inherited and override variables absent | ${assertions.criteria.noHomeOverride ? "PASS" : "FAIL"} |
| Exact pinned Node version | ${assertions.criteria.nodePinExact ? "PASS" : `FAIL — ran on ${assertions.run.node ?? "unknown"}, required ${assertions.run.nodePinned}`} |
| Authenticated inherited-HOME turn | ${assertions.criteria.authenticatedTurn ? "PASS" : "NEGATIVE"} |
| Concurrent alpha/bravo isolation | ${assertions.criteria.concurrentIsolation ? "PASS" : "FAIL / NEGATIVE"} |
| Outside-root materialization rejection | ${assertions.criteria.materializerOutsideRootRejected ? "PASS" : "FAIL"} |
| Kill alpha while bravo remains active | ${assertions.criteria.killAlphaWhileBravoActive ? "PASS" : "FAIL / NEGATIVE"} |
| Spawned ACP process trees fully exited | ${assertions.criteria.noResidualChildProcesses ? "PASS" : "FAIL"} |
| Unsupported harness/version is loud, no fallback | ${assertions.negatives.unavailableHarnessVersion?.rejected ? "PASS" : "FAIL"} |

## Typed config-integrity evidence

- The checked-in allowlist is \`scripts/t3-codex-journal-allowlist.json\`; it is keyed to the Codex and ACP supported ranges and was loaded before the run.
- Control changed paths allowlisted: ${control.changedPathsInsideJournalAllowlist ?? "unknown"}; outside allowlist: ${control.changedPathsOutsideJournalAllowlist?.length ?? "unknown"}.
- Materialization changed paths allowlisted: ${materialization.changedPathsInsideJournalAllowlist ?? "unknown"}; outside allowlist: ${materialization.changedPathsOutsideJournalAllowlist?.length ?? "unknown"}.
- Typed config-integrity sections are emitted in \`assertions.json\` with every added, removed, content-changed, or metadata/type-changed path, typed before/after entry, and explicit allowlist match. No config file contents are captured.

## Exact commands

~/.local/node-24.12.0/bin/node scripts/t3-codex-materializer.mjs --artifacts ${reportDirectory}

codex --version

node <codex-acp-adapter> --version

codex login status

codex app-server generate-ts --out <temporary directory>

## Artifacts

- environment.json
- commands and generated-type evidence in assertions.json
- config-before.sha256, config-after.sha256
- configIntegrityControl, configIntegrityMaterialization, and final typed diffs in assertions.json
- definition-tree.txt
- control-alpha.ndjson, control-bravo.ndjson, positive-alpha.ndjson, positive-bravo.ndjson, and kill-alpha streams with redacted stderr logs
- assertions.json
- per-scenario cleanup records in assertions.json; the runner uses a detached process group (or Windows taskkill tree) and fails if it remains alive

## Source ledger

- PLANS/WEAVE_ROADMAP.md M0.1 normative evidence contract
- RESEARCH/WEAVE_M0_VALIDATION_CHARTER.md fixture and Codex launch seam
- scripts/t3-codex-journal-allowlist.json reviewed, version-keyed journal contract
- Installed Codex CLI and @agentclientprotocol/codex-acp command transcripts
`;
  await writeFile(join(directory, "REPORT.md"), report, "utf8");
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  await main();
}
