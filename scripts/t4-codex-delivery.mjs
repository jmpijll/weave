#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { createReadStream } from "node:fs";
import { arch, platform, release, tmpdir, version } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertArtifactAggregateBinding,
  assertRunnerEnvironment,
  assertPrivacySafeEvidence,
  assertSupportedHarnessVersions,
  computeArtifactsSha256,
  environmentEvidence,
  mergedPrompt,
  nativeSteerAdvertised,
  REQUIRED_NODE,
  selectDeliveryPath,
  typedConfigTreeDiff,
} from "./t4-codex-delivery-contract.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = process.env.HOME;
const CODEX_HOME = HOME ? join(HOME, ".codex") : undefined;
const CODEX_EXECUTABLE = process.env.CODEX_EXECUTABLE ?? "codex";
const CODEX_ACP_COMMAND = "codex-acp";

/**
 * Resolve the adapter through PATH by default. A configured adapter remains
 * a Node-loaded script for the existing Buzz Desktop integration, but no
 * platform-specific installation path is embedded in the runner.
 */
export function adapterInvocation(configuredAdapter) {
  const adapter = typeof configuredAdapter === "string" ? configuredAdapter.trim() : "";
  return adapter
    ? { command: process.execPath, args: [adapter], executable: adapter }
    : { command: CODEX_ACP_COMMAND, args: [], executable: CODEX_ACP_COMMAND };
}

const ADAPTER_LAUNCH = adapterInvocation(process.env.CODEX_ACP_EXECUTABLE);
const ADAPTER = ADAPTER_LAUNCH.executable;
const ALLOWLIST_PATH = join(ROOT, "scripts", "t4-codex-journal-allowlist.json");
const BASE_T8_SHA = "0662a991fc03d6666a9a719a7df78ceecfeaa2a4";
const TIMEOUT_MS = 120_000;
const ORIGINAL_MARKER = "WEAVE_CODEX_ORIGINAL_COMPLETE";
const EVENT_MARKER = "WEAVE_CODEX_INJECTED_EVENT_ACCEPTED";
const ORIGINAL_TASK = [
  "TASK-ORIGINAL: use the available terminal tool to run the bounded command `sleep 8`.",
  `After it returns, provide a short result and include exactly ${ORIGINAL_MARKER} in the final answer.`,
].join(" ");
const INJECTED_EVENT = `EVENT-STEER-1: while completing the original task, include exactly ${EVENT_MARKER} in the final answer.`;

export function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--help") {
      console.log("Usage: node scripts/t4-codex-delivery.mjs [--artifacts DIR]");
      process.exit(0);
    }
    if (token !== "--artifacts" || !argv[index + 1]) throw new Error(`Invalid argument: ${token}`);
    result.artifacts = argv[index + 1];
    index += 1;
  }
  return result;
}

/**
 * True when `candidate` is the evidence root or a descendant, using a real
 * path boundary rather than a string prefix that could admit a sibling such
 * as `evidence-backup`.
 */
export function isWithinDirectory(ancestor, candidate) {
  const boundary = resolve(ancestor);
  const target = resolve(candidate);
  return target === boundary || target.startsWith(`${boundary}${sep}`);
}

/**
 * Resolve the raw-artifact destination without touching the filesystem. Raw
 * captures default to the Git-ignored local-only scratch tree and public
 * evidence destinations fail closed before `main()` can create anything or
 * launch Codex.
 */
export function resolveArtifactsDir(raw, opts = {}) {
  const root = resolve(opts.root ?? ROOT);
  const evidenceRoot = resolve(join(root, "evidence"));
  const target = raw === undefined
    ? join(root, ".scratch", "t4-codex", stamp())
    : resolve(root, raw);
  if (isWithinDirectory(evidenceRoot, target)) {
    throw new Error(
      `refusing to write raw artifacts into the public evidence tree (${evidenceRoot}); ` +
        "use a Git-ignored local-only location such as .scratch/t4-codex/<timestamp>",
    );
  }
  return target;
}

function stamp() {
  return new Date().toISOString().replaceAll(/[-:.]/g, "").replace("Z", "Z");
}

function now() {
  return new Date().toISOString();
}

function microsNow() {
  return process.hrtime.bigint().toString();
}

function displayPath(path) {
  if (!path) return path;
  if (HOME && path === HOME) return "<HOME>";
  if (HOME && path.startsWith(`${HOME}${sep}`)) return `<HOME>${path.slice(HOME.length)}`;
  if (path === CODEX_EXECUTABLE) return "<CODEX_CLI>";
  if (path === ADAPTER) return "<CODEX_ACP>";
  return isAbsolute(path) ? `<ABSOLUTE_PATH:${basename(path)}>` : path;
}

function scrub(value, replacements = []) {
  if (typeof value === "string") {
    let result = value;
    for (const [source, destination] of replacements) result = result.replaceAll(source, destination);
    return result
      .replaceAll(/sk-[A-Za-z0-9_-]{20,}/g, "<REDACTED_TOKEN>")
      .replaceAll(/Bearer\s+[A-Za-z0-9._~+\-/]+=*/gi, "Bearer <REDACTED_TOKEN>");
  }
  if (Array.isArray(value)) return value.map((entry) => scrub(entry, replacements));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
    key,
    /(token|secret|password|credential|api[_-]?key|authorization|email)/i.test(key)
      ? "<REDACTED>"
      : scrub(entry, replacements),
  ]));
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
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

const MAX_HASH_BYTES = 2 * 1024 * 1024;

async function configManifest(root) {
  const entries = {};
  if (!root || !(await exists(root))) return entries;

  async function visit(path) {
    const info = await lstat(path);
    const shown = displayPath(path).replace("<HOME>/.codex", "<CODEX_HOME>");
    if (info.isSymbolicLink()) {
      entries[shown] = { type: "symlink", target: displayPath(await readlink(path)) };
      return;
    }
    if (info.isFile()) {
      entries[shown] = {
        type: "file",
        size: info.size,
        mode: info.mode & 0o777,
        ...(info.size <= MAX_HASH_BYTES ? { sha256: await sha256(path) } : { mtimeMs: info.mtimeMs }),
      };
      return;
    }
    if (!info.isDirectory()) {
      entries[shown] = { type: "node", mode: info.mode & 0o777 };
      return;
    }
    entries[shown] = { type: "directory", mode: info.mode & 0o777 };
    for (const child of (await readdir(path)).sort((left, right) => left.localeCompare(right))) {
      await visit(join(path, child));
    }
  }

  await visit(root);
  return entries;
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function artifactEntries(root) {
  return Promise.all(
    (await readdir(root, { withFileTypes: true }))
      .filter((entry) => entry.isFile())
      .map(async (entry) => ({
        name: entry.name,
        bytes: await readFile(join(root, entry.name)),
      })),
  );
}

async function assertArtifactPrivacy(root) {
  for (const entry of await artifactEntries(root)) {
    if (entry.name !== "assertions.json") {
      assertPrivacySafeEvidence(entry.bytes.toString("utf8"), entry.name);
    }
  }
}

function commandIdentity(command) {
  if (command === CODEX_EXECUTABLE) return "codex-cli";
  if (command === ADAPTER) return "@agentclientprotocol/codex-acp";
  return isAbsolute(command) ? basename(command) : command;
}

function argumentIdentity(argument) {
  if (argument === CODEX_EXECUTABLE) return "codex-cli";
  if (argument === ADAPTER) return "@agentclientprotocol/codex-acp";
  return isAbsolute(argument) ? basename(argument) : argument;
}

function commandEvidence(command, commandArgs, replacements) {
  const result = spawnSync(command, commandArgs, {
    encoding: "utf8",
    env: { ...process.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  return scrub({
    command: commandIdentity(command),
    args: commandArgs.map(argumentIdentity),
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  }, replacements);
}

function versionFrom(output, pattern, label) {
  const match = `${output.stdout}\n${output.stderr}`.match(pattern);
  if (!match) throw new Error(`VERSION_DISCOVERY_FAILED: ${label}`);
  return match[1];
}

function hostProvenance() {
  return {
    platform: platform(),
    release: release(),
    version: version(),
    arch: arch(),
  };
}

function processTreeAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(process.platform === "win32" ? pid : -pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw error;
  }
}

function signalProcessTree(child, signal) {
  if (!child?.pid) return { sent: false, error: "missing ACP child pid" };
  try {
    if (process.platform === "win32") {
      execFileSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
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
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise(value);
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

function activeHandlesWithListeners() {
  return process._getActiveHandles()
    .filter((handle) => handle?.listening === true)
    .map((handle) => handle.constructor?.name ?? "unknown");
}

class AcpClient {
  constructor({ executable, cwd, replacements, launch }) {
    this.executable = executable;
    this.cwd = cwd;
    this.replacements = replacements;
    this.launch = launch;
    this.records = [];
    this.stderr = [];
    this.pending = new Map();
    this.nextId = 1;
    this.buffer = "";
    this.child = undefined;
    this.childExit = undefined;
    this.cleanup = undefined;
    this.sessionId = undefined;
  }

  start() {
    this.child = spawn(this.launch.command, this.launch.args, {
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
      this.childExit = { code, signal, at: now() };
      this.rejectPending(new Error(`ACP child exited (${code ?? "null"}, ${signal ?? "none"})`));
    });
    return this;
  }

  writeMessage(message) {
    if (!this.child || this.child.exitCode !== null) throw new Error("ACP child is not running");
    this.records.push({ at: now(), direction: "out", message });
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  onStdout(chunk) {
    this.buffer += chunk;
    while (true) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) return;
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
        this.respondToClientRequest(message);
        continue;
      }
      if (message.id === undefined) continue;
      const pending = this.pending.get(message.id);
      if (!pending) continue;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(`${message.error.code}: ${message.error.message}`));
      else pending.resolve(message.result);
    }
  }

  respondToClientRequest(message) {
    if (message.method === "session/request_permission") {
      const option = message.params?.options?.find((candidate) =>
        candidate.kind === "allow_once" || candidate.kind === "allow_always");
      const result = option
        ? { outcome: { outcome: "selected", optionId: option.optionId } }
        : { outcome: { outcome: "cancelled" } };
      this.writeMessage({ jsonrpc: "2.0", id: message.id, result });
      return;
    }
    this.writeMessage({
      jsonrpc: "2.0",
      id: message.id,
      error: { code: -32601, message: "client method not implemented by spike" },
    });
  }

  rejectPending(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  request(method, params) {
    if (!this.child || this.child.exitCode !== null) return Promise.reject(new Error("ACP child is not running"));
    const id = this.nextId++;
    const request = { jsonrpc: "2.0", id, method, params };
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method}`));
      }, TIMEOUT_MS);
      this.pending.set(id, { resolve: resolvePromise, reject, timer });
      try {
        this.writeMessage(request);
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  notify(method, params) {
    this.writeMessage({ jsonrpc: "2.0", method, params });
  }

  async waitFor(predicate, timeout = 20_000) {
    const started = Date.now();
    while (Date.now() - started < timeout) {
      const found = this.records.find(predicate);
      if (found) return found;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
    }
    throw new Error("TIMING_PROOF_FAILED: no in-flight ACP update before injection");
  }

  outputText() {
    return this.records
      .filter((record) => record.direction === "in" && record.message?.method === "session/update")
      .filter((record) => record.message.params?.sessionId === this.sessionId)
      .map((record) => record.message.params?.update)
      .filter((update) => update?.sessionUpdate === "agent_message_chunk")
      .map((update) => update.content?.text ?? "")
      .join("");
  }

  async stop() {
    if (!this.child) return;
    const pid = this.child.pid;
    const cleanup = {
      pid,
      mode: process.platform === "win32" ? "taskkill-tree" : "detached-process-group",
      childExited: this.child.exitCode !== null,
      termRequested: false,
      killRequested: false,
      processTreeExited: false,
    };
    try {
      if (this.child.exitCode === null) {
        this.child.stdin.end();
        cleanup.childExited = await waitForChildExit(this.child, 1_000);
      }
      if (processTreeAlive(pid)) {
        cleanup.termRequested = signalProcessTree(this.child, "SIGTERM");
        cleanup.childExited = await waitForChildExit(this.child, 1_000);
      }
      if (processTreeAlive(pid)) {
        cleanup.killRequested = signalProcessTree(this.child, "SIGKILL");
        cleanup.childExited = await waitForChildExit(this.child, 1_000);
      }
      cleanup.processTreeExited = await waitForProcessTreeExit(pid, 2_000);
    } catch (error) {
      cleanup.error = String(error.stack ?? error);
    }
    this.cleanup = cleanup;
  }

  transcript() {
    return `${this.records.map((record) => JSON.stringify(scrub(record, this.replacements))).join("\n")}\n`;
  }
}

function outputIncludes(text, marker) {
  return text.includes(marker);
}

async function writeReport(artifacts, assertions, configIntegrity) {
  const native = assertions.capabilities?.nativeSteerAdvertised;
  const report = `---
title: "T4 Codex Mid-Turn Delivery Spike"
tags: [weave, t4, spike, codex, acp, delivery]
status: active
created: 2026-08-17
---

# T4 — Codex mid-turn delivery spike

Executed ${assertions.run.startedAt}. The runner is bound to \`${assertions.run.runnerGitSha}\` on T8 base \`${BASE_T8_SHA}\`.

## Environment

- Node: \`${assertions.run.node}\`; required exact pin: \`${REQUIRED_NODE}\`
- Codex CLI: \`${assertions.run.codexVersion ?? "unknown"}\`
- Codex ACP adapter: \`${assertions.run.adapterVersion ?? "unknown"}\`
- Authentication status: \`${assertions.run.authenticatedStatus ?? "not captured"}\`
- Model: \`${assertions.run.model ?? "not captured"}\`; provider: \`${assertions.run.provider ?? "not captured"}\`
- HOME inherited: \`${assertions.criteria.noHomeOverride ? "true" : "false"}\`; host: \`${assertions.environment.host.platform} ${assertions.environment.host.release} (${assertions.environment.host.arch})\`

## Capability decision

The live ACP \`initialize\` response is the source of truth. Native steering is used only when initialize-level \`_meta.steering.supported === true\`; otherwise the runner cancels the active turn and sends exactly one merged prompt containing the complete original task and injected event. This run recorded native support as \`${native ?? "unknown"}\` and selected \`${assertions.delivery?.path ?? "no delivery path"}\`.

## Results

| Criterion | Result |
|---|---|
| In-flight timing before original completion | ${assertions.delivery?.injectionBeforeOriginalCompletion ? "PASS" : "NEGATIVE"} |
| Original-task marker retained | ${assertions.delivery?.finalContainsOriginal ? "PASS" : "NEGATIVE"} |
| Injected-event marker incorporated | ${assertions.delivery?.finalContainsEvent ? "PASS" : "NEGATIVE"} |
| Mid-turn delivery overall | ${assertions.criteria.midTurnDelivery ? "PASS" : "NEGATIVE"} |
| Typed config diff entirely allowlisted | ${configIntegrity?.checks?.changedPathsInsideJournalAllowlist ? "PASS" : "FAIL"} |
| ACP adapter process tree exited | ${assertions.criteria.noResidualChildProcesses ? "PASS" : "FAIL"} |
| Residual listener handles | ${assertions.cleanup?.listenerHandles?.length === 0 ? "PASS" : "FAIL"} |
| Exact Node pin | ${assertions.criteria.nodePinExact ? "PASS" : "FAIL"} |

The runner does not create, update, or delete a global Codex fixture and does not set \`HOME\`, \`CODEX_HOME\`, or \`CLAUDE_CONFIG_DIR\`. The checked-in allowlist is \`scripts/t4-codex-journal-allowlist.json\`; no allowlist entries are derived from this run.

## Artifacts

- \`environment.json\`, \`commands.json\`, \`capabilities.ndjson\`, \`delivery.ndjson\`, and redacted stderr
- \`config-before.json\`, \`config-after.json\`, and \`config-integrity.json\`
- \`assertions.json\` and this report

## Artifact integrity

The \`artifactsSha256\` value in \`assertions.json\` is reproducible by sorting the artifact filenames bytewise, excluding \`assertions.json\`, then hashing each filename followed by one NUL byte and that file's raw bytes in order.
`;
  await writeFile(join(artifacts, "REPORT.md"), report, "utf8");
}

async function main(artifacts) {
  await mkdir(artifacts, { recursive: true });
  const runRoot = await mkdtemp(join(tmpdir(), `weave-t4-codex-${process.pid}-`));
  const fixture = join(runRoot, "fixture");
  await mkdir(fixture, { recursive: true });
  const replacements = [
    ...(HOME ? [[HOME, "<HOME>"]] : []),
    [runRoot, "<RUN_ROOT>"],
    [ROOT, "<WORKTREE>"],
    ...(CODEX_HOME ? [[CODEX_HOME, "<CODEX_HOME>"]] : []),
    [CODEX_EXECUTABLE, "<CODEX_CLI>"],
    [ADAPTER, "<CODEX_ACP>"],
    [process.execPath, "<NODE>"],
  ];
  const allowlist = JSON.parse(await readFile(ALLOWLIST_PATH, "utf8"));
  const runnerGitSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  const environment = {
    homeInherited: Boolean(HOME) && process.env.HOME === HOME,
    homeOverrideRequested: false,
    forbiddenOverridePresent: {
      CODEX_HOME: Object.hasOwn(process.env, "CODEX_HOME"),
      CLAUDE_CONFIG_DIR: Object.hasOwn(process.env, "CLAUDE_CONFIG_DIR"),
    },
    host: hostProvenance(),
  };
  const assertions = {
    run: {
      startedAt: now(),
      endedAt: undefined,
      runnerGitSha,
      baseGitSha: BASE_T8_SHA,
      node: process.version,
      nodePinned: REQUIRED_NODE,
      codexTool: "codex-cli",
      adapterTool: "@agentclientprotocol/codex-acp",
    },
    supportedRange: {
      codexCli: allowlist.codexCli,
      acpAdapter: allowlist.acpAdapter,
    },
    environment,
    capabilities: undefined,
    delivery: undefined,
    cleanup: {},
    criteria: {
      nodePinExact: process.version === REQUIRED_NODE,
      noHomeOverride: environment.homeInherited && !environment.homeOverrideRequested &&
        !Object.values(environment.forbiddenOverridePresent).some(Boolean),
      midTurnDelivery: false,
      authenticatedTurn: false,
      configChangedPathsAllowlisted: false,
      noResidualChildProcesses: false,
      privacySafeEvidence: false,
      artifactAggregateBound: false,
    },
    negatives: {},
  };
  let client;
  let configBefore;
  let configAfter;
  let configIntegrity;

  try {
    assertRunnerEnvironment({ node: process.version, environment });
    configBefore = await configManifest(CODEX_HOME);
    const commands = {
      codexVersion: commandEvidence(CODEX_EXECUTABLE, ["--version"], replacements),
      adapterVersion: commandEvidence(
        ADAPTER_LAUNCH.command,
        [...ADAPTER_LAUNCH.args, "--version"],
        replacements,
      ),
      loginStatus: commandEvidence(CODEX_EXECUTABLE, ["login", "status"], replacements),
    };
    await writeJson(join(artifacts, "commands.json"), commands);
    assertions.run.codexVersion = versionFrom(commands.codexVersion, /codex-cli\s+(\d+\.\d+\.\d+)/, "Codex CLI");
    assertions.run.adapterVersion = versionFrom(commands.adapterVersion, /codex-acp\s+(\d+\.\d+\.\d+)/, "Codex ACP");
    assertions.run.authenticatedStatus = `${commands.loginStatus.stdout}${commands.loginStatus.stderr}`.trim();
    const loginAuthenticated = commands.loginStatus.status === 0 && /logged in/i.test(assertions.run.authenticatedStatus);
    let unsupportedVersionError;
    try {
      assertSupportedHarnessVersions({
        codexCli: "0.0.0",
        acpAdapter: "0.0.0",
        ranges: { codexCli: allowlist.codexCli, acpAdapter: allowlist.acpAdapter },
      });
    } catch (error) {
      unsupportedVersionError = String(error.message ?? error);
    }
    assertions.negatives.unsupportedHarnessVersion = {
      rejected: unsupportedVersionError?.includes("UNSUPPORTED_HARNESS_VERSION") === true,
      error: unsupportedVersionError ?? null,
      fallback: "none",
      childProcessStarted: false,
    };
    assert.equal(assertions.negatives.unsupportedHarnessVersion.rejected, true);
    assertSupportedHarnessVersions({
      codexCli: assertions.run.codexVersion,
      acpAdapter: assertions.run.adapterVersion,
      ranges: { codexCli: allowlist.codexCli, acpAdapter: allowlist.acpAdapter },
    });

    client = new AcpClient({ executable: ADAPTER, cwd: fixture, replacements, launch: ADAPTER_LAUNCH }).start();
    const initialize = await client.request("initialize", {
      protocolVersion: 1,
      clientCapabilities: {},
      clientInfo: { name: "weave-t4-codex-delivery", version: "0.1.0" },
    });
    const authStatus = await client.request("authentication/status", {});
    const session = await client.request("session/new", { cwd: fixture, mcpServers: [] });
    client.sessionId = session.sessionId;
    const modelOption = session.configOptions?.find((option) => option.category === "model");
    assertions.run.model = session.models?.currentModelId ?? modelOption?.currentValue ?? "unknown";
    assertions.run.provider = authStatus?.type ?? "codex-acp";
    const native = nativeSteerAdvertised(initialize);
    assertions.capabilities = scrub({ initialize, authenticationStatus: authStatus, session }, replacements);
    assertions.capabilities.nativeSteerAdvertised = native;
    assertions.capabilities.steeringMethod = native ? "_session/steering" : null;
    await writeFile(join(artifacts, "capabilities.ndjson"), client.transcript(), "utf8");

    let originalSettled = false;
    const originalStartedAt = now();
    const originalStartedMicros = microsNow();
    const originalPromise = client.request("session/prompt", {
      sessionId: session.sessionId,
      prompt: [{ type: "text", text: ORIGINAL_TASK }],
    }).finally(() => {
      originalSettled = true;
    });
    await client.waitFor((record) => {
      const update = record.message?.params?.update;
      return record.direction === "in" && record.message?.method === "session/update" &&
        record.message.params?.sessionId === session.sessionId &&
        ["tool_call", "tool_call_update", "agent_thought_chunk", "agent_message_chunk"].includes(update?.sessionUpdate);
    });
    assert.equal(originalSettled, false, "original turn completed before injection");
    const injectedAt = now();
    const injectedMicros = microsNow();
    let steeringResult;
    let fallbackReason;
    let originalResult;
    let path;
    if (native) {
      try {
        steeringResult = await client.request("_session/steering", {
          sessionId: session.sessionId,
          prompt: [{ type: "text", text: INJECTED_EVENT }],
          _meta: { steering: { idleBehavior: "promptRequired" } },
        });
      } catch (error) {
        steeringResult = { error: String(error.message ?? error) };
        fallbackReason = "native-request-error";
      }
      path = selectDeliveryPath({ nativeAdvertised: native, outcome: steeringResult?.outcome });
      if (path === "native") {
        originalResult = await originalPromise;
      }
    }
    if (path !== "native") {
      fallbackReason ??= native ? "native-outcome-not-accepted" : "native-capability-not-advertised";
      client.notify("session/cancel", { sessionId: session.sessionId });
      let originalError;
      try {
        originalResult = await originalPromise;
      } catch (error) {
        originalError = String(error.message ?? error);
      }
      steeringResult = await client.request("session/prompt", {
        sessionId: session.sessionId,
        prompt: [{ type: "text", text: mergedPrompt(ORIGINAL_TASK, INJECTED_EVENT) }],
      });
      if (originalError) originalResult = { error: originalError };
    }
    const originalCompletedAt = now();
    const originalCompletedMicros = microsNow();
    const finalText = client.outputText();
    assertions.delivery = {
      path,
      originalTask: ORIGINAL_TASK,
      injectedEvent: INJECTED_EVENT,
      originalStartedAt,
      originalStartedMicros,
      injectedAt,
      injectedMicros,
      originalCompletedAt,
      originalCompletedMicros,
      originalStopReason: originalResult?.stopReason ?? null,
      steeringResult: scrub(steeringResult, replacements),
      fallbackReason: fallbackReason ?? null,
      finalOutput: scrub(finalText, replacements),
      injectionBeforeOriginalCompletion: BigInt(injectedMicros) < BigInt(originalCompletedMicros),
      finalContainsOriginal: outputIncludes(finalText, ORIGINAL_MARKER),
      finalContainsEvent: outputIncludes(finalText, EVENT_MARKER),
      fallbackPrompt: path === "fallback-cancel-merged-reprompt" ? mergedPrompt(ORIGINAL_TASK, INJECTED_EVENT) : null,
    };
    assertions.criteria.authenticatedTurn = loginAuthenticated && !originalResult?.error &&
      (Boolean(originalResult?.stopReason) || Boolean(steeringResult?.stopReason) || Boolean(steeringResult?.outcome));
    assertions.criteria.midTurnDelivery = assertions.delivery.injectionBeforeOriginalCompletion &&
      assertions.delivery.finalContainsOriginal && assertions.delivery.finalContainsEvent &&
      (path === "native" ? ["injected", "startedNewTurn"].includes(steeringResult?.outcome) : true);
    await writeFile(join(artifacts, "delivery.ndjson"), client.transcript(), "utf8");
    await writeFile(join(artifacts, "delivery.stderr.log"), scrub(client.stderr.join(""), replacements), "utf8");
  } catch (error) {
    assertions.run.error = scrub(String(error.stack ?? error), replacements);
  } finally {
    await client?.stop();
    if (client) {
      await writeFile(join(artifacts, "delivery.ndjson"), client.transcript(), "utf8");
      await writeFile(join(artifacts, "delivery.stderr.log"), scrub(client.stderr.join(""), replacements), "utf8");
    }
    assertions.cleanup = {
      childExited: !client || client.childExit !== undefined,
      childExit: client?.childExit ?? null,
      processTree: client?.cleanup ?? null,
      processTreeExited: !client || client.cleanup?.processTreeExited === true,
      listenerHandles: activeHandlesWithListeners(),
    };
    assertions.criteria.noResidualChildProcesses = assertions.cleanup.processTreeExited;
    configAfter = await configManifest(CODEX_HOME);
    if (configBefore) {
      configIntegrity = typedConfigTreeDiff(configBefore, configAfter, allowlist);
      assertions.configIntegrity = configIntegrity;
      assertions.criteria.configChangedPathsAllowlisted = configIntegrity.checks.changedPathsInsideJournalAllowlist;
      await writeJson(join(artifacts, "config-before.json"), configBefore);
      await writeJson(join(artifacts, "config-after.json"), configAfter);
      await writeJson(join(artifacts, "config-integrity.json"), configIntegrity);
    }
    assertions.run.endedAt = now();
    await writeJson(join(artifacts, "environment.json"), environmentEvidence({
      node: assertions.run.node,
      codexCli: assertions.run.codexVersion ?? "unknown",
      acpAdapter: assertions.run.adapterVersion ?? "unknown",
      host: environment.host,
      homeInherited: environment.homeInherited,
      homeOverrideRequested: environment.homeOverrideRequested,
      forbiddenOverridePresent: environment.forbiddenOverridePresent,
    }));
    await writeReport(artifacts, assertions, configIntegrity);
    try {
      await assertArtifactPrivacy(artifacts);
      assertions.criteria.privacySafeEvidence = true;
    } catch (error) {
      assertions.run.error = scrub(String(error.stack ?? error), replacements);
    }
    const entries = await artifactEntries(artifacts);
    assertions.artifactsSha256 = computeArtifactsSha256(entries);
    try {
      assertArtifactAggregateBinding({ entries, expected: assertions.artifactsSha256 });
      assertions.criteria.artifactAggregateBound = true;
    } catch (error) {
      assertions.run.error = scrub(String(error.stack ?? error), replacements);
    }
    await writeJson(join(artifacts, "assertions.json"), scrub(assertions, replacements));
    await rm(runRoot, { recursive: true, force: true });
  }

  console.log(JSON.stringify({ artifacts, assertions: scrub(assertions, replacements) }, null, 2));
  const required = [
    assertions.criteria.nodePinExact,
    assertions.criteria.noHomeOverride,
    assertions.criteria.authenticatedTurn,
    assertions.criteria.midTurnDelivery,
    assertions.criteria.configChangedPathsAllowlisted,
    assertions.criteria.noResidualChildProcesses,
    assertions.cleanup.listenerHandles?.length === 0,
    assertions.criteria.privacySafeEvidence,
    assertions.criteria.artifactAggregateBound,
  ];
  if (!required.every(Boolean)) process.exitCode = 1;
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const args = parseArgs(process.argv.slice(2));
  await main(resolveArtifactsDir(args.artifacts));
}
