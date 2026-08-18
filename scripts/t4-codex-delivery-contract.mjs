import { createHash } from "node:crypto";

const REQUIRED_NODE = "v24.12.0";
const ABSOLUTE_PATH_FRAGMENT = /(?:^|[\s"'=])\/(?:[^\/\s"'<>]+\/)+[^\/\s"'<>]+|(?:^|[\s"'=])[A-Za-z]:[\\/][^\s"'<>]+/;

function parseVersion(version, label) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(version));
  if (!match) throw new Error(`UNSUPPORTED_HARNESS_VERSION: ${label}@${version}`);
  return match.slice(1).map(Number);
}

function compareVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

function versionInRange(version, range, label) {
  const parsed = parseVersion(version, label);
  const minimum = parseVersion(range.minInclusive, `${label}.minInclusive`);
  const maximum = parseVersion(range.maxExclusive, `${label}.maxExclusive`);
  return compareVersions(parsed, minimum) >= 0 && compareVersions(parsed, maximum) < 0;
}

export function assertSupportedHarnessVersions({ codexCli, acpAdapter, ranges }) {
  if (!versionInRange(codexCli, ranges.codexCli, "codex-cli")) {
    throw new Error(`UNSUPPORTED_HARNESS_VERSION: codex-cli@${codexCli}; no fallback`);
  }
  if (!versionInRange(acpAdapter, ranges.acpAdapter, "codex-acp")) {
    throw new Error(`UNSUPPORTED_HARNESS_VERSION: codex-acp@${acpAdapter}; no fallback`);
  }
  return { codexCli, acpAdapter };
}

export function assertRunnerEnvironment({ node, environment }) {
  if (node !== REQUIRED_NODE) {
    throw new Error(`PINNED_NODE_REQUIRED: expected ${REQUIRED_NODE}, found ${node}`);
  }
  if (!environment.homeInherited) throw new Error("HOME must be inherited");
  if (environment.homeOverrideRequested) throw new Error("HOME override is forbidden");
  for (const [name, present] of Object.entries(environment.forbiddenOverridePresent)) {
    if (present) throw new Error(`${name} override is forbidden`);
  }
}

function containsAbsolutePath(value) {
  return value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value) || ABSOLUTE_PATH_FRAGMENT.test(value);
}

export function assertPrivacySafeEvidence(value, label = "evidence") {
  if (typeof value === "string") {
    if (containsAbsolutePath(value)) throw new Error(`PRIVACY_PATH_LEAK: ${label}`);
    return true;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertPrivacySafeEvidence(entry, `${label}[${index}]`));
    return true;
  }
  if (value && typeof value === "object") {
    Object.entries(value).forEach(([key, entry]) => assertPrivacySafeEvidence(entry, `${label}.${key}`));
  }
  return true;
}

export function computeArtifactsSha256(entries) {
  const hash = createHash("sha256");
  for (const entry of [...entries]
    .filter(({ name }) => name !== "assertions.json")
    .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
    hash.update(`${entry.name}\0`, "utf8");
    hash.update(Buffer.from(entry.bytes));
  }
  return hash.digest("hex");
}

export function assertArtifactAggregateBinding({ entries, expected }) {
  if (!/^[a-f0-9]{64}$/.test(String(expected ?? ""))) {
    throw new Error("ARTIFACT_AGGREGATE_MISSING");
  }
  const actual = computeArtifactsSha256(entries);
  if (actual !== expected) {
    throw new Error(`ARTIFACT_AGGREGATE_MISMATCH: expected ${expected}, found ${actual}`);
  }
  return actual;
}

function allowlistPrefixes(allowlist) {
  if (!Array.isArray(allowlist?.configRoots?.codexHome?.allowedPrefixes)) {
    throw new Error("INVALID_JOURNAL_ALLOWLIST: missing Codex allowedPrefixes");
  }
  return allowlist.configRoots.codexHome.allowedPrefixes;
}

export function matchAllowlist(path, allowlist) {
  const relativePath = path.replace(/^<CODEX_HOME>\/?/, "");
  return allowlistPrefixes(allowlist)
    .filter((prefix) => new RegExp(`^${prefix.replaceAll(".", "\\.").replaceAll("*", ".*")}`).test(relativePath))
    .sort((left, right) => right.length - left.length)[0] ?? null;
}

export function typedConfigTreeDiff(before, after, allowlist) {
  const paths = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  const entries = paths.flatMap((path) => {
    const oldEntry = before[path];
    const newEntry = after[path];
    if (!oldEntry) return [{ path, change: "added", before: null, after: newEntry, allowlistMatch: matchAllowlist(path, allowlist) }];
    if (!newEntry) return [{ path, change: "removed", before: oldEntry, after: null, allowlistMatch: matchAllowlist(path, allowlist) }];
    if (JSON.stringify(oldEntry) === JSON.stringify(newEntry)) return [];
    const contentChanged = oldEntry.type === "file" && newEntry.type === "file" &&
      (oldEntry.sha256 !== newEntry.sha256 || oldEntry.size !== newEntry.size || oldEntry.mtimeMs !== newEntry.mtimeMs);
    return [{
      path,
      change: contentChanged ? "content-changed" : "metadata-or-type-changed",
      before: oldEntry,
      after: newEntry,
      allowlistMatch: matchAllowlist(path, allowlist),
    }];
  });
  return {
    entries,
    checks: {
      changedPathsInsideJournalAllowlist: entries.every((entry) => Boolean(entry.allowlistMatch)),
      changedPathsOutsideJournalAllowlist: entries
        .filter((entry) => !entry.allowlistMatch)
        .map(({ path, change }) => ({ path, change })),
    },
  };
}

export function nativeSteerAdvertised(initialize) {
  return initialize?._meta?.steering?.supported === true;
}

export function selectDeliveryPath({ nativeAdvertised, outcome }) {
  return nativeAdvertised && ["injected", "startedNewTurn"].includes(outcome)
    ? "native"
    : "fallback-cancel-merged-reprompt";
}

export function mergedPrompt(originalTask, injectedEvent) {
  return `Original task (preserved verbatim):\n${originalTask}\n\nEvent that arrived while the turn was active:\n${injectedEvent}\n\nContinue the original task and incorporate the event.`;
}

export function environmentEvidence({ node, codexCli, acpAdapter, host, homeInherited, homeOverrideRequested, forbiddenOverridePresent }) {
  const { platform, release, version, arch } = host ?? {};
  const evidence = {
    node,
    nodeRequired: REQUIRED_NODE,
    codexCli,
    acpAdapter,
    toolIdentity: {
      codexCli: "codex-cli",
      acpAdapter: "@agentclientprotocol/codex-acp",
    },
    home: "<HOME>",
    homeInherited,
    homeOverrideRequested,
    forbiddenOverridePresent,
    host: { platform, release, version, arch },
  };
  assertPrivacySafeEvidence(evidence, "environment");
  return evidence;
}

export { REQUIRED_NODE };
