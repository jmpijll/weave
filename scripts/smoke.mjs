import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const runtimeApplications = ["server", "daemon"];
const clientEntry = resolve(root, "apps/client/src/index.ts");

for (const application of runtimeApplications) {
  const entry = resolve(root, "apps", application, "src/index.ts");
  const source = await readFile(entry, "utf8");
  assert.match(source, /import type .* from ["']@weave\/protocol["']/s);
  const module = await import(pathToFileURL(entry).href);
  assert.deepEqual(module.component, {
    name: application,
    protocol: "weave/v1",
  });
}

const clientSource = await readFile(clientEntry, "utf8");
assert.match(clientSource, /import type .* from ["']@weave\/protocol["']/s);
assert.match(clientSource, /export type ClientMessage/);

for (const application of runtimeApplications) {
  const fixture = resolve(root, "apps", application, "fixtures/non-erasable-enum.ts");
  const enumCheck = spawnSync(process.execPath, [fixture], { encoding: "utf8" });
  assert.notEqual(enumCheck.status, 0, `${application} must reject non-erasable enum syntax`);
  assert.match(enumCheck.stderr, /ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX/);
}

console.log("runtime imports verified: server, daemon; client type import verified");
console.log("raw server and daemon entry points reject enum syntax as expected");
