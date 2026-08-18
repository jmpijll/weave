import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const applications = ["server", "daemon", "client"];

for (const application of applications) {
  const packagePath = resolve(root, "apps", application, "package.json");
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  assert.equal(
    packageJson.dependencies?.["@weave/protocol"],
    "workspace:*",
    `${application} must depend on the shared protocol workspace package`,
  );
}

for (const rawPackage of [
  "packages/protocol",
  "apps/server",
  "apps/daemon",
]) {
  const tsconfigPath = resolve(root, rawPackage, "tsconfig.json");
  const tsconfig = JSON.parse(await readFile(tsconfigPath, "utf8"));
  assert.equal(
    tsconfig.compilerOptions?.erasableSyntaxOnly,
    true,
    `${rawPackage} must reject non-erasable TypeScript syntax`,
  );
}

console.log("workspace protocol imports verified: server, daemon, client");
