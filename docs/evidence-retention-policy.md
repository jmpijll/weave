# Public Evidence Retention Policy (M0, Option A)

**Status:** active — owner-approved 2026-08-17 (Weave register Pass 31).

## Purpose

Raw host-specific spike captures carried machine identifiers (hostname, an
absolute `/Users/…` path, a per-user `/var/folders/…` temp identifier) and, once
committed, stayed reachable from the branch even after a later-deleting commit.
This policy keeps reusable runner/contract code and a safe, schema-validated
summary in the public repository while raw host-specific captures stay
local-only and are never pushed.

## Rules

1. **Public tree shape.** Under each `evidence/<spike>/` directory exactly two
   **regular files** are permitted: `summary.json` and its generated
   `REPORT.md`. No other files, no nested directories, no symbolic links, and
   no non-regular entries. The top level `evidence/` contains only spike
   directories. Any unknown, symlinked, or non-regular entry fails closed in CI.

2. **Strict summary schema.** `summary.json` must pass
   `scripts/evidence-contract.mjs` validation, which admits only booleans,
   enumerated values, anchored semantic versions, ISO timestamps, Git SHAs and
   SHA-256 digests. There is deliberately **no free-form string field**, so host
   paths, hostnames, usernames, temp identifiers, prompts and raw environment
   content cannot be expressed. Version fields are **fully anchored**: a value
   with any arbitrary trailing payload fails. The `results` object must contain
   the **exact** fixed, reviewed key set — no unknown keys and no omissions.
   Unknown keys, unknown values, and omitted required keys fail closed.

3. **Physical/identity boundary.** Each `evidence/<spike>/` directory is bound
   to the validated `summary.spike`: the directory name must equal
   `summary.spike`, and that spike must be a registered spike.

4. **Report is generated, not authored.** `REPORT.md` is rendered
   deterministically from `summary.json` and CI regenerates and byte-compares
   it, so prose cannot drift from data. Regenerate with:
   `node scripts/evidence-report.mjs --spike <spike> --write`.

5. **Public provenance resolves.** `publicProvenance.integrationCommit` must be
   an **ancestor of HEAD** as proven from git history in CI (CI fetches the
   full history via `actions/checkout` with `fetch-depth: 0`), not merely a
   40-hex SHA.

6. **Local provenance is an equality anchor, never content.**
   `localProvenance` carries `visibility: "not-published"`, the local runner
   SHA, a capture aggregate SHA-256, and a non-sensitive logical record ID. It
   never names an absolute path, host, username, temp identifier, prompt, or
   environment field.

7. **Raw captures stay local.** Raw host-specific captures are not copied,
   redacted-and-committed, deleted, or rewritten. Their negative-result
   conclusions are preserved in the safe summary/review record instead of as
   unsafe bytes.

## Verification

`pnpm evidence` (runs `scripts/verify-evidence.mjs` then
`scripts/evidence-contract.test.mjs`) is wired into `pnpm test` and a dedicated
CI step. Regression tests cover an unexpected file, an unexpected nested
directory, a symbolic link, an unknown key, an omitted required result key, an
anchored-version bypass, an unsafe free-form value shape, a spike binding
mismatch, and a non-ancestor `integrationCommit`.

## Implementation

- `scripts/evidence-contract.mjs` — reviewed schema, strict validator, and
  deterministic report renderer (single source of truth).
- `scripts/verify-evidence.mjs` — walks `evidence/`, rejects unknown /
  symlinked / non-regular entries, binds each directory to `summary.spike`,
  validates every summary, byte-compares every `REPORT.md`, and resolves each
  `publicProvenance.integrationCommit` against git history.
- `scripts/evidence-report.mjs` — regenerates `REPORT.md` from a summary.
- `scripts/evidence-contract.test.mjs` — regression tests for the failure shapes.
- `evidence/t3-codex/summary.json` + `evidence/t3-codex/REPORT.md` — the safe
  public summary for the T3 Codex spike.
