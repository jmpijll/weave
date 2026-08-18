import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";

export class MigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MigrationError";
  }
}

/** the application-scoped advisory lock key that serialises concurrent starts */
export const MIGRATION_ADVISORY_LOCK_KEY = 0x7765617665;

const MIGRATIONS_DIR = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "migrations",
);

export interface PendingMigration {
  version: number;
  filename: string;
  checksum: string;
  sql: string;
}

export interface MigrationResult {
  /** versions applied by this run */
  applied: number[];
  /** count of migrations already recorded before this run */
  skipped: number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function loadMigrationFiles(migrationsDir: string): Promise<PendingMigration[]> {
  const entries = await readdir(migrationsDir);
  const files: PendingMigration[] = [];
  for (const filename of entries) {
    const match = /^(\d+)_.+\.sql$/.exec(filename);
    if (!match) continue;
    const sql = await readFile(join(migrationsDir, filename), "utf8");
    files.push({ version: Number(match[1]), filename, checksum: sha256(sql), sql });
  }
  files.sort((a, b) => a.version - b.version);
  return files;
}

async function ensureLedger(client: PoolClient): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS public.schema_migration (
      version    integer     PRIMARY KEY,
      checksum   text        NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
}

export interface RunMigrationsOptions {
  migrationsDir?: string;
  advisoryLockKey?: number;
}

/**
 * Apply every pending forward-only migration in one transaction taken under a
 * transaction-scoped advisory lock. The history check and every pending
 * migration commit or roll back together. Refuses an unknown applied version
 * (a future schema this build cannot migrate) and a checksum change on an
 * already-applied migration. Never removes a migration.
 */
export async function runMigrations(
  pool: Pool,
  options: RunMigrationsOptions = {},
): Promise<MigrationResult> {
  const migrationsDir = options.migrationsDir ?? MIGRATIONS_DIR;
  const lockKey = options.advisoryLockKey ?? MIGRATION_ADVISORY_LOCK_KEY;
  const files = await loadMigrationFiles(migrationsDir);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock($1)", [lockKey]);
    await ensureLedger(client);

    const appliedRows = await client.query<{ version: number; checksum: string }>(
      "SELECT version, checksum FROM public.schema_migration ORDER BY version",
    );
    const applied = new Map<number, string>();
    for (const row of appliedRows.rows) {
      applied.set(Number(row.version), String(row.checksum));
    }

    const byVersion = new Map<number, PendingMigration>();
    for (const file of files) byVersion.set(file.version, file);

    // Fail closed on future or changed history before applying anything new.
    for (const [version, checksum] of applied) {
      const file = byVersion.get(version);
      if (!file) {
        throw new MigrationError(
          `schema is ahead of this build: applied migration ${version} is not in the known migration set`,
        );
      }
      if (file.checksum !== checksum) {
        throw new MigrationError(
          `migration history changed: applied migration ${version} checksum differs from its file`,
        );
      }
    }

    const appliedNow: number[] = [];
    for (const file of files) {
      if (applied.has(file.version)) continue;
      await client.query(file.sql);
      await client.query(
        "INSERT INTO public.schema_migration (version, checksum) VALUES ($1, $2)",
        [file.version, file.checksum],
      );
      appliedNow.push(file.version);
    }

    await client.query("COMMIT");
    return { applied: appliedNow, skipped: applied.size };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
