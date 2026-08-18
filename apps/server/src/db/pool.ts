import pg from "pg";

export interface DatabaseConfig {
  connectionString: string;
  max: number;
}

export function databaseUrlFromEnv(env: Record<string, string | undefined> = process.env): string | null {
  const connectionString = env.DATABASE_URL;
  return connectionString && connectionString.length > 0 ? connectionString : null;
}

export function createDatabasePool(config: DatabaseConfig): pg.Pool {
  return new pg.Pool({
    connectionString: config.connectionString,
    max: config.max,
    // Pin the search_path so every connection (including the migration client
    // and every transactional client) resolves unqualified relations against
    // `public` deterministically, never against a server-default or user
    // search_path that could change after connection.
    options: "-c search_path=public",
  });
}

export function createDatabaseConfig(connectionString: string, max = 10): DatabaseConfig {
  return { connectionString, max };
}
