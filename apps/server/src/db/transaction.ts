import type { Pool, PoolClient } from "pg";
import type { DbClient } from "./db-client.ts";

/**
 * Run `work` on a single checked-out client inside one transaction. This is the
 * only allowed way to perform multi-write mutations: node-postgres requires a
 * transaction to use one client rather than pool.query, and the migration,
 * consume-and-audit, and grant/revoke boundaries all depend on that.
 */
export async function withTransaction<T>(
  pool: Pool,
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Run `work` on a connection that already participates in a transaction if it
 * is a checked-out client, or start a fresh transaction when it is a `Pool`.
 * A command that writes an audit record alongside its mutation must run through
 * this helper so the two writes always commit or roll back together.
 */
export async function inTransaction<T>(
  client: DbClient,
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  if ("release" in client) {
    return work(client as PoolClient);
  }
  return withTransaction(client as Pool, work);
}
