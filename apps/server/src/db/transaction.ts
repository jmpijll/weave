import type { Pool, PoolClient } from "pg";

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
