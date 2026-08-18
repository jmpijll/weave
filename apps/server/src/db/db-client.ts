import type { Pool, PoolClient } from "pg";

/**
 * A connection that can run parameterized queries. Both a `Pool` (from the pool
 * factory) and a checked-out `PoolClient` (inside `withTransaction`) satisfy it.
 * Domain functions accept this so callers may run a single statement against a
 * pool or participate in a shared transaction via a client.
 */
export type DbClient = Pool | PoolClient;
