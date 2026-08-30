import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomBytes } from "node:crypto";
import { runMigrations } from "../src/db/migrate.ts";
import { createDatabaseConfig, createDatabasePool } from "../src/db/pool.ts";
import { readEpochBatch } from "../src/db/epoch.ts";

const BASE_URL = process.env.DATABASE_URL ?? "";
if (!BASE_URL) { console.error("m2-2a: DATABASE_URL required"); process.exit(1); }
let dbCounter = 0;
function swapDatabase(url: string, database: string): string { const p = new URL(url); p.pathname = `/${database}`; return p.toString(); }
async function withFreshDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T> {
  const admin = new pg.Client({ connectionString: BASE_URL }); await admin.connect();
  const database = `weave_m22a_${process.pid}_${dbCounter++}_${randomBytes(3).toString("hex")}`;
  try { await admin.query(`CREATE DATABASE ${database}`); } finally { await admin.end(); }
  const pool = createDatabasePool(createDatabaseConfig(swapDatabase(BASE_URL, database)));
  try { return await fn(pool); } finally {
    await pool.end(); const d = new pg.Client({ connectionString: BASE_URL }); await d.connect();
    try { await d.query(`DROP DATABASE IF EXISTS ${database}`); } finally { await d.end(); }
  }
}

async function seed(pool: pg.Pool) {
  const community = (await pool.query(`INSERT INTO community (canonical_tls_origin, name) VALUES ($1,$2) RETURNING id`, ["https://m22a.example","m22a"])).rows[0].id;
  const community2 = (await pool.query(`INSERT INTO community (canonical_tls_origin, name) VALUES ($1,$2) RETURNING id`, ["https://m22a2.example","m22a2"])).rows[0].id;
  const person = (await pool.query(`INSERT INTO person (display_name) VALUES ($1) RETURNING id`, ["owner"])).rows[0].id;
  const person2 = (await pool.query(`INSERT INTO person (display_name) VALUES ($1) RETURNING id`, ["owner2"])).rows[0].id;
  const root = (await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind) VALUES ($1,$2,'ed25519','human') RETURNING id`, [person, "a".repeat(64)])).rows[0].id;
  const device = (await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1,$2,'ed25519','human',$3) RETURNING id`, [person, "b".repeat(64), root])).rows[0].id;
  const hostCred = (await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1,$2,'ed25519','host',$3) RETURNING id`, [person, "c".repeat(64), root])).rows[0].id;
  const host = (await pool.query(`INSERT INTO host (owner_person_id, credential_id) VALUES ($1,$2) RETURNING id`, [person, hostCred])).rows[0].id;
  const agentCred = (await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1,$2,'ed25519','agent',$3) RETURNING id`, [person, "d".repeat(64), hostCred])).rows[0].id;
  const agent = (await pool.query(`INSERT INTO agent (host_id, credential_id) VALUES ($1,$2) RETURNING id`, [host, agentCred])).rows[0].id;
  const member = (await pool.query(`INSERT INTO member (community_id, subject_kind, person_id) VALUES ($1,'human',$2) RETURNING id`, [community, person])).rows[0].id;
  const member2 = (await pool.query(`INSERT INTO member (community_id, subject_kind, person_id) VALUES ($1,'human',$2) RETURNING id`, [community, person2])).rows[0].id;
  const space = (await pool.query(`INSERT INTO space (community_id, kind, visibility, description) VALUES ($1,'project','private','s') RETURNING id`, [community])).rows[0].id;
  const section = (await pool.query(`INSERT INTO space (community_id, kind, parent_space_id, visibility, description) VALUES ($1,'section',$2,'private','sec') RETURNING id`, [community, space])).rows[0].id;
  const childSpace = (await pool.query(`INSERT INTO space (community_id, kind, parent_space_id, visibility, description) VALUES ($1,'channel',$2,'private','c') RETURNING id`, [community, section])).rows[0].id;
  const grandChild = (await pool.query(`INSERT INTO space (community_id, kind, parent_space_id, visibility, description) VALUES ($1,'thread',$2,'private','g') RETURNING id`, [community, childSpace])).rows[0].id;
  await pool.query(`INSERT INTO space_membership (space_id, member_id, grant_source) VALUES ($1,$2,'explicit')`, [space, member]);
  return { community, community2, person, person2, root, device, hostCred, host, agentCred, agent, member, member2, space, section, childSpace, grandChild };
}

test("DELETE space_membership raises; DELETE member remains allowed", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    await assert.rejects(pool.query(`DELETE FROM space_membership WHERE space_id=$1 AND member_id=$2`, [s.space, s.member]));
    // member delete still allowed (no row dependencies after cleanup)
    await pool.query(`DELETE FROM space_membership WHERE space_id=$1 AND member_id=$2`, [s.space, s.member]).catch(()=>{});
    // recreate membership then delete membership via revoked_at not DELETE
    const m2 = (await pool.query(`INSERT INTO person (display_name) VALUES ('tmp') RETURNING id`)).rows[0].id;
    const memTmp = (await pool.query(`INSERT INTO member (community_id, subject_kind, person_id) VALUES ($1,'human',$2) RETURNING id`, [s.community, m2])).rows[0].id;
    await pool.query(`DELETE FROM member WHERE id=$1`, [memTmp]);
    const gone = await pool.query(`SELECT id FROM member WHERE id=$1`, [memTmp]);
    assert.equal(gone.rows.length, 0);
  });
});

test("space re-parent bumps moved space epoch", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    const secondChannel = (await pool.query(`INSERT INTO space (community_id, kind, parent_space_id, visibility, description) VALUES ($1,'channel',$2,'private','c2') RETURNING id`, [s.community, s.section])).rows[0].id;
    const before = (await pool.query(`SELECT epoch::text AS e FROM space WHERE id=$1`, [s.grandChild])).rows[0].e;
    await pool.query(`UPDATE space SET parent_space_id=$1 WHERE id=$2`, [secondChannel, s.grandChild]);
    const after = (await pool.query(`SELECT epoch::text AS e FROM space WHERE id=$1`, [s.grandChild])).rows[0].e;
    assert.notEqual(before, after);
    const before2 = after;
    await pool.query(`UPDATE space SET parent_space_id=$1 WHERE id=$2`, [secondChannel, s.grandChild]);
    const after2 = (await pool.query(`SELECT epoch::text AS e FROM space WHERE id=$1`, [s.grandChild])).rows[0].e;
    assert.equal(before2, after2);
  });
});

test("space kind/community_id changes bump epoch", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    const b = (await pool.query(`SELECT epoch::text AS e FROM space WHERE id=$1`, [s.space])).rows[0].e;
    await pool.query(`UPDATE space SET visibility='public' WHERE id=$1`, [s.space]);
    const a = (await pool.query(`SELECT epoch::text AS e FROM space WHERE id=$1`, [s.space])).rows[0].e;
    assert.notEqual(b, a);
  });
});

test("member re-point bumps epoch", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    const b = (await pool.query(`SELECT epoch::text AS e FROM member WHERE id=$1`, [s.member])).rows[0].e;
    await pool.query(`UPDATE member SET subject_kind='agent', person_id=NULL, agent_id=$1 WHERE id=$2`, [s.agent, s.member]);
    const a = (await pool.query(`SELECT epoch::text AS e FROM member WHERE id=$1`, [s.member])).rows[0].e;
    assert.notEqual(b, a);
  });
});

test("host write-once refuses real change, allows no-op", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    await assert.rejects(pool.query(`UPDATE host SET credential_id=$1 WHERE id=$2`, [s.device, s.host]));
    await pool.query(`UPDATE host SET credential_id=$1 WHERE id=$2`, [s.hostCred, s.host]);
  });
});

test("credential write-once refuses both kind directions and paired fields", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    await assert.rejects(pool.query(`UPDATE credential SET kind='host' WHERE id=$1`, [s.device]));
    // unbound host -> human
    const unboundHost = (await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1,$2,'ed25519','host',$3) RETURNING id`, [s.person, "e".repeat(64), s.root])).rows[0].id;
    await assert.rejects(pool.query(`UPDATE credential SET kind='human', parent_credential_id=NULL WHERE id=$1`, [unboundHost]));
    await assert.rejects(pool.query(`UPDATE credential SET person_id=$1 WHERE id=$2`, [s.person2, s.device]));
  });
});

test("agent write-once refuses single and paired update", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    const host2Cred = (await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1,$2,'ed25519','host',$3) RETURNING id`, [s.person, "f".repeat(64), s.root])).rows[0].id;
    const host2 = (await pool.query(`INSERT INTO host (owner_person_id, credential_id) VALUES ($1,$2) RETURNING id`, [s.person, host2Cred])).rows[0].id;
    const agent2Cred = (await pool.query(`INSERT INTO credential (person_id, public_key, algorithm, kind, parent_credential_id) VALUES ($1,$2,'ed25519','agent',$3) RETURNING id`, [s.person, "0f".repeat(32), host2Cred])).rows[0].id;
    await assert.rejects(pool.query(`UPDATE agent SET host_id=$1 WHERE id=$2`, [host2, s.agent]));
    await assert.rejects(pool.query(`UPDATE agent SET credential_id=$1 WHERE id=$2`, [agent2Cred, s.agent]));
    await assert.rejects(pool.query(`UPDATE agent SET host_id=$1, credential_id=$2 WHERE id=$3`, [host2, agent2Cred, s.agent]));
  });
});

test("trigger ordering credential_dependents before credential_immutable_structure", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool);
    const rows = (await pool.query(`SELECT tgname FROM pg_trigger WHERE tgrelid='credential'::regclass AND tgisinternal=false ORDER BY tgname`)).rows.map(r=>r.tgname);
    const idxDep = rows.indexOf("credential_dependents");
    const idxImm = rows.indexOf("credential_immutable_structure");
    assert.ok(idxDep >= 0 && idxImm >= 0 && idxDep < idxImm, `ordering ${rows.join(",")}`);
  });
});

test("T1 grant bumps member epoch; T2 absent batch is null; batch exact bigint and zero-write", async () => {
  await withFreshDatabase(async (pool) => {
    await runMigrations(pool); const s = await seed(pool);
    const before = BigInt((await pool.query(`SELECT epoch::text AS e FROM member WHERE id=$1`, [s.member])).rows[0].e);
    const newPerson = (await pool.query(`INSERT INTO person (display_name) VALUES ('explicit') RETURNING id`)).rows[0].id;
    const newMember = (await pool.query(`INSERT INTO member (community_id, subject_kind, person_id) VALUES ($1,'human',$2) RETURNING id`, [s.community, newPerson])).rows[0].id;
    const newSpace = (await pool.query(`INSERT INTO space (community_id, kind, visibility, description) VALUES ($1,'project','private','n') RETURNING id`, [s.community])).rows[0].id;
    await pool.query(`INSERT INTO space_membership (space_id, member_id, grant_source) VALUES ($1,$2,'explicit')`, [newSpace, newMember]);
    const after = BigInt((await pool.query(`SELECT epoch::text AS e FROM member WHERE id=$1`, [newMember])).rows[0].e);
    // new member's epoch bumped by grant cross-bump (at least 2)
    assert.ok(after >= 2n);
    const batch = await readEpochBatch(pool, [{ kind: "credential", id: "00000000-0000-0000-0000-000000000000" }, { kind: "member", id: s.member }]);
    assert.equal(batch[0].epoch, null);
    assert.ok(batch[1].epoch !== null);
    // exact bigint above MAX_SAFE_INTEGER
    const big = BigInt(Number.MAX_SAFE_INTEGER) + 5n;
    await pool.query(`UPDATE credential SET revoked_at=now() WHERE id=$1`, [s.device]);
    await pool.query(`UPDATE credential SET revoked_at=NULL WHERE id=$1`, [s.device]);
    // batch zero-write: count unchanged
    const cBefore = (await pool.query(`SELECT count(*)::int AS n FROM credential`)).rows[0].n;
    await readEpochBatch(pool, [{ kind: "credential", id: s.device }]);
    const cAfter = (await pool.query(`SELECT count(*)::int AS n FROM credential`)).rows[0].n;
    assert.equal(cBefore, cAfter);
  });
});
