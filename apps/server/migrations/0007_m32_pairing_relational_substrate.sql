-- Weave M3.2-I2 — pairing relational substrate (persistence only).
--
-- Turns the dormant M3.1 pairing_token replay-guard table into the selected
-- M3.2 lifecycle store: a durable immutable one-row policy registry, exact
-- bigint Unix-millisecond lifecycle times, and raw-insert integrity backstops
-- for policy derivation, E1 issuer eligibility, and immutable issuance facts.
--
-- This migration is persistence only. It authorizes no consumption: the server
-- connects as the schema-owning role, so these triggers are an integrity
-- backstop for normal application/raw-SQL paths, not proof authorization.
-- The locked proof/freshness/conditional-consume/host/audit transaction is I4.
-- Trigger error text is database-internal test evidence only and must never
-- reach a public response (I4 maps failures through the E2/S8 boundary).
--
-- Forward-only; no down migration. Never edit 0001-0006. No proof, proof hash,
-- transcript, request body, receipt, nonce, session, audit, retry, default,
-- ON CONFLICT DO NOTHING, policy-active flag, or trigger on credential/host/
-- member is introduced here. Existing non-pairing timestamptz/now() uses are
-- out of scope.

-- ---------------------------------------------------------------------------
-- Empty-table gate: the legacy timestamp columns are replaced, never converted.
-- ---------------------------------------------------------------------------
LOCK TABLE pairing_token IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pairing_token) THEN
    RAISE EXCEPTION '0007 pairing substrate refused: pairing_token is not empty; explicit data migration required';
  END IF;
END;
$$;

ALTER TABLE pairing_token
  ALTER COLUMN expires_at TYPE bigint USING NULL::bigint,
  ALTER COLUMN consumed_at TYPE bigint USING NULL::bigint;

COMMENT ON COLUMN pairing_token.expires_at IS
  'Exact derived expiry in Unix milliseconds (issued_at + policy duration). No legacy timestamp value is preserved: 0007 requires an empty table.';
COMMENT ON COLUMN pairing_token.consumed_at IS
  'Lifecycle state only: NULL = pending; one-way transition to an exact Unix-millisecond value on consume.';

-- ---------------------------------------------------------------------------
-- Missing durable facts: exact issue time and immutable policy reference.
-- ---------------------------------------------------------------------------
ALTER TABLE pairing_token
  ADD COLUMN issued_at bigint NOT NULL,
  ADD COLUMN policy_version integer NOT NULL;

COMMENT ON COLUMN pairing_token.issued_at IS
  'Exact issue time in Unix milliseconds, 0..9007199254740991. No default: the I4 issuance transaction supplies it explicitly.';
COMMENT ON COLUMN pairing_token.policy_version IS
  'Immutable reference to the sole pairing policy version. No default: the I4 issuance transaction supplies it explicitly.';

-- ---------------------------------------------------------------------------
-- Durable policy authority: the sole M3.2 pairing policy, immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE pairing_policy_registry (
  version     integer PRIMARY KEY,
  duration_ms bigint NOT NULL,
  CONSTRAINT pairing_policy_registry_version_check CHECK (version = 1),
  CONSTRAINT pairing_policy_registry_duration_check CHECK (duration_ms = 600000)
);

COMMENT ON TABLE pairing_policy_registry IS
  'Durable authority for the sole M3.2 pairing policy: version 1, 600000 ms (10 minutes). Immutable seed; rotation is a future migration and product decision.';
COMMENT ON COLUMN pairing_policy_registry.duration_ms IS
  'Authoritative 10-minute pairing duration in milliseconds. Retained so expiry derivation survives process restarts and preserves history.';

CREATE OR REPLACE FUNCTION refuse_pairing_policy_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'pairing policy registry is immutable: version % may not be %', OLD.version, TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER refuse_pairing_policy_mutation
  BEFORE UPDATE OR DELETE ON pairing_policy_registry
  FOR EACH ROW EXECUTE FUNCTION refuse_pairing_policy_mutation();

INSERT INTO pairing_policy_registry (version, duration_ms) VALUES (1, 600000);

ALTER TABLE pairing_token
  ADD CONSTRAINT pairing_token_policy_version_fk
  FOREIGN KEY (policy_version) REFERENCES pairing_policy_registry(version) ON DELETE RESTRICT;

-- ---------------------------------------------------------------------------
-- Row-local scalar invariants (range, ordering, valid consumed value).
-- ---------------------------------------------------------------------------
ALTER TABLE pairing_token
  ADD CONSTRAINT pairing_token_issued_at_range
  CHECK (issued_at >= 0 AND issued_at <= 9007199254740991),
  ADD CONSTRAINT pairing_token_expires_at_range
  CHECK (expires_at >= 0 AND expires_at <= 9007199254740991),
  ADD CONSTRAINT pairing_token_expiry_after_issue
  CHECK (expires_at > issued_at),
  ADD CONSTRAINT pairing_token_consumed_at_range
  CHECK (consumed_at IS NULL OR (consumed_at >= 0 AND consumed_at <= 9007199254740991));

-- ---------------------------------------------------------------------------
-- BEFORE INSERT backstop: policy derivation, overflow, E1 issuer eligibility.
-- Locks the policy row, then issuer/root in ascending UUID order, then the
-- active human member row last. I4 and revocation paths must reuse this order.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_pairing_token_insert() RETURNS trigger AS $$
DECLARE
  policy_duration bigint;
  device_row RECORD;
  root_row   RECORD;
  first_id   uuid;
  second_id  uuid;
  member_row RECORD;
BEGIN
  SELECT duration_ms INTO policy_duration
    FROM pairing_policy_registry WHERE version = NEW.policy_version FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'pairing issue refused: unknown policy version % (only version 1 exists)', NEW.policy_version;
  END IF;

  -- Overflow is checked before arithmetic: bigint addition raises, never wraps.
  IF NEW.issued_at > 9007199254740991 - policy_duration THEN
    RAISE EXCEPTION 'pairing issue refused: issued_at % overflows with duration %', NEW.issued_at, policy_duration;
  END IF;
  IF NEW.expires_at <> NEW.issued_at + policy_duration THEN
    RAISE EXCEPTION 'pairing issue refused: expires_at must equal issued_at + %', policy_duration;
  END IF;

  SELECT * INTO device_row FROM credential WHERE id = NEW.issued_by_credential_id;
  IF device_row.id IS NULL THEN
    RAISE EXCEPTION 'pairing issue refused: unknown issuer credential';
  END IF;
  IF device_row.kind <> 'human' OR device_row.parent_credential_id IS NULL THEN
    RAISE EXCEPTION 'pairing issue refused: issuer must be a human device, not a root, host, or agent';
  END IF;
  IF device_row.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'pairing issue refused: issuer device is revoked';
  END IF;

  SELECT * INTO root_row FROM credential WHERE id = device_row.parent_credential_id;
  IF root_row.id IS NULL THEN
    RAISE EXCEPTION 'pairing issue refused: issuer device has no stored root';
  END IF;
  IF root_row.kind <> 'human' OR root_row.parent_credential_id IS NOT NULL THEN
    RAISE EXCEPTION 'pairing issue refused: issuer device must parent directly to a human root';
  END IF;
  IF root_row.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'pairing issue refused: issuer root is revoked';
  END IF;
  IF root_row.person_id IS DISTINCT FROM device_row.person_id THEN
    RAISE EXCEPTION 'pairing issue refused: cross-person issuer chain';
  END IF;

  -- Lock issuer and root in ascending UUID order, then revalidate under lock.
  IF device_row.id < root_row.id THEN
    first_id := device_row.id; second_id := root_row.id;
  ELSE
    first_id := root_row.id; second_id := device_row.id;
  END IF;
  PERFORM 1 FROM credential WHERE id = first_id FOR UPDATE;
  PERFORM 1 FROM credential WHERE id = second_id FOR UPDATE;
  SELECT * INTO device_row FROM credential WHERE id = NEW.issued_by_credential_id;
  SELECT * INTO root_row FROM credential WHERE id = device_row.parent_credential_id;
  IF device_row.revoked_at IS NOT NULL OR root_row.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'pairing issue refused: issuer revoked under lock';
  END IF;
  IF root_row.person_id IS DISTINCT FROM device_row.person_id THEN
    RAISE EXCEPTION 'pairing issue refused: cross-person issuer chain under lock';
  END IF;

  -- Active human membership of the issuer person in the token community, locked last.
  SELECT * INTO member_row FROM member
    WHERE community_id = NEW.community_id
      AND person_id = device_row.person_id
      AND subject_kind = 'human'
      AND revoked_at IS NULL
    FOR UPDATE;
  IF member_row.id IS NULL THEN
    RAISE EXCEPTION 'pairing issue refused: no active human membership for the issuer in this community';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_pairing_token_insert
  BEFORE INSERT ON pairing_token
  FOR EACH ROW EXECUTE FUNCTION enforce_pairing_token_insert();

-- ---------------------------------------------------------------------------
-- BEFORE UPDATE backstop: issuance facts immutable; consume one-way; no reset.
-- A full no-op row rewrite is permitted; every other transition except a
-- single NULL -> valid-bigint consume is refused.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_pairing_token_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.issued_by_credential_id IS DISTINCT FROM OLD.issued_by_credential_id
     OR NEW.host_public_key IS DISTINCT FROM OLD.host_public_key
     OR NEW.community_id IS DISTINCT FROM OLD.community_id
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'pairing token issuance facts are immutable';
  END IF;
  IF NEW.consumed_at IS NOT DISTINCT FROM OLD.consumed_at THEN
    RETURN NEW;
  END IF;
  IF OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'pairing consumed state is one-way and immutable once set';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_pairing_token_update
  BEFORE UPDATE ON pairing_token
  FOR EACH ROW EXECUTE FUNCTION enforce_pairing_token_update();

-- ---------------------------------------------------------------------------
-- Token rows are never deleted.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION refuse_pairing_token_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'pairing token rows may not be deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER refuse_pairing_token_delete
  BEFORE DELETE ON pairing_token
  FOR EACH ROW EXECUTE FUNCTION refuse_pairing_token_delete();
