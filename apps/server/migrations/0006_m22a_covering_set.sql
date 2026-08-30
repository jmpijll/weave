-- Weave M2.2a — covering-set hardening (SNAP-1).
--
-- Makes authorization snapshots honest: every currently mutable
-- authorization input either bumps a snapshot epoch or is structurally
-- immutable. Additive/append-only; no down migration.
--
-- C1: space_membership DELETE is the only membership mutation that would
-- otherwise remove a grant without an epoch signal; all other tables are
-- already RESTRICT-protected and the absent-member fixture requires member
-- DELETE to remain valid, so only this table's DELETE is refused.
-- C2/C4: widen space/member epoch predicates so re-parent/re-point
-- mutations invalidate the snapshot. The moved row's epoch bumps; the
-- future guard re-derives the full ancestor set on mismatch (set-vs-value).
-- C3/C5: host/credential/agent bindings become write-once (IS DISTINCT FROM);
-- a real change raises, a no-op (same value) does not. Credential
-- revoked_at remains the only mutable resolver credential field and is
-- already epoch-bumped. No rotation (algorithm/public_key) in this lane;
-- that needs a separate contract and is deliberately excluded.

-- ---------------------------------------------------------------------------
-- C1: prevent DELETE on space_membership
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION prevent_space_membership_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'space_membership rows may not be deleted (use revoked_at)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER prevent_space_membership_delete
  BEFORE DELETE ON space_membership
  FOR EACH ROW EXECUTE FUNCTION prevent_space_membership_delete();

-- ---------------------------------------------------------------------------
-- C2: widen space epoch to visibility, archived_at, parent_space_id, kind, community_id
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_space_epoch_bump() RETURNS trigger AS $$
BEGIN
  IF NEW.visibility IS DISTINCT FROM OLD.visibility
     OR NEW.archived_at IS DISTINCT FROM OLD.archived_at
     OR NEW.parent_space_id IS DISTINCT FROM OLD.parent_space_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.community_id IS DISTINCT FROM OLD.community_id THEN
    NEW.epoch := OLD.epoch + 1;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS space_epoch_bump ON space;
CREATE TRIGGER space_epoch_bump
  BEFORE UPDATE OF visibility, archived_at, parent_space_id, kind, community_id
  ON space FOR EACH ROW EXECUTE FUNCTION enforce_space_epoch_bump();

-- ---------------------------------------------------------------------------
-- C4: widen member epoch to revoked_at, person_id, agent_id, subject_kind, community_id
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_member_epoch_bump() RETURNS trigger AS $$
BEGIN
  IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
     OR NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
     OR NEW.subject_kind IS DISTINCT FROM OLD.subject_kind
     OR NEW.community_id IS DISTINCT FROM OLD.community_id THEN
    NEW.epoch := OLD.epoch + 1;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS member_epoch_bump ON member;
CREATE TRIGGER member_epoch_bump
  BEFORE UPDATE OF revoked_at, person_id, agent_id, subject_kind, community_id
  ON member FOR EACH ROW EXECUTE FUNCTION enforce_member_epoch_bump();

-- ---------------------------------------------------------------------------
-- C3: host write-once (credential_id, owner_person_id)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_host_immutable_binding() RETURNS trigger AS $$
BEGIN
  IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.owner_person_id IS DISTINCT FROM OLD.owner_person_id THEN
    RAISE EXCEPTION 'host binding is write-once (credential_id, owner_person_id)';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER host_immutable_binding
  BEFORE UPDATE OF credential_id, owner_person_id
  ON host FOR EACH ROW EXECUTE FUNCTION enforce_host_immutable_binding();

-- ---------------------------------------------------------------------------
-- C5a/c: credential write-once (person_id, kind, parent_credential_id)
-- Runs after credential_dependents alphabetically (credential_immutable_structure > credential_dependents).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_credential_immutable_structure() RETURNS trigger AS $$
BEGIN
  IF NEW.person_id IS DISTINCT FROM OLD.person_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.parent_credential_id IS DISTINCT FROM OLD.parent_credential_id THEN
    RAISE EXCEPTION 'credential binding is write-once (person_id, kind, parent_credential_id)';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_immutable_structure
  BEFORE UPDATE OF person_id, kind, parent_credential_id
  ON credential FOR EACH ROW EXECUTE FUNCTION enforce_credential_immutable_structure();

-- ---------------------------------------------------------------------------
-- C5b: agent write-once (host_id, credential_id)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_agent_immutable_binding() RETURNS trigger AS $$
BEGIN
  IF NEW.host_id IS DISTINCT FROM OLD.host_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id THEN
    RAISE EXCEPTION 'agent binding is write-once (host_id, credential_id)';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_immutable_binding
  BEFORE UPDATE OF host_id, credential_id
  ON agent FOR EACH ROW EXECUTE FUNCTION enforce_agent_immutable_binding();
