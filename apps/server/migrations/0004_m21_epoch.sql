-- Weave M2.1 — database-enforced delivery epochs.
--
-- Builds on M1.1/M1.2/M1.3.1-M1.3.3. Adds one monotonic `epoch bigint NOT NULL
-- DEFAULT 1` counter to each authorization-bearing entity the M2 delivery
-- snapshot depends on (`credential`, `member`, `space`, `space_membership`) and
-- a database-trigger bump discipline scoped to the authorization columns that
-- actually gate delivery access.
--
-- Why triggers, not commands: R1 (credential revoke) and R2 (member revoke) are
-- reachable only by raw SQL today (no domain command exists), and this schema
-- already enforces every direct authorization rule as a trigger. A trigger
-- bump is the only mechanism that survives a raw authorization write, closing
-- the bump-site-omission invalidation risk the M2 decision names first.
--
-- The member counter is the delivery snapshot's membership-set invalidator: a
-- space-membership grant creates a row with no epoch in an already-captured
-- snapshot, so the grant also bumps the one entity every snapshot contains —
-- the subject member. The M2.2 guard detects the mismatch and re-evaluates the
-- full current access set on the next protected delivery (already-frozen
-- stale-snapshot refresh, not a new route). A raw membership reassignment
-- (re-pointing a row's space_id or member_id) moves access between members, so
-- the trigger bumps every affected member exactly once, not just the one named
-- in the write.
--
-- Scoping: `member_role_assignment` and both invite tables gate management
-- authority (re-checked per request by hasPermission), not the delivery access
-- snapshot — they are outside the delivery epoch set.
--
-- No audit is written inside any trigger. Auditing stays at authenticated
-- command boundaries, so the trigger backstop never invents an actor,
-- correlation, or audit vocabulary. A future production credential/member
-- revoke command must add its explicitly selected typed audit event in the
-- same transaction; creating that command or vocabulary is out of M2.1.
--
-- Additive/append-only; no down migration — a live rollback requires a
-- separately authorized backup/restore operation. No protocol/package/
-- client/daemon/route/transport change.
--
-- The M2 delivery send gate, guard, downgrade/close, and sweep are M2.2/M2.3.

-- ---------------------------------------------------------------------------
-- epoch counters, one per authorization-bearing entity
-- ---------------------------------------------------------------------------
ALTER TABLE credential      ADD COLUMN epoch bigint NOT NULL DEFAULT 1;
ALTER TABLE member          ADD COLUMN epoch bigint NOT NULL DEFAULT 1;
ALTER TABLE space           ADD COLUMN epoch bigint NOT NULL DEFAULT 1;
ALTER TABLE space_membership ADD COLUMN epoch bigint NOT NULL DEFAULT 1;

COMMENT ON COLUMN credential.epoch IS
  'Monotonic version of this credential''s delivery-authorization state. '
  'Bumped by trigger on a real revoked_at transition (R1); a revoked ancestor '
  'suppresses descendants at the read boundary via the M1.3.3 walk.';

COMMENT ON COLUMN member.epoch IS
  'Monotonic membership-set snapshot invalidator for this member. Bumped by '
  'trigger on a real revoked_at transition (R2) and on any space-membership '
  'grant/revoke for the member (R3), so a new grant row absent from an existing '
  'snapshot becomes visible to the delivery guard.';

COMMENT ON COLUMN space.epoch IS
  'Monotonic version of this space''s access-mode state. Bumped by trigger on a '
  'real visibility or archived_at change (R4).';

COMMENT ON COLUMN space_membership.epoch IS
  'Monotonic per-(member,space) scope version. DEFAULT 1 on a grant; bumped by '
  'trigger on that row''s revoked_at / space_id / member_id real change (R3, '
  'including raw reassignment and move). Co-located detail; the member epoch is '
  'the snapshot invalidator.';

-- ---------------------------------------------------------------------------
-- credential: bump on a real revoked_at transition (R1)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_credential_epoch_bump() RETURNS trigger AS $$
BEGIN
  IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    NEW.epoch := OLD.epoch + 1;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_epoch_bump
  BEFORE UPDATE OF revoked_at
  ON credential
  FOR EACH ROW
  EXECUTE FUNCTION enforce_credential_epoch_bump();

-- ---------------------------------------------------------------------------
-- member: bump on a real revoked_at transition (R2)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_member_epoch_bump() RETURNS trigger AS $$
BEGIN
  IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    NEW.epoch := OLD.epoch + 1;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER member_epoch_bump
  BEFORE UPDATE OF revoked_at
  ON member
  FOR EACH ROW
  EXECUTE FUNCTION enforce_member_epoch_bump();

-- ---------------------------------------------------------------------------
-- space: bump on a real visibility / archived_at change (R4)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_space_epoch_bump() RETURNS trigger AS $$
BEGIN
  IF NEW.visibility IS DISTINCT FROM OLD.visibility
     OR NEW.archived_at IS DISTINCT FROM OLD.archived_at THEN
    NEW.epoch := OLD.epoch + 1;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER space_epoch_bump
  BEFORE UPDATE OF visibility, archived_at
  ON space
  FOR EACH ROW
  EXECUTE FUNCTION enforce_space_epoch_bump();

-- ---------------------------------------------------------------------------
-- space_membership: bump on grant / real revoked_at, space_id, member_id change
-- (R3, including raw member reassignment and space move)
-- ---------------------------------------------------------------------------
-- The member cross-bump updates only `epoch`, so it does not touch the member
-- revoked_at column and therefore does not re-fire the member R2 trigger — no
-- recursion. The member row is the always-present snapshot root, so this makes
-- a freshly granted (or revoked, or reassigned) space visible to the delivery
-- guard.
--
-- `UPDATE OF revoked_at, space_id, member_id` extends the original revoke-only
-- trigger to raw reassignment: a row re-pointed to a new member moves delivery
-- access from the old member (who must re-evaluate — their set shrank) to the
-- new member (who must re-evaluate — their set grew). Per-row epoch advances on
-- any real change; the member epoch bump covers old AND new member on a member
-- assignment, and the one member on a space move or revoke. A no-op write
-- (re-writing an unchanged field) is not a transition and does not bump.
CREATE OR REPLACE FUNCTION enforce_space_membership_epoch_bump() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.epoch := 1;
    UPDATE member SET epoch = epoch + 1 WHERE id = NEW.member_id;
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.space_id IS DISTINCT FROM OLD.space_id
       OR NEW.member_id IS DISTINCT FROM OLD.member_id THEN
      NEW.epoch := OLD.epoch + 1;
      IF NEW.member_id IS DISTINCT FROM OLD.member_id THEN
        UPDATE member SET epoch = epoch + 1 WHERE id = OLD.member_id;
        UPDATE member SET epoch = epoch + 1 WHERE id = NEW.member_id;
      ELSE
        UPDATE member SET epoch = epoch + 1 WHERE id = NEW.member_id;
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER space_membership_epoch_bump
  BEFORE INSERT OR UPDATE OF revoked_at, space_id, member_id
  ON space_membership
  FOR EACH ROW
  EXECUTE FUNCTION enforce_space_membership_epoch_bump();
