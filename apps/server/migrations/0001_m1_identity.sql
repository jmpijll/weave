-- Weave M1.1 — identity and credential-tree storage.
--
-- Creates: community, person, credential, host, agent, and append-only
-- audit_event. The migration runner owns the `schema_migration` ledger and the
-- transaction-scoped advisory lock; this file only defines the application
-- schema for identity and credential ancestry so PostgreSQL is a safe source of
-- truth before product operations exist.
--
-- All mutation-bearing tables carry issuer/timestamp housekeeping except the
-- bootstrap-rooted `community` / `person` rows, whose issuer is the bootstrap
-- actor and so is not yet namable at M1.1.

-- ---------------------------------------------------------------------------
-- community
-- ---------------------------------------------------------------------------
CREATE TABLE community (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  canonical_tls_origin text        NOT NULL UNIQUE,
  name                 text        NOT NULL,
  bootstrap_complete   boolean     NOT NULL DEFAULT FALSE,
  created_at           timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- person
-- ---------------------------------------------------------------------------
CREATE TABLE person (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name text        NOT NULL,
  avatar       text,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- credential
-- ---------------------------------------------------------------------------
-- A public, revocable authenticator owned by a person. The tree position is
-- expressed by (kind, parent_credential_id):
--   * kind='human'  AND parent IS NULL  -> the portable human root
--   * kind='human'  AND parent NOT NULL -> a human device under that root
--   * kind='host'                       -> a host under its owner's root
--   * kind='agent'                      -> an agent under its recorded host
-- Enforces Pass 40/41 write-time shape via triggers.
CREATE TABLE credential (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  person_id            uuid        NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
  public_key           text        NOT NULL,
  algorithm            text        NOT NULL,
  kind                 text        NOT NULL CHECK (kind IN ('human', 'host', 'agent')),
  parent_credential_id uuid        REFERENCES credential(id) ON DELETE RESTRICT,
  created_at           timestamptz NOT NULL DEFAULT now(),
  revoked_at           timestamptz,
  revoked_reason       text,
  CONSTRAINT credential_no_self_parent CHECK (parent_credential_id IS NULL OR parent_credential_id <> id)
);

COMMENT ON COLUMN credential.kind IS
  'human|host|agent; a human with a NULL parent is the portable root, a human '
  'with a parent is a per-device credential (Pass 39/40/41).';

-- Exactly one active human root per person per server (Pass 41).
CREATE UNIQUE INDEX credential_one_active_root_per_person
  ON credential (person_id)
  WHERE kind = 'human' AND parent_credential_id IS NULL AND revoked_at IS NULL;

CREATE INDEX credential_person_idx ON credential (person_id);
CREATE INDEX credential_parent_idx ON credential (parent_credential_id);

-- A credential's (algorithm, public_key) identity is unique across the entire
-- credential lifetime, not merely among active rows: the same authenticator can
-- never be inserted for a second person, nor re-enrolled after revocation. A
-- signed-request resolver can therefore select exactly one credential for a
-- given proof regardless of revocation history (Pass 41; no ambiguous auth).
CREATE UNIQUE INDEX credential_identity_unique
  ON credential (algorithm, public_key);

-- Validate that a credential of `p_child_kind` owned by `p_child_person` may sit
-- at `p_parent_credential` in the bounded tree. Walks every ancestor so a
-- revoked ancestor (direct or higher), a cross-person chain, or an over-long /
-- cyclic chain is denied, not just the immediate parent. The immediate parent is
-- passed in as a record (never re-selected) so callers can supply the in-flight
-- `NEW` row of the credential being updated; a self-referential SELECT inside a
-- BEFORE trigger would observe the pre-update row. Depth is the number of parent
-- hops from `p_parent_credential` up to the root.
CREATE OR REPLACE FUNCTION check_credential_placement(
  p_child_kind       text,
  p_child_person     uuid,
  p_parent_credential credential
) RETURNS void AS $$
DECLARE
  cur   RECORD;
  depth integer := 0;
BEGIN
  IF p_parent_credential IS NULL THEN
    IF p_child_kind <> 'human' THEN
      RAISE EXCEPTION 'a % credential must have a parent', p_child_kind;
    END IF;
    RETURN;
  END IF;

  IF p_parent_credential.person_id <> p_child_person THEN
    RAISE EXCEPTION 'credential parent must belong to the same person (cross-person denied)';
  END IF;
  IF p_parent_credential.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'credential parent must not be revoked (revoked ancestor denied)';
  END IF;

  cur := p_parent_credential;
  LOOP
    IF depth > 2 THEN
      RAISE EXCEPTION 'credential tree exceeds bounded depth (cycle or over-long chain)';
    END IF;
    IF cur.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'revoked ancestor denied in chain above parent %', p_parent_credential.id;
    END IF;
    IF cur.parent_credential_id IS NULL THEN
      EXIT;
    END IF;
    SELECT c.* INTO STRICT cur FROM credential c WHERE c.id = cur.parent_credential_id;
    IF cur.person_id <> p_child_person THEN
      RAISE EXCEPTION 'credential ancestor must belong to the same person (cross-person denied)';
    END IF;
    depth := depth + 1;
  END LOOP;

  -- `cur` is now the root; `depth` is the number of parent hops to it.
  IF p_child_kind = 'human' OR p_child_kind = 'host' THEN
    IF depth <> 0 THEN
      IF p_child_kind = 'human' THEN
        RAISE EXCEPTION 'human device must parent only to an activation root';
      ELSE
        RAISE EXCEPTION 'host must parent only to its owner active root';
      END IF;
    END IF;
    IF cur.kind <> 'human' THEN
      RAISE EXCEPTION '% must parent only to a human root', p_child_kind;
    END IF;
  ELSIF p_child_kind = 'agent' THEN
    IF p_parent_credential.kind <> 'host' THEN
      RAISE EXCEPTION 'agent must parent only to a host credential';
    END IF;
    IF depth <> 1 THEN
      RAISE EXCEPTION 'agent must parent to exactly a host under a human root';
    END IF;
    IF cur.kind <> 'human' THEN
      RAISE EXCEPTION 'agent host must be under a human root';
    END IF;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Validate a credential's own placement in the typed acyclic tree at write
-- time (Pass 40/41): every ancestor is checked, not just the direct parent.
CREATE OR REPLACE FUNCTION enforce_credential_tree_shape() RETURNS trigger AS $$
DECLARE
  parent credential;
BEGIN
  IF NEW.parent_credential_id = NEW.id THEN
    RAISE EXCEPTION 'credential cannot parent itself';
  END IF;
  IF NEW.parent_credential_id IS NOT NULL THEN
    SELECT c.* INTO STRICT parent FROM credential c WHERE c.id = NEW.parent_credential_id;
  END IF;
  PERFORM check_credential_placement(NEW.kind, NEW.person_id, parent);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_tree_shape
  BEFORE INSERT OR UPDATE OF person_id, public_key, algorithm, kind, parent_credential_id
  ON credential
  FOR EACH ROW
  EXECUTE FUNCTION enforce_credential_tree_shape();

-- Revalidate every dependent row when a credential's structural columns change,
-- so an UPDATE can never silently break the binding that host / agent / child
-- rows already rely on. This is the write-side invariant closure for the
-- "one-way trigger" gap on `credential` updates.
CREATE OR REPLACE FUNCTION enforce_credential_dependents() RETURNS trigger AS $$
DECLARE
  host_row   RECORD;
  agent_row  RECORD;
  child      RECORD;
  host_cred  uuid;
  host_owner uuid;
BEGIN
  -- host records pointing at this credential must still agree with it.
  FOR host_row IN SELECT * FROM host WHERE credential_id = NEW.id LOOP
    IF NEW.kind <> 'host' THEN
      RAISE EXCEPTION 'host % references a non-host credential (kind changed to %)', host_row.id, NEW.kind;
    END IF;
    IF host_row.owner_person_id IS DISTINCT FROM NEW.person_id THEN
      RAISE EXCEPTION 'host % owner must match its credential owner (person changed)', host_row.id;
    END IF;
  END LOOP;

  -- agent records pointing at this credential must still agree with it.
  FOR agent_row IN SELECT * FROM agent WHERE credential_id = NEW.id LOOP
    IF NEW.kind <> 'agent' THEN
      RAISE EXCEPTION 'agent % references a non-agent credential (kind changed to %)', agent_row.id, NEW.kind;
    END IF;
    SELECT h.credential_id, h.owner_person_id INTO host_cred, host_owner
      FROM host h WHERE h.id = agent_row.host_id;
    IF NEW.parent_credential_id IS DISTINCT FROM host_cred THEN
      RAISE EXCEPTION 'agent % credential must parent to its recorded host credential (cross-host after update)', agent_row.id;
    END IF;
    IF host_owner IS DISTINCT FROM NEW.person_id THEN
      RAISE EXCEPTION 'agent % host owner must match the agent credential owner (person changed)', agent_row.id;
    END IF;
  END LOOP;

  -- child credentials parented by this credential must remain valid. Pass
  -- `NEW` (the in-flight row) as the parent so the child check observes the new
  -- values, not the pre-update row a self-referential SELECT would return.
  FOR child IN SELECT * FROM credential WHERE parent_credential_id = NEW.id LOOP
    PERFORM check_credential_placement(child.kind, child.person_id, NEW);
  END LOOP;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_dependents
  BEFORE UPDATE OF person_id, kind, parent_credential_id
  ON credential
  FOR EACH ROW
  EXECUTE FUNCTION enforce_credential_dependents();

-- ---------------------------------------------------------------------------
-- host / agent (minimal ownership records so root -> host -> agent is executable)
-- ---------------------------------------------------------------------------
CREATE TABLE host (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_person_id uuid        NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
  credential_id   uuid        NOT NULL UNIQUE REFERENCES credential(id) ON DELETE RESTRICT,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id       uuid        NOT NULL REFERENCES host(id) ON DELETE RESTRICT,
  credential_id uuid        NOT NULL UNIQUE REFERENCES credential(id) ON DELETE RESTRICT,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION enforce_host_owner_binding() RETURNS trigger AS $$
DECLARE
  cred RECORD;
BEGIN
  SELECT c.* INTO STRICT cred FROM credential c WHERE c.id = NEW.credential_id;
  IF cred.kind <> 'host' THEN
    RAISE EXCEPTION 'host credential must be a kind=host credential';
  END IF;
  IF cred.person_id <> NEW.owner_person_id THEN
    RAISE EXCEPTION 'host owner must match its credential owner';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER host_owner_binding
  BEFORE INSERT OR UPDATE OF owner_person_id, credential_id
  ON host
  FOR EACH ROW
  EXECUTE FUNCTION enforce_host_owner_binding();

CREATE OR REPLACE FUNCTION enforce_agent_host_binding() RETURNS trigger AS $$
DECLARE
  cred     RECORD;
  host_row RECORD;
BEGIN
  SELECT c.* INTO STRICT cred FROM credential c WHERE c.id = NEW.credential_id;
  IF cred.kind <> 'agent' THEN
    RAISE EXCEPTION 'agent credential must be a kind=agent credential';
  END IF;

  SELECT h.* INTO STRICT host_row FROM host h WHERE h.id = NEW.host_id;

  -- Cross-host rule: the agent credential must parent to the exact host
  -- credential recorded for its host.
  IF cred.parent_credential_id IS DISTINCT FROM host_row.credential_id THEN
    RAISE EXCEPTION 'agent credential must parent to its recorded host credential (cross-host denied)';
  END IF;
  IF host_row.owner_person_id <> cred.person_id THEN
    RAISE EXCEPTION 'agent host owner must match the agent credential owner';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_host_binding
  BEFORE INSERT OR UPDATE OF host_id, credential_id
  ON agent
  FOR EACH ROW
  EXECUTE FUNCTION enforce_agent_host_binding();

-- ---------------------------------------------------------------------------
-- audit_event (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_event (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type          text        NOT NULL,
  community_id        uuid        REFERENCES community(id) ON DELETE RESTRICT,
  actor_person_id     uuid        REFERENCES person(id) ON DELETE RESTRICT,
  actor_credential_id uuid        REFERENCES credential(id) ON DELETE RESTRICT,
  target_type         text        NOT NULL,
  target_id           text        NOT NULL,
  metadata            jsonb       NOT NULL DEFAULT '{}'::jsonb,
  correlation_id      text        NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_event_community_time ON audit_event (community_id, created_at);
CREATE INDEX audit_event_type_time ON audit_event (event_type, created_at);

CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_event is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_event_append_only
  BEFORE UPDATE OR DELETE
  ON audit_event
  FOR EACH ROW
  EXECUTE FUNCTION prevent_audit_mutation();
