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
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_tls_origin text       NOT NULL UNIQUE,
    name                text        NOT NULL,
    bootstrap_complete  boolean     NOT NULL DEFAULT FALSE,
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- person
-- ---------------------------------------------------------------------------
CREATE TABLE person (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name   text        NOT NULL,
    avatar         text,
    created_at     timestamptz NOT NULL DEFAULT now()
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
-- Enforces Pass 40/41 write-time shape via a trigger.
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
CREATE INDEX credential_lookup_idx ON credential (public_key, algorithm);

-- Validate the typed acyclic tree at write time (Pass 40/41).
CREATE OR REPLACE FUNCTION enforce_credential_tree_shape() RETURNS trigger AS $$
DECLARE
    parent_cred RECORD;
BEGIN
    IF NEW.parent_credential_id IS NOT NULL AND NEW.parent_credential_id = NEW.id THEN
        RAISE EXCEPTION 'credential cannot parent itself';
    END IF;

    IF NEW.parent_credential_id IS NULL THEN
        -- Root only for human; a host or agent always needs a parent.
        IF NEW.kind <> 'human' THEN
            RAISE EXCEPTION 'a % credential must have a parent', NEW.kind;
        END IF;
        RETURN NEW;
    END IF;

    SELECT c.* INTO STRICT parent_cred FROM credential c WHERE c.id = NEW.parent_credential_id;

    IF parent_cred.person_id <> NEW.person_id THEN
        RAISE EXCEPTION 'credential parent must belong to the same person (cross-person denied)';
    END IF;
    IF parent_cred.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'credential parent must not be revoked (revoked ancestor denied)';
    END IF;

    IF NEW.kind = 'human' THEN
        -- A human device parents only to the same person's active root.
        IF parent_cred.kind <> 'human' OR parent_cred.parent_credential_id IS NOT NULL THEN
            RAISE EXCEPTION 'human device must parent only to the same person activation root';
        END IF;
    ELSIF NEW.kind = 'host' THEN
        -- A host parents only to its owner's active root.
        IF parent_cred.kind <> 'human' OR parent_cred.parent_credential_id IS NOT NULL THEN
            RAISE EXCEPTION 'host must parent only to its owner active root';
        END IF;
    ELSIF NEW.kind = 'agent' THEN
        -- An agent parents only to a host credential (the recorded host binding
        -- is enforced by the agent trigger for the cross-host rule).
        IF parent_cred.kind <> 'host' THEN
            RAISE EXCEPTION 'agent must parent only to a host credential';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credential_tree_shape
    BEFORE INSERT OR UPDATE OF person_id, public_key, algorithm, kind, parent_credential_id
    ON credential
    FOR EACH ROW
    EXECUTE FUNCTION enforce_credential_tree_shape();

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
    cred RECORD;
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
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type         text        NOT NULL,
    community_id       uuid        REFERENCES community(id) ON DELETE RESTRICT,
    actor_person_id    uuid        REFERENCES person(id) ON DELETE RESTRICT,
    actor_credential_id uuid       REFERENCES credential(id) ON DELETE RESTRICT,
    target_type        text        NOT NULL,
    target_id          text        NOT NULL,
    metadata           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    correlation_id     text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now()
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
