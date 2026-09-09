-- Weave M1.2 — membership, roles, and space-access foundation.
--
-- Builds on M1.1 identity/credential storage. Adds the single authorization
-- subject (`member`, human or agent interchangeably), the versioned M1
-- bootstrap role/permission matrix, the four-level space tree with Pass 35
-- effective-access support, `space_membership` as the only normal access grant,
-- and the separate targeted admission/space-invite lifecycle state machines.
--
-- Migration-controlled data: the three bootstrap roles and their permission
-- mappings are seeded here. They are not mutable M1 API state.
--
-- No route, HTTP, signature, recovery-runtime, client/daemon, or deployment
-- behavior is introduced. This is storage + invariants only.

-- ---------------------------------------------------------------------------
-- member — the sole authorization subject (human or agent interchangeably)
-- ---------------------------------------------------------------------------
CREATE TABLE member (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id   uuid        NOT NULL REFERENCES community(id) ON DELETE RESTRICT,
  subject_kind   text        NOT NULL CHECK (subject_kind IN ('human', 'agent')),
  person_id      uuid        REFERENCES person(id) ON DELETE RESTRICT,
  agent_id       uuid        REFERENCES agent(id) ON DELETE RESTRICT,
  revoked_at     timestamptz,
  revoked_reason text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_kind_target CHECK (
    (subject_kind = 'human' AND person_id IS NOT NULL AND agent_id IS NULL) OR
    (subject_kind = 'agent' AND agent_id IS NOT NULL AND person_id IS NULL)
  )
);

COMMENT ON TABLE member IS
  'The only authorization subject. A human or an agent member share one path; '
  'credential/member kind never implies a role or access grant.';

-- At most one active membership per (community, person) and per (community, agent).
CREATE UNIQUE INDEX member_one_active_human_per_community
  ON member (community_id, person_id)
  WHERE subject_kind = 'human' AND revoked_at IS NULL;
CREATE UNIQUE INDEX member_one_active_agent_per_community
  ON member (community_id, agent_id)
  WHERE subject_kind = 'agent' AND revoked_at IS NULL;

CREATE INDEX member_active_lookup_idx
  ON member (community_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- role / permission / role_permission — versioned M1 bootstrap matrix
-- ---------------------------------------------------------------------------
CREATE TABLE role (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text        NOT NULL UNIQUE,
  scope      text        NOT NULL CHECK (scope IN ('community', 'project')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE permission (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text        NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE role_permission (
  role_id       uuid NOT NULL REFERENCES role(id) ON DELETE RESTRICT,
  permission_id uuid NOT NULL REFERENCES permission(id) ON DELETE RESTRICT,
  PRIMARY KEY (role_id, permission_id)
);

-- Seed the confirmed, minimal M1 bootstrap matrix (migration-controlled data).
INSERT INTO role (id, name, scope) VALUES
  ('00000000-0000-4000-8000-0000000000a1', 'community_admin',  'community'),
  ('00000000-0000-4000-8000-0000000000a2', 'project_owner',    'project'),
  ('00000000-0000-4000-8000-0000000000a3', 'recovery_operator','community');

INSERT INTO permission (id, name) VALUES
  ('00000000-0000-4000-8000-0000000000b1', 'community.members.manage'),
  ('00000000-0000-4000-8000-0000000000b2', 'community.projects.create'),
  ('00000000-0000-4000-8000-0000000000b3', 'roles.assign'),
  ('00000000-0000-4000-8000-0000000000b4', 'project.spaces.manage'),
  ('00000000-0000-4000-8000-0000000000b5', 'project.access.manage'),
  ('00000000-0000-4000-8000-0000000000b6', 'project.invites.manage'),
  ('00000000-0000-4000-8000-0000000000b7', 'identity.recover');

INSERT INTO role_permission (role_id, permission_id) VALUES
  ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000b1'),
  ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000b2'),
  ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000b3'),
  ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000b4'),
  ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000b5'),
  ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000b6'),
  ('00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-0000000000b7');

-- ---------------------------------------------------------------------------
-- space — project > section > channel > thread, four levels, Pass 35 visibility
-- ---------------------------------------------------------------------------
CREATE TABLE space (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id    uuid        NOT NULL REFERENCES community(id) ON DELETE RESTRICT,
  kind            text        NOT NULL CHECK (kind IN ('project', 'section', 'channel', 'thread')),
  parent_space_id uuid        REFERENCES space(id) ON DELETE RESTRICT,
  owner_member_id uuid        REFERENCES member(id) ON DELETE RESTRICT,
  visibility      text        NOT NULL CHECK (visibility IN ('public', 'private')),
  description     text,
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT space_no_self_parent CHECK (parent_space_id IS NULL OR parent_space_id <> id),
  CONSTRAINT space_project_root_only CHECK (
    (kind = 'project' AND parent_space_id IS NULL) OR
    (kind <> 'project' AND parent_space_id IS NOT NULL)
  )
);

CREATE INDEX space_parent_idx ON space (parent_space_id);
CREATE INDEX space_community_idx ON space (community_id);

-- Enforce parent kind/depth (project > section > channel > thread; depth <= 4)
-- and reject cross-community parents.
CREATE OR REPLACE FUNCTION enforce_space_tree_shape() RETURNS trigger AS $$
DECLARE
  parent space%ROWTYPE;
BEGIN
  IF NEW.parent_space_id IS NOT NULL THEN
    SELECT * INTO STRICT parent FROM space WHERE id = NEW.parent_space_id;
    IF parent.community_id <> NEW.community_id THEN
      RAISE EXCEPTION 'space parent must be in the same community (cross-community denied)';
    END IF;
    IF NEW.kind = 'section' THEN
      IF parent.kind <> 'project' THEN
        RAISE EXCEPTION 'section must parent only to a project';
      END IF;
    ELSIF NEW.kind = 'channel' THEN
      IF parent.kind <> 'section' THEN
        RAISE EXCEPTION 'channel must parent only to a section';
      END IF;
    ELSIF NEW.kind = 'thread' THEN
      IF parent.kind <> 'channel' THEN
        RAISE EXCEPTION 'thread must parent only to a channel';
      END IF;
    ELSIF NEW.kind = 'project' THEN
      RAISE EXCEPTION 'project must be a root space (no parent)';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER space_tree_shape
  BEFORE INSERT OR UPDATE OF community_id, kind, parent_space_id
  ON space
  FOR EACH ROW
  EXECUTE FUNCTION enforce_space_tree_shape();

-- ---------------------------------------------------------------------------
-- space_membership — access, not an authority role (Pass 35)
-- ---------------------------------------------------------------------------
CREATE TABLE space_membership (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  space_id            uuid        NOT NULL REFERENCES space(id) ON DELETE RESTRICT,
  member_id           uuid        NOT NULL REFERENCES member(id) ON DELETE RESTRICT,
  grant_source        text        NOT NULL CHECK (grant_source IN ('explicit', 'invite')),
  granted_by_member_id uuid       REFERENCES member(id) ON DELETE RESTRICT,
  granted_at          timestamptz NOT NULL DEFAULT now(),
  revoked_at          timestamptz,
  revoked_reason      text
);

-- At most one active grant per (space, member); a later grant after revocation
-- is a fresh row (revoked rows are retained for audit).
CREATE UNIQUE INDEX space_membership_one_active
  ON space_membership (space_id, member_id) WHERE revoked_at IS NULL;
CREATE INDEX space_membership_member_lookup_idx
  ON space_membership (member_id) WHERE revoked_at IS NULL;

-- A grant requires an active member in the space's community.
CREATE OR REPLACE FUNCTION enforce_space_membership() RETURNS trigger AS $$
DECLARE
  member_row  member%ROWTYPE;
  space_row   space%ROWTYPE;
BEGIN
  SELECT * INTO STRICT member_row FROM member WHERE id = NEW.member_id;
  IF member_row.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'space grant requires an active member';
  END IF;
  SELECT * INTO STRICT space_row FROM space WHERE id = NEW.space_id;
  IF space_row.community_id <> member_row.community_id THEN
    RAISE EXCEPTION 'space grant must be within the member''s community (cross-community denied)';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER space_membership_checks
  BEFORE INSERT OR UPDATE OF space_id, member_id
  ON space_membership
  FOR EACH ROW
  EXECUTE FUNCTION enforce_space_membership();

-- ---------------------------------------------------------------------------
-- member_role_assignment — explicit, scoped, revocable; references member only
-- ---------------------------------------------------------------------------
CREATE TABLE member_role_assignment (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  member_id          uuid        NOT NULL REFERENCES member(id) ON DELETE RESTRICT,
  role_id            uuid        NOT NULL REFERENCES role(id) ON DELETE RESTRICT,
  scope_community_id uuid        REFERENCES community(id) ON DELETE RESTRICT,
  scope_space_id     uuid        REFERENCES space(id) ON DELETE RESTRICT,
  granted_at         timestamptz NOT NULL DEFAULT now(),
  granted_by_member_id uuid     REFERENCES member(id) ON DELETE RESTRICT,
  revoked_at         timestamptz,
  revoked_reason     text,
  CONSTRAINT role_assignment_scope_shape CHECK (
    (scope_community_id IS NOT NULL AND scope_space_id IS NULL) OR
    (scope_community_id IS NULL AND scope_space_id IS NOT NULL)
  )
);

-- One active assignment of a given role at a given scope per member.
CREATE UNIQUE INDEX role_assignment_one_active
  ON member_role_assignment (member_id, role_id, scope_community_id, scope_space_id)
  WHERE revoked_at IS NULL;

CREATE INDEX role_assignment_member_lookup_idx
  ON member_role_assignment (member_id) WHERE revoked_at IS NULL;
CREATE INDEX role_assignment_project_lookup_idx
  ON member_role_assignment (scope_space_id) WHERE revoked_at IS NULL;

-- The assignment scope must match the role's declared scope, live within the
-- member's community, and (for a project scope) target a project root.
CREATE OR REPLACE FUNCTION enforce_role_assignment_scope() RETURNS trigger AS $$
DECLARE
  role_row role%ROWTYPE;
  member_row member%ROWTYPE;
  space_row space%ROWTYPE;
BEGIN
  SELECT * INTO STRICT role_row FROM role WHERE id = NEW.role_id;
  SELECT * INTO STRICT member_row FROM member WHERE id = NEW.member_id;

  IF role_row.scope = 'community' THEN
    IF NEW.scope_community_id IS NULL OR NEW.scope_space_id IS NOT NULL THEN
      RAISE EXCEPTION 'community role % must be assigned at community scope', role_row.name;
    END IF;
    IF NEW.scope_community_id <> member_row.community_id THEN
      RAISE EXCEPTION 'role assignment must be within the member''s community (cross-community denied)';
    END IF;
  ELSE
    IF NEW.scope_space_id IS NULL OR NEW.scope_community_id IS NOT NULL THEN
      RAISE EXCEPTION 'project role % must be assigned at project scope', role_row.name;
    END IF;
    SELECT * INTO STRICT space_row FROM space WHERE id = NEW.scope_space_id;
    IF space_row.kind <> 'project' OR space_row.parent_space_id IS NOT NULL THEN
      RAISE EXCEPTION 'project-scoped role must target a project root';
    END IF;
    IF space_row.community_id <> member_row.community_id THEN
      RAISE EXCEPTION 'role assignment must be within the member''s community (cross-community denied)';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER role_assignment_scope
  BEFORE INSERT OR UPDATE OF member_id, role_id, scope_community_id, scope_space_id
  ON member_role_assignment
  FOR EACH ROW
  EXECUTE FUNCTION enforce_role_assignment_scope();

-- ---------------------------------------------------------------------------
-- community_admission_invite — targeted, expiring, accepted once, terminal
-- ---------------------------------------------------------------------------
CREATE TABLE community_admission_invite (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id        uuid        NOT NULL REFERENCES community(id) ON DELETE RESTRICT,
  target_kind         text        NOT NULL CHECK (target_kind IN ('human', 'agent')),
  target_credential_id uuid       REFERENCES credential(id) ON DELETE RESTRICT,
  target_agent_id     uuid        REFERENCES agent(id) ON DELETE RESTRICT,
  issuer_member_id    uuid        NOT NULL REFERENCES member(id) ON DELETE RESTRICT,
  state               text        NOT NULL DEFAULT 'issued' CHECK (state IN ('issued', 'accepted', 'revoked', 'expired')),
  expires_at          timestamptz NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  accepted_at         timestamptz,
  revoked_at          timestamptz,
  revoked_reason      text,
  CONSTRAINT admission_invite_target_shape CHECK (
    (target_kind = 'human' AND target_credential_id IS NOT NULL AND target_agent_id IS NULL) OR
    (target_kind = 'agent' AND target_agent_id IS NOT NULL AND target_credential_id IS NULL)
  )
);

CREATE INDEX community_admission_invite_target_idx
  ON community_admission_invite (community_id, target_kind, state);

-- A community-admission invite must target an active human root credential or
-- an existing active agent, and be issued by an active member of the community.
CREATE OR REPLACE FUNCTION enforce_community_admission_invite_target() RETURNS trigger AS $$
DECLARE
  issuer     member%ROWTYPE;
  cred       credential%ROWTYPE;
  agent_row  agent%ROWTYPE;
  agent_cred credential%ROWTYPE;
BEGIN
  SELECT * INTO STRICT issuer FROM member WHERE id = NEW.issuer_member_id;
  IF issuer.revoked_at IS NOT NULL OR issuer.community_id <> NEW.community_id THEN
    RAISE EXCEPTION 'admission invite issuer must be an active member of the community';
  END IF;

  IF NEW.target_kind = 'human' THEN
    SELECT * INTO STRICT cred FROM credential WHERE id = NEW.target_credential_id;
    IF cred.kind <> 'human' OR cred.parent_credential_id IS NOT NULL OR cred.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'human admission invite must target an active human root credential';
    END IF;
  ELSE
    SELECT * INTO STRICT agent_row FROM agent WHERE id = NEW.target_agent_id;
    SELECT * INTO STRICT agent_cred FROM credential WHERE id = agent_row.credential_id;
    IF agent_cred.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'agent admission invite must target an existing active agent';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER community_admission_invite_target_checks
  BEFORE INSERT OR UPDATE OF community_id, issuer_member_id, target_kind, target_credential_id, target_agent_id
  ON community_admission_invite
  FOR EACH ROW
  EXECUTE FUNCTION enforce_community_admission_invite_target();

-- ---------------------------------------------------------------------------
-- space_invite — targeted at an existing active member; never admits
-- ---------------------------------------------------------------------------
CREATE TABLE space_invite (
  id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id        uuid        NOT NULL REFERENCES community(id) ON DELETE RESTRICT,
  target_member_id    uuid        NOT NULL REFERENCES member(id) ON DELETE RESTRICT,
  space_id            uuid        NOT NULL REFERENCES space(id) ON DELETE RESTRICT,
  issuer_member_id    uuid        NOT NULL REFERENCES member(id) ON DELETE RESTRICT,
  state               text        NOT NULL DEFAULT 'issued' CHECK (state IN ('issued', 'accepted', 'revoked', 'expired')),
  expires_at          timestamptz NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  accepted_at         timestamptz,
  revoked_at          timestamptz,
  revoked_reason      text
);

CREATE INDEX space_invite_target_idx
  ON space_invite (target_member_id, state);

-- A space invite must target an active member of the space's community, point
-- at a project root or a private descendant (never a public non-root node), and
-- be issued by an active member of the same community.
CREATE OR REPLACE FUNCTION enforce_space_invite_target() RETURNS trigger AS $$
DECLARE
  member_row member%ROWTYPE;
  space_row  space%ROWTYPE;
  issuer_row member%ROWTYPE;
BEGIN
  SELECT * INTO STRICT member_row FROM member WHERE id = NEW.target_member_id;
  IF member_row.revoked_at IS NOT NULL OR member_row.community_id <> NEW.community_id THEN
    RAISE EXCEPTION 'space invite must target an active member of the community';
  END IF;
  SELECT * INTO STRICT space_row FROM space WHERE id = NEW.space_id;
  IF space_row.community_id <> NEW.community_id THEN
    RAISE EXCEPTION 'space invite must be within the community (cross-community denied)';
  END IF;
  IF NOT (
    (space_row.kind = 'project' AND space_row.parent_space_id IS NULL)
    OR (space_row.kind <> 'project' AND space_row.visibility = 'private')
  ) THEN
    RAISE EXCEPTION 'space invite must target a project root or a private descendant';
  END IF;
  SELECT * INTO STRICT issuer_row FROM member WHERE id = NEW.issuer_member_id;
  IF issuer_row.revoked_at IS NOT NULL OR issuer_row.community_id <> NEW.community_id THEN
    RAISE EXCEPTION 'space invite issuer must be an active member of the community';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER space_invite_target_checks
  BEFORE INSERT OR UPDATE OF target_member_id, space_id, community_id, issuer_member_id
  ON space_invite
  FOR EACH ROW
  EXECUTE FUNCTION enforce_space_invite_target();

-- ---------------------------------------------------------------------------
-- Shared invite state machine (admission + space): issued -> accepted/revoked/
-- expired are terminal; an invite cannot be accepted twice or after expiry, and
-- each terminal state carries exactly its own timestamp/reason shape:
--   * issued   -> no terminal fields (accepted_at/revoked_at/revoked_reason NULL)
--   * accepted -> only accepted_at (no revocation fields)
--   * revoked  -> revoked_at plus a non-empty revoked_reason (no accepted_at)
--   * expired  -> no accepted/revoked/reason fields (the service-layer clock
--                 check decides whether an issued row is due; the schema keeps
--                 the shape invariant only, so the now() gate stays in service
--                 code as the implementation spec assigns)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION enforce_invite_state_machine() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.state <> 'issued' THEN
      RAISE EXCEPTION 'invite is terminal (%), no further transitions', OLD.state;
    END IF;
    IF NEW.state = 'accepted' THEN
      IF NEW.accepted_at IS NULL THEN
        NEW.accepted_at := now();
      END IF;
      IF NEW.accepted_at > OLD.expires_at THEN
        RAISE EXCEPTION 'invite cannot be accepted after expiry';
      END IF;
      IF NEW.revoked_at IS NOT NULL OR NEW.revoked_reason IS NOT NULL THEN
        RAISE EXCEPTION 'accepted invite must not carry revocation fields';
      END IF;
    ELSIF NEW.state = 'revoked' THEN
      IF NEW.revoked_at IS NULL THEN
        NEW.revoked_at := now();
      END IF;
      IF NEW.revoked_reason IS NULL OR btrim(NEW.revoked_reason) = '' THEN
        RAISE EXCEPTION 'revoked invite must carry a non-empty revoke reason';
      END IF;
      IF NEW.accepted_at IS NOT NULL THEN
        RAISE EXCEPTION 'revoked invite must not carry an acceptance timestamp';
      END IF;
    ELSIF NEW.state = 'expired' THEN
      IF NEW.accepted_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revoked_reason IS NOT NULL THEN
        RAISE EXCEPTION 'expired invite must not carry terminal fields';
      END IF;
    ELSE
      RAISE EXCEPTION 'invalid target invite state %', NEW.state;
    END IF;
  ELSIF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'issued' THEN
      RAISE EXCEPTION 'invite must be created in the issued state';
    END IF;
    IF NEW.accepted_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revoked_reason IS NOT NULL THEN
      RAISE EXCEPTION 'issued invite must not carry terminal fields';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER community_admission_invite_state_machine
  BEFORE INSERT OR UPDATE OF state, accepted_at, revoked_at, revoked_reason
  ON community_admission_invite
  FOR EACH ROW
  EXECUTE FUNCTION enforce_invite_state_machine();

CREATE TRIGGER space_invite_state_machine
  BEFORE INSERT OR UPDATE OF state, accepted_at, revoked_at, revoked_reason
  ON space_invite
  FOR EACH ROW
  EXECUTE FUNCTION enforce_invite_state_machine();

-- ---------------------------------------------------------------------------
-- audit_event — extend to allow member-level authority attribution (M1.2),
-- without altering the immutable M1.1 identity audit facts/columns.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_event
  ADD COLUMN actor_member_id uuid REFERENCES member(id) ON DELETE RESTRICT;

CREATE INDEX audit_event_actor_member_idx ON audit_event (actor_member_id, created_at);
