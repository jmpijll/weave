-- Weave M1.3.1 — recovery verifier and challenge schema with persisted v1
-- version/protocol metadata.
--
-- Builds on M1.1 identity/credential storage and M1.2 membership/access. Adds
-- the two recovery tables the M1.3.A production credential protocol needs,
-- normalized to production conventions (not copied from the test harness):
--
--   * version/scheme/algorithm/environment metadata persisted on BOTH the
--     verifier and the issued challenge, so a proof can be validated against
--     the stored rows (fail-closed on disagreement) rather than against
--     current defaults. The fixed `weave-recovery` v1 format label is a
--     protocol constant, NOT a per-row field.
--   * exactly one active verifier per (person, community).
--   * each challenge is bound to the matching (verifier, person, community)
--     tuple so it can never be presented against a different verifier or a
--     different subject scope.
--   * production conventions: public keys as `text` (same representation as
--     `credential.public_key`), timestamp lifecycle fields
--     (`created_at` / `revoked_at` / `consumed_at`) instead of harness
--     booleans, and fixed-size 32-byte nonce storage (`bytea`, length-checked).
--
-- The v1 migration pins the fixed version/algorithm values and the four
-- permitted environment codes. A later protocol version requires a new
-- migration before it can be stored.
--
-- No table stores a phrase, entropy, seed, private key, root signature,
-- recovery proof, or a refusal-code registry. Refusal codes live in the
-- protocol/application boundary (S8), never as a PostgreSQL table.
--
-- No route, HTTP, signed-envelope, recovery-completion, UI, or deployment
-- behavior is introduced. This is storage + invariants only. Append-only: no
-- down migration; a live rollback requires a separately authorized
-- backup/restore operation.

-- ---------------------------------------------------------------------------
-- recovery_verifier — a public verifier registered per (person, community)
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_verifier (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  person_id         uuid        NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
  community_id      uuid        NOT NULL REFERENCES community(id) ON DELETE RESTRICT,
  public_key        text        NOT NULL,
  algorithm         text        NOT NULL DEFAULT 'ed25519' CHECK (algorithm = 'ed25519'),
  algorithm_code    integer     NOT NULL DEFAULT 1 CHECK (algorithm_code = 1),
  protocol_version  integer     NOT NULL DEFAULT 1 CHECK (protocol_version = 1),
  scheme_version    integer     NOT NULL DEFAULT 1 CHECK (scheme_version = 1),
  environment_code  integer     NOT NULL CHECK (environment_code IN (1, 2, 3, 4)),
  created_at        timestamptz NOT NULL DEFAULT now(),
  revoked_at        timestamptz,
  revoked_reason    text
);

COMMENT ON TABLE recovery_verifier IS
  'A public recovery verifier registered per (person, community). The v1 '
  'format label is a protocol constant; the row-varying protocol/scheme/'
  'algorithm/environment values are persisted so a proof is validated against '
  'the stored row, never against current defaults. No secret material is '
  'stored here (public verifier key only).';

-- At most one ACTIVE verifier per (person, community); a later verifier after
-- revocation is a fresh row (revoked rows are retained for audit). This mirrors
-- the one-active-credential / one-active-membership convention.
CREATE UNIQUE INDEX recovery_verifier_one_active_per_person_community
  ON recovery_verifier (person_id, community_id)
  WHERE revoked_at IS NULL;

CREATE INDEX recovery_verifier_person_idx ON recovery_verifier (person_id);
CREATE INDEX recovery_verifier_community_idx ON recovery_verifier (community_id);

-- A composite unique key on (id, person_id, community_id) is the target of the
-- challenge's composite foreign key, so the binding is composite on the server
-- side rather than a single id reference that could drift from its scope.
CREATE UNIQUE INDEX recovery_verifier_identity_tuple_idx
  ON recovery_verifier (id, person_id, community_id);

-- ---------------------------------------------------------------------------
-- recovery_challenge — a single-use, fully bound proof challenge (S9)
-- ---------------------------------------------------------------------------
CREATE TABLE recovery_challenge (
  id                        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Composite foreign key to the matching verifier: the challenge is bound to
  -- the (verifier, person, community) tuple, so its subject scope can never
  -- disagree with the verifier it is presented against.
  verifier_id               uuid        NOT NULL,
  person_id                 uuid        NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
  community_id              uuid        NOT NULL REFERENCES community(id) ON DELETE RESTRICT,
  canonical_tls_origin      text        NOT NULL,
  nonce                     bytea       NOT NULL CHECK (octet_length(nonce) = 32),
  intended_device_public_key text       NOT NULL,
  algorithm                 text        NOT NULL DEFAULT 'ed25519' CHECK (algorithm = 'ed25519'),
  algorithm_code            integer     NOT NULL DEFAULT 1 CHECK (algorithm_code = 1),
  protocol_version          integer     NOT NULL DEFAULT 1 CHECK (protocol_version = 1),
  scheme_version            integer     NOT NULL DEFAULT 1 CHECK (scheme_version = 1),
  environment_code          integer     NOT NULL CHECK (environment_code IN (1, 2, 3, 4)),
  expires_at                timestamptz NOT NULL,
  created_at                timestamptz NOT NULL DEFAULT now(),
  consumed_at               timestamptz,
  -- The canonical TLS origin must be a nonempty wss:// endpoint whose UTF-8
  -- byte length the frozen S9 transcript can represent (u16 length-prefix,
  -- must be nonempty and at most 255 bytes). Full canonical TLS-origin parsing
  -- and normalization stay at the M1.3.2 application boundary; this is only the
  -- durable representability/scheme floor.
  CONSTRAINT recovery_challenge_canonical_tls_origin_check CHECK (
    canonical_tls_origin LIKE 'wss://%'
    AND length(canonical_tls_origin) > 6
    AND octet_length(canonical_tls_origin) <= 255
  ),
  CONSTRAINT recovery_challenge_verifier_binding
    FOREIGN KEY (verifier_id, person_id, community_id)
    REFERENCES recovery_verifier (id, person_id, community_id)
    ON DELETE RESTRICT
);

COMMENT ON TABLE recovery_challenge IS
  'A single-use recovery proof challenge bound to the exact (verifier, person, '
  'community) tuple and the canonical wss:// TLS origin, with the persisted v1 '
  'protocol/scheme/algorithm/environment values used to validate the proof. '
  'Fixed-size 32-byte nonce; expires_at / consumed_at lifecycle. No proof or '
  'secret material is stored here.';

-- Challenges are read by person/community and by verifier; the composite FK
-- already indexes the verifier tuple, so a person/community lookup index covers
-- the active-presentation path.
CREATE INDEX recovery_challenge_person_community_idx
  ON recovery_challenge (person_id, community_id);
CREATE INDEX recovery_challenge_verifier_idx
  ON recovery_challenge (verifier_id);
