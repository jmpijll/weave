-- Weave M3.1 — enrollment-schema + host status/capability additions.
--
-- Builds on M1.1/M1.2/M1.3/M2.1. Lands the `pairing_token` replay-guard table
-- and the four additive `host` columns (capabilities/last_seen_at/status/
-- paired_at) that the host enrollment and capability-report contract specifies
-- but that no migration creates today. These are pure schema persistence: the
-- `enroll.host` wire type is a compile-time protocol shape only (M3.1 scope),
-- and no runtime handshake, enrollment ceremony, consume, or audit write is
-- introduced here.
--
-- Pairing tokens are replay protection only, NEVER a bearer credential or trust
-- anchor (M3 contract §2, architect correction): a token is useful only inside a
-- valid owner-authorized, host-public-key-bound enrollment request, which is
-- M3.2 and deliberately not implemented now. `consumed_at` NULL = pending; a
-- consumed or expired token is inert.
--
-- The host columns capture host-level facts that drive the M3 reconnect status
-- window and capability report. `capabilities` is server-validated JSONB with a
-- safe empty default (the frozen `HostCapabilities` form `{"harnesses":[]}`, so
-- the persisted shape is always valid); `status` is constrained to the frozen
-- ready/degraded/offline set with a safe `offline` default; `paired_at` is
-- non-null with an insertion-time default (auditable enrollment time);
-- `last_seen_at` is nullable because a fresh host has never been seen until its
-- first report.
--
-- No change is made to `credential` or its legacy `public_key` constraints —
-- M3.1 freezes only the additive pairing-token and host columns.
--
-- Additive/append-only; no down migration. No protocol/package/runtime/route/
-- transport change beyond the compile-time `enroll.host` protocol type shape.

-- ---------------------------------------------------------------------------
-- pairing_token: single-use, expiring replay-guard record (M3.1 §2)
-- ---------------------------------------------------------------------------
-- The row is an issue record that the M3.2 consume completes by setting
-- `consumed_at`, advancing it from NULL (pending) to a timestamp-consumed row.
-- It is not a credential; enrollment authority comes from the
-- owner-authorized, host-public-key-bound request, never from possession of the
-- token. `host_public_key` is the key the enrollment is bound to; it is frozen
-- to strict 64-char lowercase hex (matching the M1.3.A lower-hex decision) and
-- must never be a human/agent key (a separate M3.2 request-level check).
CREATE TABLE pairing_token (
  id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  issued_by_credential_id uuid     NOT NULL REFERENCES credential(id) ON DELETE RESTRICT,
  host_public_key       text        NOT NULL,
  community_id          uuid        NOT NULL REFERENCES community(id) ON DELETE RESTRICT,
  expires_at            timestamptz NOT NULL,
  consumed_at           timestamptz,
  CONSTRAINT pairing_token_host_public_key_lower_hex
    CHECK (host_public_key ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE pairing_token IS
  'Single-use, expiring replay-guard for host enrollment. Replay protection '
  'only — never a bearer credential or trust anchor; a consumed/expired token '
  'is inert.';

COMMENT ON COLUMN pairing_token.issued_by_credential_id IS
  'The owner human/device credential authorizing the enrollment.';
COMMENT ON COLUMN pairing_token.host_public_key IS
  'Strict 64-char lowercase-hex host key the enrollment is bound to. Never a '
  'human or agent key.';
COMMENT ON COLUMN pairing_token.community_id IS
  'The community into which the host is being enrolled.';
COMMENT ON COLUMN pairing_token.expires_at IS
  'Short-lived validity; not a persistent reusable token.';
COMMENT ON COLUMN pairing_token.consumed_at IS
  'Replay guard: NULL = pending; set on consume. Consumed tokens are inert.';

-- ---------------------------------------------------------------------------
-- host: additive status / capability persistence (M3.1 §3)
-- ---------------------------------------------------------------------------
ALTER TABLE host ADD COLUMN capabilities jsonb NOT NULL DEFAULT '{"harnesses":[]}'::jsonb;
ALTER TABLE host ADD COLUMN last_seen_at  timestamptz;
ALTER TABLE host ADD COLUMN status        text NOT NULL DEFAULT 'offline'
  CHECK (status IN ('ready', 'degraded', 'offline'));
ALTER TABLE host ADD COLUMN paired_at     timestamptz NOT NULL DEFAULT now();

COMMENT ON COLUMN host.capabilities IS
  'Server-validated capability descriptor reported by the host; a safe empty '
  'HostCapabilities default ({"harnesses":[]}) so the persisted shape is always '
  'the frozen HostCapabilities form. Detected per HarnessDriver.capabilities(); '
  'never inspects credentials.';
COMMENT ON COLUMN host.last_seen_at IS
  'Nullable last host capability/status report; drives the status window.';
COMMENT ON COLUMN host.status IS
  'Frozen ready/degraded/offline host status; safe offline default (a fresh '
  'host has not reported yet).';
COMMENT ON COLUMN host.paired_at IS
  'Auditable enrollment time; non-null with an insertion-time default.';
