# Pairing Assurance Boundary (D1b/I5 — ratified)

Decision record linked to Brainstorm record
`604f1708ab4f29aafa5bc969e34e29e26e906f19f8fe40b322ef17eb01c3e4b5`.
Posture: **no operational correct-host or display-integrity claim**; no
I3/client/daemon implementation work authorized.

## What enrollment checks

- Owner authorization of the consume call.
- Host-key possession for the enrolled key.
- Lifecycle and replay controls (token lifecycle, single consume, freshness
  window, audit).

## What it does not check

- It does **not** check that a scanned or displayed enrollment request
  represents the owner's intended machine.
- The server is an authenticated echo of client-supplied pairing carrier
  values, not an independent comparison source.

## Claims that must not be made

- The product must not claim "correct host", "verified host", or any
  display-integrity protection for pairing.

## Future hypotheses (not current capability)

- A future out-of-band host-key fingerprint comparison is only a hypothesis
  to evaluate. It is not current capability, does not survive producer
  compromise, and must fail closed if its reference path cannot be
  authenticated and compared.
- A producer-compromise-resilient correct-host claim requires a separately
  trusted external authority. No such authority is selected or funded.

## Retention

Raw proofs, proof-derived data, tokens, and request bodies stay out of new
sources and all observability/persistence sinks, consistent with the existing
zero-retention policy. Existing server authorization remains authoritative.
