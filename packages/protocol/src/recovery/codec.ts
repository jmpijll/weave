/**
 * Weave M1.3.2 — canonical external Ed25519 text codec (ADR §M1.3.2).
 *
 * A raw Ed25519 public key is exactly 32 bytes and is represented externally
 * and in recovery text columns by exactly 64 lowercase ASCII hex characters
 * matching `^[0-9a-f]{64}$`. A raw Ed25519 signature is exactly 64 bytes and is
 * represented by exactly 128 lowercase ASCII hex characters matching
 * `^[0-9a-f]{128}$`. The server-issued 32-byte nonce uses the same 64-char
 * form on the wire.
 *
 * This is the single shared writer/read path for new recovery text key
 * material. It rejects every noncanonical spelling (uppercase, prefix, padding,
 * whitespace, line wrapping, alternate alphabet, wrong byte length) BEFORE
 * decoding; it must not rely on permissive `Buffer.from(value, "hex")`
 * behaviour alone. Accepted text is decoded to raw bytes before S9 construction
 * and before the transient SPKI wrapper; hex text itself is never signed.
 */

const KEY_REGEX = /^[0-9a-f]{64}$/;
const SIGNATURE_REGEX = /^[0-9a-f]{128}$/;

/** True iff `value` is exactly 64 lowercase ASCII hex chars (32 raw bytes). */
export function isLowerHexEd25519PublicKey(value: string): boolean {
  return KEY_REGEX.test(value);
}

/** True iff `value` is exactly 128 lowercase ASCII hex chars (64 raw bytes). */
export function isLowerHexEd25519Signature(value: string): boolean {
  return SIGNATURE_REGEX.test(value);
}

/**
 * Decode a 32-byte Ed25519 public key / nonce from exactly 64 lowercase hex
 * chars. Returns null for any noncanonical spelling rather than throwing, so a
 * caller can map the refusal at the boundary. Never decodes non-lowercase or
 * wrong-length text.
 */
export function decodeLowerHexEd25519Key(value: string): Uint8Array | null {
  if (!KEY_REGEX.test(value)) return null;
  const bytes = Buffer.from(value, "hex");
  if (bytes.length !== 32) return null;
  return new Uint8Array(bytes);
}

/**
 * Decode a 64-byte Ed25519 signature from exactly 128 lowercase hex chars.
 * Returns null for any noncanonical spelling rather than throwing.
 */
export function decodeLowerHexEd25519Signature(value: string): Uint8Array | null {
  if (!SIGNATURE_REGEX.test(value)) return null;
  const bytes = Buffer.from(value, "hex");
  if (bytes.length !== 64) return null;
  return new Uint8Array(bytes);
}

/** Encode 32 raw bytes as exactly 64 lowercase hex chars (inverse of decode). */
export function encodeLowerHexEd25519Key(raw: Uint8Array): string {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  return Buffer.from(raw).toString("hex");
}

/** Encode 64 raw bytes as exactly 128 lowercase hex chars (inverse of decode). */
export function encodeLowerHexEd25519Signature(raw: Uint8Array): string {
  if (raw.length !== 64) {
    throw new Error(`Ed25519 signature must be 64 bytes, got ${raw.length}`);
  }
  return Buffer.from(raw).toString("hex");
}
