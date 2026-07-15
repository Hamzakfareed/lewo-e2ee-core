/**
 * C1 — device cross-signing (ghost-device defense).
 *
 * A user's PRIMARY device Ed25519-signs each secondary device's identity +
 * signing keys. Before the send fan-out encrypts a message copy to a non-primary
 * device, it verifies this signature against the peer's primary signing key — so
 * a malicious/compelled server that injects an extra device row cannot receive
 * keys (it cannot forge the primary's signature).
 *
 * The signature covers a domain-separated BLAKE2b digest of the device's stable
 * identity so it cannot be replayed onto a different device/user. The server only
 * stores/serves the signature; this module is the sole source of truth for how it
 * is produced and checked, so signer and verifier never diverge.
 */
import { ed25519Sign, ed25519Verify, hash256, bytesToHex, hexToBytes } from '../SodiumCrypto';

const DOMAIN = 'lewo-device-xsig-v1';
const SEP = 0x1f; // unit separator between fields — prevents concatenation ambiguity

/**
 * Canonical digest a primary signs over a secondary device's identity.
 * BLAKE2b-256( domain ⊐ userId ⊐ deviceId ⊐ identityKey ⊐ signingPublicKey ),
 * where ⊐ is a 0x1f separator.
 */
export function buildDeviceCrossSignPayload(
  userId: string,
  deviceId: string,
  identityKeyHex: string,
  signingPublicKeyHex: string,
): Uint8Array {
  const enc = new TextEncoder();
  const fields = [DOMAIN, userId, deviceId, identityKeyHex, signingPublicKeyHex].map((f) =>
    enc.encode(f),
  );
  const total = fields.reduce((n, f) => n + f.length, 0) + (fields.length - 1);
  const buf = new Uint8Array(total);
  let off = 0;
  fields.forEach((f, i) => {
    if (i > 0) buf[off++] = SEP;
    buf.set(f, off);
    off += f.length;
  });
  return hash256(buf);
}

/**
 * Produce a hex cross-signature. `primarySigningPrivateKeyHex` is the primary
 * device's Ed25519 signing private key (32-byte seed or 64-byte seed+pub).
 */
export function signDeviceCrossSignature(
  primarySigningPrivateKeyHex: string,
  userId: string,
  deviceId: string,
  identityKeyHex: string,
  signingPublicKeyHex: string,
): string {
  const payload = buildDeviceCrossSignPayload(userId, deviceId, identityKeyHex, signingPublicKeyHex);
  return bytesToHex(ed25519Sign(payload, hexToBytes(primarySigningPrivateKeyHex)));
}

/**
 * Verify a device's cross-signature against the peer's PRIMARY signing key.
 * Returns false (never throws) on any malformed input so the caller can treat a
 * bad signature exactly like a missing one.
 */
export function verifyDeviceCrossSignature(
  primarySigningPublicKeyHex: string,
  crossSignatureHex: string,
  userId: string,
  deviceId: string,
  identityKeyHex: string,
  signingPublicKeyHex: string,
): boolean {
  try {
    if (!primarySigningPublicKeyHex || !crossSignatureHex) return false;
    const payload = buildDeviceCrossSignPayload(userId, deviceId, identityKeyHex, signingPublicKeyHex);
    return ed25519Verify(payload, hexToBytes(crossSignatureHex), hexToBytes(primarySigningPublicKeyHex));
  } catch {
    return false;
  }
}
