/**
 * MultiDeviceFingerprint
 *
 * Pure helper that turns a device's identity public key into a human-readable
 * fingerprint used by the multi-device verification UI. The format is:
 *
 *     XXXX XXXX XXXX XXXX   (16 hex chars, uppercase, space-separated)
 *
 * The input may already be hex or it may have arrived from the server as
 * Base64; `normalizeKeyToHex` handles both. We then take the first 8 bytes
 * of BLAKE2b(key) as the fingerprint material — this is intentionally short
 * because users have to compare it visually.
 */

import { hexToBytes, hash256 } from '../SodiumCrypto';
import { normalizeKeyToHex } from '../../utils/keyEncodingConverter';

/**
 * Format 16 hex chars as `XXXX XXXX XXXX XXXX`.
 * Exposed for callers that already have a hex digest.
 */
export function formatDeviceFingerprintGroups(hex16: string): string {
  if (hex16.length !== 16) {
    throw new Error(
      `[MultiDeviceFingerprint] Expected 16-char digest, got ${hex16.length}`
    );
  }
  const upper = hex16.toUpperCase();
  return `${upper.slice(0, 4)} ${upper.slice(4, 8)} ${upper.slice(8, 12)} ${upper.slice(12, 16)}`;
}

/**
 * Compute a device's display fingerprint from its public identity key.
 * Accepts hex or Base64 input.
 */
export function computeDeviceFingerprint(publicKey: string): string {
  const publicKeyHex = normalizeKeyToHex(publicKey);
  const keyBytes = hexToBytes(publicKeyHex);
  const hashBytes = hash256(keyBytes);

  const fingerprint = Array.from(hashBytes.slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return formatDeviceFingerprintGroups(fingerprint);
}

/**
 * Compare two fingerprints, ignoring whitespace and case.
 * Returns true when they are the same fingerprint.
 */
export function fingerprintsMatch(a: string, b: string): boolean {
  const normA = a.replace(/\s+/g, '').toUpperCase();
  const normB = b.replace(/\s+/g, '').toUpperCase();
  return normA === normB;
}
