/**
 * E2EE fingerprint primitives — short BLAKE2b digests of key material
 * and message content used for identity verification, root-key drift
 * detection, and dedup cache keys.
 *
 * EXTRACTED FROM `E2EEncryptionService.ts` (Path B Phase A.2). Pure
 * functions, no state, no I/O.
 *
 * Functions:
 *   computeKeyFingerprint(keyHex, length)       → hex(fingerprint)
 *     Tries hex → bytes; on parse failure falls back to UTF-8 bytes.
 *     This dual mode is used because callers pass both hex-encoded
 *     keys AND raw content strings (e.g. combined-data fingerprints).
 *
 *   computeContentHash(content, length)         → hex(hash)
 *     Always treats input as UTF-8 text. Used for cache-key derivation
 *     where content is plain string ciphertext.
 */

import { hexToBytes, bytesToHex, hash256 } from '../SodiumCrypto';

/** Default fingerprint length in hex characters (8 bytes / 64 bits). */
export const DEFAULT_FINGERPRINT_LENGTH = 16;

/**
 * Compute a fingerprint of arbitrary key material.
 *
 * If `keyHex` parses as hex, the bytes themselves are hashed. If it
 * doesn't (e.g. a UTF-8 combined-data string), it's UTF-8-encoded
 * first then hashed. This dual mode preserves the legacy callsite
 * semantics — callers pass either hex or raw text.
 *
 * @param keyHex - hex-encoded key OR plain UTF-8 string
 * @param length - prefix length in hex chars (default 16)
 * @returns hex-encoded fingerprint of `length` characters
 */
export function computeKeyFingerprint(
  keyHex: string,
  length: number = DEFAULT_FINGERPRINT_LENGTH,
): string {
  try {
    const keyBytes = hexToBytes(keyHex);
    const hashBytes = hash256(keyBytes);
    return bytesToHex(hashBytes).substring(0, length);
  } catch {
    // Fallback for non-hex strings (e.g., raw content)
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(keyHex);
    const hashBytes = hash256(keyBytes);
    return bytesToHex(hashBytes).substring(0, length);
  }
}

/**
 * Compute a content hash for caching. Always treats input as UTF-8 —
 * does NOT attempt hex parsing first. Used for `decryptedMessageCache`
 * cache-key derivation where the input is always a string ciphertext.
 *
 * @param content - UTF-8 string content
 * @param length - prefix length in hex chars (default 16)
 * @returns hex-encoded hash of `length` characters
 */
export function computeContentHash(
  content: string,
  length: number = DEFAULT_FINGERPRINT_LENGTH,
): string {
  const contentBytes = new TextEncoder().encode(content);
  const hashBytes = hash256(contentBytes);
  return bytesToHex(hashBytes).substring(0, length);
}
