import * as SecureStore from './SecureStoreBackend';
import { blake2b } from '@noble/hashes/blake2b';
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { secureCompare } from '../SodiumCrypto';

const INTEGRITY_VERSION = 'v1';
const INTEGRITY_MAC_KEY_NAME = 'e2e_sec_integrity_key';
const MAC_KEY_BYTES = 32;

const SECURE_STORE_OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

let cachedIntegrityKey: Uint8Array | null = null;
// Concurrent first-time callers must NOT each generate-and-overwrite a fresh
// integrity key — that races and leaves data wrapped with one key and the
// MAC computed under another, making every subsequent read fail to verify.
// We coalesce concurrent first-time calls onto a single in-flight promise.
let inFlightIntegrityKey: Promise<Uint8Array> | null = null;

/**
 * Returns the device-unique integrity MAC key, generating + persisting one
 * to the OS keychain on first use. Cached in-process so subsequent reads
 * don't pay the SecureStore round-trip.
 */
export async function getIntegrityKey(): Promise<Uint8Array> {
  if (cachedIntegrityKey) return cachedIntegrityKey;
  if (inFlightIntegrityKey) return inFlightIntegrityKey;

  inFlightIntegrityKey = (async () => {
    try {
      const stored = await SecureStore.getItemAsync(INTEGRITY_MAC_KEY_NAME);
      if (stored) {
        cachedIntegrityKey = hexToBytes(stored);
        return cachedIntegrityKey;
      }
    } catch {
      console.warn('[IntegrityMAC] Failed to load integrity key, generating new one');
    }

    // Round-8 (H1): SINGLE-WRITER creation on web. The in-flight coalescing
    // above is per-JS-context only — two TABS racing first-time creation
    // each generated-and-overwrote a fresh key, leaving one tab's wrapped
    // identity verifying against the other tab's key → "SECURITY ALERT:
    // integrity verification FAILED" → identity discarded and reminted (a
    // manufactured new-device window). Only the E2EE leader tab may CREATE
    // the key; followers wait briefly for the leader's write to land and
    // re-read. Native (single context) and lockless browsers fall through
    // unchanged (the leader check is always-true there).
    try {
      const { isE2EELeader } = require('./WebLeaderElection');
      if (!isE2EELeader()) {
        for (let attempt = 0; attempt < 20; attempt++) {
          await new Promise((r) => setTimeout(r, 250));
          const stored = await SecureStore.getItemAsync(INTEGRITY_MAC_KEY_NAME).catch(() => null);
          if (stored) {
            cachedIntegrityKey = hexToBytes(stored);
            return cachedIntegrityKey;
          }
          if (isE2EELeader()) break; // promoted mid-wait — create below
        }
        // Leader never wrote within ~5s (crashed tab / no leader): fail OPEN
        // and create — identical to today's single-tab behavior.
      }
    } catch {
      /* leader module unavailable (tests/native edge) — legacy behavior */
    }

    const fresh = randomBytes(MAC_KEY_BYTES);
    await SecureStore.setItemAsync(
      INTEGRITY_MAC_KEY_NAME,
      bytesToHex(fresh),
      SECURE_STORE_OPTIONS,
    );
    cachedIntegrityKey = fresh;
    return fresh;
  })();

  try {
    return await inFlightIntegrityKey;
  } finally {
    inFlightIntegrityKey = null;
  }
}

/** Test seam — clears the in-process cache. Used by logout / explicit reset. */
export function clearCachedIntegrityKey(): void {
  cachedIntegrityKey = null;
  inFlightIntegrityKey = null;
}

/**
 * BLAKE2b keyed MAC over an arbitrary string. Returns a hex-encoded
 * 32-byte tag. The key is the device-unique integrity key from
 * `getIntegrityKey()`; callers should not pass any other key.
 */
export function computeMAC(data: string, key: Uint8Array): string {
  const dataBytes = new TextEncoder().encode(data);
  const mac = blake2b(dataBytes, { key, dkLen: MAC_KEY_BYTES });
  return bytesToHex(mac);
}

/**
 * Wraps a payload with the integrity MAC. Output format is:
 *
 *     VERSION|MAC|DATA
 *
 * The version prefix lets us evolve the wrapping scheme without
 * confusing old data for tampered data.
 */
export async function wrapWithIntegrity(data: string): Promise<string> {
  const key = await getIntegrityKey();
  const mac = computeMAC(data, key);
  return `${INTEGRITY_VERSION}|${mac}|${data}`;
}

interface UnwrapResult {
  data: string | null;
  verified: boolean;
}

/**
 * Inverts `wrapWithIntegrity`:
 *   - on a valid v1 envelope: returns `{ data, verified: true }`
 *   - on a malformed envelope: returns `{ data: null, verified: false }`
 *   - on tampered data (MAC mismatch): returns `{ data: '', verified: false }`
 *     so the caller can detect tampering separately from "bad format"
 *   - on legacy unwrapped data (no version prefix): returns
 *     `{ data: wrapped, verified: false }` so the caller can choose to
 *     use-and-upgrade instead of losing keys (D-03 fix).
 *
 * MAC comparison is constant-time to prevent timing-side-channel leakage.
 */
export async function unwrapAndVerify(wrapped: string): Promise<UnwrapResult> {
  if (!wrapped.startsWith(`${INTEGRITY_VERSION}|`)) {
    console.warn('[IntegrityMAC] Data without integrity MAC detected (legacy format) — migrating in place');
    return { data: wrapped, verified: false };
  }

  const parts = wrapped.split('|');
  if (parts.length < 3) {
    console.error('[IntegrityMAC] Invalid integrity format');
    return { data: null, verified: false };
  }

  const [, storedMac, ...dataParts] = parts;
  const data = dataParts.join('|');

  const key = await getIntegrityKey();
  const computedMac = computeMAC(data, key);

  const storedMacBytes = hexToBytes(storedMac);
  const computedMacBytes = hexToBytes(computedMac);
  if (!secureCompare(storedMacBytes, computedMacBytes)) {
    // Round-8 (H1): before declaring tampering, re-read the STORED key once —
    // the in-process cache can be stale when another tab (or an earlier
    // session) created/replaced the key after we cached ours. A genuine
    // tamper still fails against the re-read key (fail-closed preserved);
    // only the false alarm that discarded a healthy identity is healed.
    try {
      const stored = await SecureStore.getItemAsync(INTEGRITY_MAC_KEY_NAME);
      if (stored) {
        const rereadKey = hexToBytes(stored);
        if (!secureCompare(rereadKey, key)) {
          const recomputed = computeMAC(data, rereadKey);
          if (secureCompare(hexToBytes(recomputed), storedMacBytes)) {
            cachedIntegrityKey = rereadKey; // adopt the real stored key
            console.warn('[IntegrityMAC] in-process key was stale — re-verified against the stored key');
            return { data, verified: true };
          }
        }
      }
    } catch {
      /* re-read is best-effort; fall through to the tamper verdict */
    }
    console.error('[IntegrityMAC] SECURITY ALERT: Integrity MAC verification FAILED! Data may have been tampered.');
    return { data: '', verified: false };
  }

  return { data, verified: true };
}
