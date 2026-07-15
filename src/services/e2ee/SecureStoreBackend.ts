/**
 * SecureStoreBackend — durable key/value backend for E2EE key material.
 *
 * Drop-in for the subset of `expo-secure-store` used by the E2EE storage layer
 * (`getItemAsync` / `setItemAsync` / `deleteItemAsync` + the keychain-accessible
 * constants + the options type). Import it as `* as SecureStore` in place of
 * `expo-secure-store` and existing call sites work unchanged.
 *
 * WHY THIS EXISTS — the multi-device "messages never arrive on web" root cause:
 *   `expo-secure-store` has NO persistent web implementation. On a browser it is
 *   effectively in-memory, so EVERY page reload wipes the stored E2EE identity
 *   keypair, signed pre-key, and integrity-MAC key. The startup path then sees
 *   "no keys" and GENERATES A FRESH IDENTITY on every reload. That changes the
 *   user's identity fingerprint constantly, so every peer's pinned key goes
 *   stale and the server bounces their messages as STALE_RECIPIENT_KEY /
 *   NOT_IN_SENDER_STORAGE — i.e. messages are silently lost. (The device id
 *   survived because it was already in AsyncStorage; only the secure keys
 *   churned, which is why the symptom was so confusing.)
 *
 * FIX: on web, persist to AsyncStorage (localStorage-backed, survives reloads);
 * on native, keep using the hardware-backed Keychain/Keystore via
 * `expo-secure-store` EXACTLY as before (zero behavior change on iOS/Android).
 * A browser has no hardware enclave, so durable localStorage is the correct and
 * standard tradeoff for web E2EE — and it is what makes the identity STABLE so
 * no message is ever lost to spurious key rotation.
 *
 * Keys are written under the SAME key names native uses (no prefix): the E2EE
 * key names (`e2e_sec_*`, chunk/meta suffixes, integrity-MAC key) are already
 * distinctive and cannot collide with the app's other AsyncStorage keys.
 * `SecureStoreOptions` (keychainAccessible, etc.) are native-only and ignored
 * on web.
 */

import { Platform } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Defensive: `Platform` can be momentarily undefined under some jest module
// states (RN mock not yet applied); default to the native path rather than
// throwing at module load. In a real RN/web runtime Platform is always defined,
// so this is behaviour-neutral in production.
const IS_WEB = Platform?.OS === 'web';

/** Re-exported so call sites that reference the type keep compiling. */
export type SecureStoreOptions = SecureStore.SecureStoreOptions;

/**
 * `expo-secure-store` only accepts keys matching `[A-Za-z0-9._-]` and throws
 * `Invalid key provided to SecureStore` for anything else. Some callers reuse
 * the AsyncStorage `@`-prefix convention (e.g. the channel/identity writability
 * probes `@lewo_channel_writability_probe` / `@lewo_e2ee_writability_probe`).
 * On native that threw on every read/write — which silently bricked
 * `probeChannelStorageWritable`: it always reported `writable:false`, so
 * `setupChannelAsAdmin`'s persistent-miss branch ALWAYS threw
 * `SuspiciousMissingKeyError` instead of recovering a genuinely-lost channel
 * sender key via regeneration. That left the admin unable to post to an
 * encrypted channel ("No Sender Key … Key distribution required").
 *
 * Map any out-of-charset character to `_` deterministically so the SAME logical
 * key always resolves to the SAME SecureStore slot (get/set/delete agree). This
 * is a NO-OP for every real E2EE key name (`e2e_sec_*`, `channel_e2e_*`, …)
 * which already satisfy the charset, so it cannot orphan stored data: a key
 * SecureStore would have rejected can never have persisted anything. It only
 * rescues otherwise-throwing keys such as the writability probes.
 *
 * Web is unaffected — AsyncStorage accepts `@`-prefixed keys, and rewriting
 * them would orphan already-persisted web data. So sanitization is native-only.
 */
const SECURE_STORE_KEY_OK = /^[A-Za-z0-9._-]+$/;
function toNativeKey(key: string): string {
  if (SECURE_STORE_KEY_OK.test(key)) return key;
  return key.replace(/[^A-Za-z0-9._-]/g, '_');
}

/** Keychain-accessibility constants — native-only; harmless passthrough on web. */
export const WHEN_UNLOCKED_THIS_DEVICE_ONLY = SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY;
export const AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY = SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY;

export async function getItemAsync(
  key: string,
  options?: SecureStoreOptions,
): Promise<string | null> {
  if (IS_WEB) {
    return AsyncStorage.getItem(key);
  }
  return SecureStore.getItemAsync(toNativeKey(key), options);
}

export async function setItemAsync(
  key: string,
  value: string,
  options?: SecureStoreOptions,
): Promise<void> {
  if (IS_WEB) {
    await AsyncStorage.setItem(key, value);
    return;
  }
  await SecureStore.setItemAsync(toNativeKey(key), value, options);
}

export async function deleteItemAsync(
  key: string,
  options?: SecureStoreOptions,
): Promise<void> {
  if (IS_WEB) {
    await AsyncStorage.removeItem(key);
    return;
  }
  await SecureStore.deleteItemAsync(toNativeKey(key), options);
}
