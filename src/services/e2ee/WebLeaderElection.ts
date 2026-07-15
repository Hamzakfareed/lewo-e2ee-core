/**
 * WebLeaderElection — ensures exactly one browser tab acts as the E2EE device.
 *
 * THE PROBLEM: on web, every tab of the same browser profile shares ONE
 * E2EE device identity (deviceId, identity keys, Double-Ratchet state all
 * live in shared localStorage/IndexedDB). Without coordination, two tabs
 * running as the same user + deviceId concurrently both double-ratchet the
 * same sealed messages (last-writer-wins on the
 * persisted ratchet → auth-tag failures), both answered every resend
 * request (doubling false NOT_IN_SENDER_STORAGE signals), and both ran key
 * fetch/upload (double 429 pressure). Per-device crypto is single-writer BY
 * DESIGN — exactly one tab may act as the E2EE device.
 *
 * THE FIX: Web Locks leader election. The first tab to request the
 * exclusive lock becomes the E2EE leader and holds it until the tab closes
 * (the browser auto-releases the lock — no heartbeats); waiting tabs queue
 * and the next one is promoted automatically when the leader goes away.
 * Promotion fires the registered bring-up callbacks, so the E2EE pipeline
 * (subscriptions, decryption service, key setup) starts late but completely.
 *
 * Scope: WEB ONLY. Native is always the leader (one JS context per device).
 * Fail-open: when neither the Web Locks API nor a usable environment exists,
 * the tab is treated as leader (current behavior — no regression on exotic
 * browsers; the dual-tab hazard there is unchanged from today).
 *
 * Non-leader tabs still connect the plaintext WS (typing, presence, calls,
 * plaintext chat) and render already-decrypted local history; they skip
 * E2EE subscriptions, decryption-service init, resend replies, and ALL
 * key-mutating ops (upload/rotation are gated in useEncryptionSetup).
 * Leadership handover-on-focus ("Use here") is a deliberate follow-up —
 * mid-flight pipeline teardown is where corruption lives.
 */

import { Platform } from 'react-native';

type LeaderState = 'unknown' | 'leader' | 'follower';

let state: LeaderState = 'unknown';
let requested = false;
const onLeaderCallbacks: Array<() => void> = [];

function isWeb(): boolean {
  // Platform may be undefined under some jest setups (SecureStoreBackend lesson).
  return (Platform as any)?.OS === 'web';
}

function markLeader(): void {
  if (state === 'leader') return;
  state = 'leader';
  const cbs = onLeaderCallbacks.splice(0);
  for (const cb of cbs) {
    try {
      cb();
    } catch (err) {
      if (__DEV__) console.warn('[E2EELeader] onLeader callback threw:', err);
    }
  }
}

/**
 * Idempotently start the election. On native (or web without the Locks API)
 * this resolves leadership immediately. On web, the FIRST call queues an
 * exclusive lock request: granted now (no other tab) → leader; otherwise →
 * follower until the current leader tab closes.
 */
export function ensureE2EELeadershipRequested(): void {
  if (requested) return;
  requested = true;

  if (!isWeb()) {
    markLeader();
    return;
  }

  const locks: any = (globalThis as any)?.navigator?.locks;
  if (!locks?.request) {
    // No Web Locks API → fail OPEN to current single-actor assumption.
    if (__DEV__) {
      console.warn('[E2EELeader] Web Locks API unavailable — assuming leadership (fail-open)');
    }
    markLeader();
    return;
  }

  state = 'follower';
  try {
    // The holder function's promise NEVER resolves — we hold the lock for
    // the tab's lifetime; the browser releases it when the tab closes and
    // grants it to the next waiter, which then runs markLeader().
    void locks.request('lewo-e2ee-device-leader', { mode: 'exclusive' }, () => {
      if (__DEV__) console.log('👑 [E2EELeader] this tab is now the E2EE leader');
      markLeader();
      return new Promise<void>(() => {
        /* held until tab close */
      });
    });
  } catch (err) {
    if (__DEV__) console.warn('[E2EELeader] lock request failed — assuming leadership:', err);
    markLeader();
  }
}

/**
 * True when this context may act as the E2EE device (decrypt, answer
 * resends, upload/rotate keys). Triggers the election lazily so callers
 * don't need a separate bootstrap step. Native → always true.
 */
export function isE2EELeader(): boolean {
  ensureE2EELeadershipRequested();
  return state === 'leader';
}

/**
 * Run `cb` once leadership is held — immediately when already leader,
 * otherwise on promotion (the prior leader tab closed). Used by the E2EE
 * bring-up sites to re-arm themselves on late promotion.
 */
export function whenE2EELeader(cb: () => void): void {
  ensureE2EELeadershipRequested();
  if (state === 'leader') {
    cb();
    return;
  }
  onLeaderCallbacks.push(cb);
}

/** Promise form of {@link whenE2EELeader} for async flows (useEncryptionSetup). */
export function awaitE2EELeadership(): Promise<void> {
  return new Promise((resolve) => whenE2EELeader(resolve));
}

/** Test hook: reset module state between cases. */
export function __resetE2EELeaderForTest(): void {
  state = 'unknown';
  requested = false;
  onLeaderCallbacks.length = 0;
}
