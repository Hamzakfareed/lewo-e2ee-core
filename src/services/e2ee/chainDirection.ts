/**
 * Double-Ratchet chain-key DIRECTION tiebreak.
 *
 * A 1:1 session derives two symmetric chain keys (A and B) from the shared
 * secret. Each end must use OPPOSITE keys for SEND vs RECEIVE for the duplex
 * channel to work: one end sends on A / receives on B, the other sends on B /
 * receives on A. `isFirstParticipant === true` means "send on A, receive on B".
 *
 * The two ends therefore MUST compute opposite `isFirstParticipant` flags.
 *
 * - Genuine peers (myUserId !== peerUserId): legacy userId tiebreak. Each side
 *   compares the lexicographically-first userId against ITS OWN id; because the
 *   two ids differ, the flags are naturally opposite. (Unchanged behaviour.)
 *
 * - SELF-SYNC (myUserId === peerUserId, e.g. user1's web ↔ user1's phone): the
 *   userId tiebreak is DEGENERATE — both ends share one userId, so both compute
 *   the same flag, both pick the same send chain, and every message fails with
 *   "authentication tag invalid". Break the tie by DEVICE id instead (my device
 *   vs the other device), which IS asymmetric.
 *
 * Role fallback (initiator ⇒ first) is used only when a device id cannot be
 * resolved — see {@link resolveOwnDeviceIdSync}. In steady state the sender's
 * fan-out has already resolved its own device id and the receiver resolved its
 * own to subscribe to the per-device topic, so the fallback is a cold-start edge.
 */

/**
 * Synchronously resolve this install's stable device id (a real, non-'primary'
 * id), or null when it hasn't been resolved yet. Mirrors the resolution used by
 * the own-message-echo guard in E2EEncryptionService.decrypt so both agree.
 */
export function resolveOwnDeviceIdSync(): string | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { multiDeviceManager } = require('./MultiDeviceManager');
    const id = multiDeviceManager?.getOwnDeviceIdSync?.();
    return typeof id === 'string' && id.length > 0 && id !== 'primary' ? id : null;
  } catch {
    return null;
  }
}

/**
 * AWAIT this install's stable device id for self-sync session establishment.
 *
 * The sync variant ({@link resolveOwnDeviceIdSync}) reads a module memo that is
 * only populated by an async, fire-and-forget call (`getOwnDeviceId()` →
 * AsyncStorage). During the cold-start window — and on the very first message of
 * a conversation, before the per-device subscription's async resolve has settled
 * — it returns null, which silently degrades the self-sync direction tiebreak to
 * the role fallback. For a self-sync pair the role is NOT a valid discriminator
 * (each device is an initiator toward the other), so both ends pick the same
 * send chain and every message fails "authentication tag invalid", and the wrong
 * direction is then persisted and reused forever.
 *
 * Resolving asynchronously here forces the AsyncStorage read to complete so the
 * deterministic device-id tiebreak ALWAYS runs for self-sync. Returns null only
 * on genuine failure / 'primary' (defensive default), in which case callers fall
 * back to role exactly as before. Session-build paths are already async, so the
 * extra await is free; the genuine-peer path never calls this.
 */
export async function resolveOwnDeviceId(): Promise<string | null> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { multiDeviceManager } = require('./MultiDeviceManager');
    const id = await multiDeviceManager?.getOwnDeviceId?.();
    return typeof id === 'string' && id.length > 0 && id !== 'primary' ? id : null;
  } catch {
    return null;
  }
}

export interface ChainDirectionArgs {
  /** The local user's id (the side computing this flag). */
  myUserId: string;
  /** The other party's user id. Equal to myUserId for a self-sync session. */
  peerUserId: string;
  /** The local device's id (non-'primary'), or null if unresolved. */
  myDeviceId: string | null;
  /** The other device's id from the session/envelope (peerDeviceId / senderDeviceId). */
  otherDeviceId?: string;
  /** True when this side ran the X3DH initiator, false for the responder. */
  roleIsInitiator: boolean;
}

/**
 * Decide the `isFirstParticipant` flag for chain-key SEND/RECEIVE assignment.
 * See the module doc for the invariant and the self-sync rationale.
 */
export function resolveChainDirectionIsFirst(args: ChainDirectionArgs): boolean {
  const { myUserId, peerUserId, myDeviceId, otherDeviceId, roleIsInitiator } = args;

  // Genuine peer: byte-identical to the legacy userId tiebreak.
  if (myUserId !== peerUserId) {
    return [myUserId, peerUserId].sort()[0] === myUserId;
  }

  // Self-sync: tie-break by device id (asymmetric because the two devices differ).
  if (
    myDeviceId &&
    otherDeviceId &&
    otherDeviceId !== 'primary' &&
    myDeviceId !== otherDeviceId
  ) {
    return [myDeviceId, otherDeviceId].sort()[0] === myDeviceId;
  }

  // Device id unresolved — fall back to role so the two ends still land on
  // opposite chains (initiator ⇒ first). Warned because a divergence here would
  // silently break self-sync delivery for this session.
  console.warn(
    '⚠️ [E2EE] self-sync chain-direction tiebreak fell back to role (device id unresolved) — ' +
      'self-sync delivery may be unreliable until device ids resolve',
  );
  return roleIsInitiator;
}
