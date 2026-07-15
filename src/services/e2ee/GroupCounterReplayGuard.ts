/**
 * Replay-counter and counter-gap-DoS guards for inbound group messages.
 *
 * Two related checks share this module:
 *
 * 1. `enforceCounterGapBound` — rejects messages whose counter is more
 *    than `MAX_ALLOWED_GAP` ahead of our last-seen counter. Without this,
 *    a malicious sender could force us to ratchet the chain millions of
 *    times to catch up, blocking the event loop.
 *
 * 2. `MAX_ALLOWED_GROUP_COUNTER_GAP` — exported constant for parity with
 *    the in-line literal that was previously buried in
 *    GroupE2EEncryptionService.decryptMessage.
 *
 * The replay-vs-current check stays inline at the call site because it
 * branches into the H10 previous-chain fallback (an instance method).
 */

export const MAX_ALLOWED_GROUP_COUNTER_GAP = 1000;

/**
 * Throws if `messageCounter - storedCounter > MAX_ALLOWED_GROUP_COUNTER_GAP`.
 * Caller must already have checked `messageCounter > storedCounter` (the
 * replay path is handled separately).
 */
export function enforceCounterGapBound(params: {
  messageCounter: number;
  storedCounter: number;
  maxAllowedGap?: number;
}): void {
  const { messageCounter, storedCounter, maxAllowedGap = MAX_ALLOWED_GROUP_COUNTER_GAP } = params;
  const gap = messageCounter - storedCounter;
  if (gap > maxAllowedGap) {
    throw new Error(
      `COUNTER_GAP_EXCEEDED: Message counter gap too large. Session may need re-keying.`,
    );
  }
}
