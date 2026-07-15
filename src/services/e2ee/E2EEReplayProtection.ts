/**
 * E2EE replay-protection primitives — pure validators for the
 * timestamp + counter window checks that gate every decrypt path.
 *
 * EXTRACTED FROM `E2EEncryptionService.ts` (Path B Phase A.3). This is
 * the module where the NaN-timestamp bypass bug lived; isolating it
 * here makes the bug-class trivially testable and ensures every
 * future caller goes through the same validator.
 *
 * Pure functions only. Each returns a typed result instead of
 * throwing (callers can decide to map to E2EError). The orchestrator
 * adapts the result back to its existing throw-based contract.
 */

/** Result of a timestamp validation. */
export type TimestampValidationResult =
  | { ok: true }
  | {
      ok: false;
      reason:
        | 'INVALID_TIMESTAMP'   // NaN / unparseable date
        | 'FUTURE_MESSAGE'      // exceeds future window
        | 'EXPIRED_MESSAGE'     // exceeds max-age window
        | 'PRE_RESET_MESSAGE';  // before a session reset boundary
      detail: string;
    };

/**
 * Validate a message's `messageSentAt` against future-window and
 * expiry-window bounds. Fail-closed on NaN — this is the regression
 * guard for the bug where `new Date('garbage').getTime()` returns NaN
 * and `NaN > X` / `X > NaN` are both false, silently bypassing both
 * windows.
 *
 * @param messageSentAt - ISO timestamp from the message envelope
 * @param maxFutureMs - acceptable clock skew above `now` (default 60s)
 * @param maxAgeMs - reject messages older than this (default 24h)
 * @param now - injection point for testability (default Date.now())
 */
export function validateMessageTimestamp(
  messageSentAt: string | undefined,
  maxFutureMs: number = 60 * 1000,
  maxAgeMs: number = 24 * 60 * 60 * 1000,
  now: number = Date.now(),
): TimestampValidationResult {
  if (!messageSentAt) {
    // Missing timestamp is allowed by the existing contract (the
    // orchestrator only validates when the field is present).
    return { ok: true };
  }

  const messageTime = new Date(messageSentAt).getTime();

  // SECURITY: Must come BEFORE the window comparisons. NaN > X and
  // X > NaN are both false; without this, malformed timestamps skip
  // BOTH the future and expiry checks.
  if (Number.isNaN(messageTime)) {
    return {
      ok: false,
      reason: 'INVALID_TIMESTAMP',
      detail: `messageSentAt '${messageSentAt}' is not a valid date`,
    };
  }

  if (messageTime > now + maxFutureMs) {
    return {
      ok: false,
      reason: 'FUTURE_MESSAGE',
      detail: `Message timestamp ${messageSentAt} is too far in the future`,
    };
  }

  if (now - messageTime > maxAgeMs) {
    return {
      ok: false,
      reason: 'EXPIRED_MESSAGE',
      detail: `Message timestamp ${messageSentAt} is too old (>${maxAgeMs / (24 * 60 * 60 * 1000)} days)`,
    };
  }

  return { ok: true };
}

/**
 * Validate a message's `messageSentAt` against the session's reset
 * boundary. Used to reject messages encrypted with keys that were
 * invalidated by a session reset — those messages can never decrypt
 * with the current keys.
 *
 * Same NaN guard as above — without it, a malformed timestamp
 * compares-false against any number and the pre-reset gate
 * fails-open.
 */
export function validatePreReset(
  messageSentAt: string | undefined,
  resetTimestamp: number | undefined,
): TimestampValidationResult {
  if (!messageSentAt || resetTimestamp == null) {
    return { ok: true };
  }

  const messageTime = new Date(messageSentAt).getTime();

  if (Number.isNaN(messageTime)) {
    return {
      ok: false,
      reason: 'INVALID_TIMESTAMP',
      detail: `messageSentAt '${messageSentAt}' is not a valid date`,
    };
  }

  if (messageTime < resetTimestamp) {
    return {
      ok: false,
      reason: 'PRE_RESET_MESSAGE',
      detail: 'Message was encrypted before encryption reset and cannot be decrypted',
    };
  }

  return { ok: true };
}
