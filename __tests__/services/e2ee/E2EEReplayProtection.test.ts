/**
 * Unit tests for E2EEReplayProtection — Path B Phase A.3.
 *
 * This module is the home of the NaN-timestamp bypass guard. Tests
 * cover EVERY branch + EVERY input boundary so a regression is
 * impossible without a red test.
 *
 * NaN guard test cases are first-class: they MUST come before window
 * comparisons in the implementation. If a refactor reorders, one of
 * these tests fails.
 */

import {
  validateMessageTimestamp,
  validatePreReset,
} from '@/src/services/e2ee/E2EEReplayProtection';

const NOW = Date.UTC(2026, 0, 15, 12, 0, 0); // a fixed reference time

describe('validateMessageTimestamp', () => {
  describe('happy path', () => {
    test('undefined messageSentAt → ok (validation only triggers when present)', () => {
      expect(validateMessageTimestamp(undefined, 60_000, 24 * 60 * 60_000, NOW))
        .toEqual({ ok: true });
    });

    test('empty string messageSentAt → ok (treated as absent)', () => {
      expect(validateMessageTimestamp('', 60_000, 24 * 60 * 60_000, NOW))
        .toEqual({ ok: true });
    });

    test('timestamp at exactly NOW → ok', () => {
      const ts = new Date(NOW).toISOString();
      expect(validateMessageTimestamp(ts, 60_000, 24 * 60 * 60_000, NOW).ok)
        .toBe(true);
    });

    test('timestamp 30s in the future → ok (within 60s window)', () => {
      const ts = new Date(NOW + 30_000).toISOString();
      expect(validateMessageTimestamp(ts, 60_000, 24 * 60 * 60_000, NOW).ok)
        .toBe(true);
    });

    test('timestamp 23h ago → ok (within 24h window)', () => {
      const ts = new Date(NOW - 23 * 60 * 60_000).toISOString();
      expect(validateMessageTimestamp(ts, 60_000, 24 * 60 * 60_000, NOW).ok)
        .toBe(true);
    });
  });

  describe('NaN timestamp bypass — fail-closed regression guard', () => {
    test("'not-a-date' is rejected with INVALID_TIMESTAMP", () => {
      const r = validateMessageTimestamp('not-a-date', 60_000, 24 * 60 * 60_000, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('INVALID_TIMESTAMP');
    });

    test('"" is treated as absent (not NaN — see happy path)', () => {
      expect(validateMessageTimestamp('', 60_000, 24 * 60 * 60_000, NOW))
        .toEqual({ ok: true });
    });

    test('numeric-shaped non-date "NaN" string → INVALID_TIMESTAMP', () => {
      const r = validateMessageTimestamp('NaN', 60_000, 24 * 60 * 60_000, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('INVALID_TIMESTAMP');
    });

    test('garbage with sneaky chars → INVALID_TIMESTAMP', () => {
      const r = validateMessageTimestamp('2026-99-99T99:99', 60_000, 24 * 60 * 60_000, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('INVALID_TIMESTAMP');
    });

    test('the NaN guard runs BEFORE the future/expiry comparisons (must not fall through)', () => {
      // If the NaN check were after the future/expiry comparisons,
      // a malformed timestamp would compare-false against both bounds
      // and the function would return ok: true. Verifying by passing
      // very narrow bounds AND a malformed timestamp: an ok:true
      // return would mean the NaN guard isn't running first.
      const r = validateMessageTimestamp('garbage', 1, 1, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('INVALID_TIMESTAMP');
    });
  });

  describe('future-window rejection', () => {
    test('timestamp 61s in the future is rejected (just past 60s window)', () => {
      const ts = new Date(NOW + 61_000).toISOString();
      const r = validateMessageTimestamp(ts, 60_000, 24 * 60 * 60_000, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('FUTURE_MESSAGE');
    });

    test('timestamp 1 year in the future is rejected', () => {
      const ts = new Date(NOW + 365 * 24 * 60 * 60_000).toISOString();
      const r = validateMessageTimestamp(ts, 60_000, 24 * 60 * 60_000, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('FUTURE_MESSAGE');
    });

    test('window is configurable — narrower window rejects sooner', () => {
      const ts = new Date(NOW + 5_000).toISOString();
      // 1s window — 5s in the future fails.
      const r = validateMessageTimestamp(ts, 1_000, 24 * 60 * 60_000, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('FUTURE_MESSAGE');
    });
  });

  describe('expiry-window rejection', () => {
    test('timestamp 25h ago is rejected (just past 24h window)', () => {
      const ts = new Date(NOW - 25 * 60 * 60_000).toISOString();
      const r = validateMessageTimestamp(ts, 60_000, 24 * 60 * 60_000, NOW);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('EXPIRED_MESSAGE');
    });

    test('window is configurable — wider window accepts older', () => {
      const ts = new Date(NOW - 100 * 60 * 60_000).toISOString();
      // 200h window accommodates 100h-old.
      const r = validateMessageTimestamp(ts, 60_000, 200 * 60 * 60_000, NOW);
      expect(r.ok).toBe(true);
    });
  });
});

describe('validatePreReset', () => {
  test('undefined messageSentAt → ok', () => {
    expect(validatePreReset(undefined, NOW)).toEqual({ ok: true });
  });

  test('undefined resetTimestamp → ok (no reset boundary)', () => {
    expect(validatePreReset(new Date(NOW).toISOString(), undefined))
      .toEqual({ ok: true });
  });

  test('message at exactly resetTimestamp → ok (boundary is open above)', () => {
    expect(validatePreReset(new Date(NOW).toISOString(), NOW))
      .toEqual({ ok: true });
  });

  test('message 1s after reset → ok', () => {
    expect(validatePreReset(new Date(NOW + 1_000).toISOString(), NOW).ok)
      .toBe(true);
  });

  test('message 1s before reset → PRE_RESET_MESSAGE', () => {
    const r = validatePreReset(new Date(NOW - 1_000).toISOString(), NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('PRE_RESET_MESSAGE');
  });

  test('NaN guard fires BEFORE the resetTimestamp comparison', () => {
    // Without the guard, NaN < resetTimestamp is false → ok: true →
    // pre-reset messages with malformed timestamps slip through.
    const r = validatePreReset('garbage', NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('INVALID_TIMESTAMP');
  });
});
