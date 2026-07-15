/**
 * Unit tests for E2EEMessageSerializer — Path B Phase A.4.
 *
 * AAD construction is protocol-critical: any difference in byte
 * layout between sender and receiver breaks decryption silently.
 * These tests pin the byte-exact format so a future "tidy up"
 * refactor can't change the encoding without going red.
 */

import { buildMessageAAD } from '@/src/services/e2ee/E2EEMessageSerializer';
import { initializeSodium } from '@/src/services/SodiumCrypto';

beforeAll(async () => {
  // hexToBytes (used when ratchetPublicKey is present) requires Sodium init.
  await initializeSodium();
});

describe('buildMessageAAD', () => {
  describe('byte layout', () => {
    test('without ratchetPublicKey: layout is convId-utf8 || counter-LE32 (no trailing key)', () => {
      const aad = buildMessageAAD('conv-1', 42);
      const expectedConv = new TextEncoder().encode('conv-1');
      expect(aad.length).toBe(expectedConv.length + 4);

      // First N bytes = utf8(conversationId).
      for (let i = 0; i < expectedConv.length; i++) {
        expect(aad[i]).toBe(expectedConv[i]);
      }
      // Trailing 4 bytes = counter as little-endian uint32.
      const counterView = new DataView(aad.buffer, expectedConv.length, 4);
      expect(counterView.getUint32(0, /* littleEndian */ true)).toBe(42);
    });

    test('with ratchetPublicKey: trailing segment is the raw key bytes', () => {
      // Hex 'aabbcc' → bytes [0xaa, 0xbb, 0xcc].
      const aad = buildMessageAAD('c', 1, 'aabbcc');
      const expectedConv = new TextEncoder().encode('c');
      expect(aad.length).toBe(expectedConv.length + 4 + 3);
      expect(aad[expectedConv.length + 4]).toBe(0xaa);
      expect(aad[expectedConv.length + 5]).toBe(0xbb);
      expect(aad[expectedConv.length + 6]).toBe(0xcc);
    });

    test('counter 0 produces 4 zero bytes (regression: counter must be present even when 0)', () => {
      const aad = buildMessageAAD('c', 0);
      const expectedConv = new TextEncoder().encode('c');
      // 4 trailing bytes (counter) all zero.
      expect(aad.length).toBe(expectedConv.length + 4);
      for (let i = expectedConv.length; i < aad.length; i++) {
        expect(aad[i]).toBe(0);
      }
    });

    test('large counter (2^32 - 1) encodes as four 0xff bytes (little-endian)', () => {
      const aad = buildMessageAAD('c', 0xffffffff);
      const expectedConv = new TextEncoder().encode('c');
      // Trailing 4 bytes all 0xff.
      for (let i = 0; i < 4; i++) {
        expect(aad[expectedConv.length + i]).toBe(0xff);
      }
    });
  });

  describe('determinism + symmetry', () => {
    test('same arguments produce byte-identical AAD (sender + receiver agreement)', () => {
      const a = buildMessageAAD('conv-A', 7, 'deadbeef');
      const b = buildMessageAAD('conv-A', 7, 'deadbeef');
      expect(Array.from(a)).toEqual(Array.from(b));
    });

    test('different conversationId → different AAD', () => {
      const a = buildMessageAAD('conv-A', 7);
      const b = buildMessageAAD('conv-B', 7);
      expect(Array.from(a)).not.toEqual(Array.from(b));
    });

    test('different counter → different AAD', () => {
      const a = buildMessageAAD('c', 1);
      const b = buildMessageAAD('c', 2);
      expect(Array.from(a)).not.toEqual(Array.from(b));
    });

    test('different ratchetPublicKey → different AAD', () => {
      const a = buildMessageAAD('c', 1, 'aa');
      const b = buildMessageAAD('c', 1, 'bb');
      expect(Array.from(a)).not.toEqual(Array.from(b));
    });

    test('absent vs present ratchetPublicKey → different lengths', () => {
      const a = buildMessageAAD('c', 1);
      const b = buildMessageAAD('c', 1, 'aa');
      expect(a.length).toBeLessThan(b.length);
    });
  });

  describe('endianness invariant (regression guard)', () => {
    test('counter is encoded LITTLE-endian (matches the rest of the protocol)', () => {
      // counter = 0x12345678 → bytes [0x78, 0x56, 0x34, 0x12].
      const aad = buildMessageAAD('c', 0x12345678);
      const expectedConv = new TextEncoder().encode('c');
      expect(aad[expectedConv.length + 0]).toBe(0x78);
      expect(aad[expectedConv.length + 1]).toBe(0x56);
      expect(aad[expectedConv.length + 2]).toBe(0x34);
      expect(aad[expectedConv.length + 3]).toBe(0x12);
    });
  });

  describe('unicode conversationId', () => {
    test('handles multi-byte UTF-8 conversation IDs without truncation', () => {
      const conv = '会話-α-🌍';
      const aad = buildMessageAAD(conv, 0);
      const utf8 = new TextEncoder().encode(conv);
      expect(aad.length).toBe(utf8.length + 4);
      for (let i = 0; i < utf8.length; i++) {
        expect(aad[i]).toBe(utf8[i]);
      }
    });
  });

  describe('V2 user-id binding (Tier 1 B5)', () => {
    test('V1 layout when no user-ids passed — backwards-compat byte-identical', () => {
      const v1 = buildMessageAAD('c', 1, 'aabbcc');
      const v2WithoutIds = buildMessageAAD('c', 1, 'aabbcc', undefined, undefined);
      expect(Array.from(v1)).toEqual(Array.from(v2WithoutIds));
    });

    test('passing only senderUserId (no recipient) keeps V1 layout (avoids half-bound AAD)', () => {
      const v1 = buildMessageAAD('c', 1, 'aabbcc');
      const halfBound = buildMessageAAD('c', 1, 'aabbcc', 'alice', undefined);
      expect(Array.from(v1)).toEqual(Array.from(halfBound));
    });

    test('passing only recipientUserId (no sender) keeps V1 layout', () => {
      const v1 = buildMessageAAD('c', 1, 'aabbcc');
      const halfBound = buildMessageAAD('c', 1, 'aabbcc', undefined, 'bob');
      expect(Array.from(v1)).toEqual(Array.from(halfBound));
    });

    test('passing both ids appends 0x1E || senderId || 0x1E || recipientId', () => {
      const aad = buildMessageAAD('c', 1, 'aabbcc', 'alice', 'bob');
      const expectedConvLen = new TextEncoder().encode('c').length;
      const expectedRatchetLen = 3; // aabbcc → 3 bytes
      const baseLen = expectedConvLen + 4 + expectedRatchetLen;
      // After base, we expect: 0x1E "alice" 0x1E "bob"
      expect(aad[baseLen]).toBe(0x1e);
      expect(new TextDecoder().decode(aad.slice(baseLen + 1, baseLen + 6))).toBe('alice');
      expect(aad[baseLen + 6]).toBe(0x1e);
      expect(new TextDecoder().decode(aad.slice(baseLen + 7))).toBe('bob');
    });

    test('V2 binding makes cross-conversation envelope swap detectable', () => {
      // Same conversationId, same counter, same ratchet key — but different
      // user-id pair. Without V2 the AADs match; with V2 they differ.
      const aliceToBob = buildMessageAAD('shared-c', 5, 'beef', 'alice', 'bob');
      const carolToBob = buildMessageAAD('shared-c', 5, 'beef', 'carol', 'bob');
      expect(Array.from(aliceToBob)).not.toEqual(Array.from(carolToBob));
    });

    test('V2 binding distinguishes direction (alice→bob ≠ bob→alice)', () => {
      const fwd = buildMessageAAD('c', 1, 'aa', 'alice', 'bob');
      const rev = buildMessageAAD('c', 1, 'aa', 'bob', 'alice');
      expect(Array.from(fwd)).not.toEqual(Array.from(rev));
    });

    test('V2 binding with empty-string ids treats as V1 (no half-bound)', () => {
      const v1 = buildMessageAAD('c', 1, 'aa');
      // Empty strings are falsy, should fall back to V1.
      const empty = buildMessageAAD('c', 1, 'aa', '', '');
      expect(Array.from(v1)).toEqual(Array.from(empty));
    });

    test('V2 binding with multi-byte unicode user-ids encodes UTF-8 correctly', () => {
      const aad = buildMessageAAD('c', 1, undefined, 'アリス', 'ボブ');
      const expectedSender = new TextEncoder().encode('アリス');
      const expectedRecipient = new TextEncoder().encode('ボブ');
      const baseLen = new TextEncoder().encode('c').length + 4;
      expect(aad[baseLen]).toBe(0x1e);
      const senderActual = aad.slice(baseLen + 1, baseLen + 1 + expectedSender.length);
      expect(Array.from(senderActual)).toEqual(Array.from(expectedSender));
      expect(aad[baseLen + 1 + expectedSender.length]).toBe(0x1e);
      const recipientActual = aad.slice(baseLen + 1 + expectedSender.length + 1);
      expect(Array.from(recipientActual)).toEqual(Array.from(expectedRecipient));
    });
  });
});
