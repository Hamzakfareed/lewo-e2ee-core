import { DecryptionPipeline } from '@/src/services/e2ee/DecryptionPipeline';
import { initializeSodium, randomBytes, bytesToHex, encryptXChaCha20Poly1305 } from '@/src/services/SodiumCrypto';
import { buildMessageAAD } from '@/src/services/e2ee/E2EEMessageSerializer';

beforeAll(async () => {
  await initializeSodium();
});

const opts = {
  maxMessageSizeBytes: 1_000_000,
  maxFutureTimestampMs: 60_000,
  maxMessageAgeMs: 24 * 60 * 60 * 1000,
};

describe('DecryptionPipeline.validateInputs', () => {
  test('throws on null/undefined messageCounter', () => {
    expect(() => DecryptionPipeline.validateInputs(undefined, 'c', 'iv', undefined, opts)).toThrow(/INVALID_COUNTER/);
    expect(() => DecryptionPipeline.validateInputs(null, 'c', 'iv', undefined, opts)).toThrow(/INVALID_COUNTER/);
  });

  test('coerces string counter to number', () => {
    expect(DecryptionPipeline.validateInputs('42' as any, 'c', 'iv', undefined, opts)).toBe(42);
  });

  test('throws on non-integer/negative counter', () => {
    expect(() => DecryptionPipeline.validateInputs(2.5, 'c', 'iv', undefined, opts)).toThrow(/INVALID_COUNTER/);
    expect(() => DecryptionPipeline.validateInputs(-1, 'c', 'iv', undefined, opts)).toThrow(/INVALID_COUNTER/);
  });

  test('throws on oversized payload', () => {
    const big = 'a'.repeat(2_000_000);
    expect(() => DecryptionPipeline.validateInputs(0, big, 'iv', undefined, opts)).toThrow(/MESSAGE_TOO_LARGE/);
  });

  test('throws on NaN timestamp (replay-bypass guard)', () => {
    expect(() =>
      DecryptionPipeline.validateInputs(0, 'c', 'iv', 'not-a-date', opts),
    ).toThrow(/INVALID_TIMESTAMP/);
  });

  test('throws on far-future timestamp', () => {
    const futureIso = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    expect(() =>
      DecryptionPipeline.validateInputs(0, 'c', 'iv', futureIso, opts),
    ).toThrow(/FUTURE_MESSAGE/);
  });

  test('throws on stale message older than max age', () => {
    const staleIso = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    expect(() =>
      DecryptionPipeline.validateInputs(0, 'c', 'iv', staleIso, opts),
    ).toThrow(/EXPIRED_MESSAGE/);
  });

  test('passes through valid current-time timestamp', () => {
    expect(
      DecryptionPipeline.validateInputs(7, 'c', 'iv', new Date().toISOString(), opts),
    ).toBe(7);
  });

  test('returns counter when no timestamp supplied', () => {
    expect(DecryptionPipeline.validateInputs(3, 'c', 'iv', undefined, opts)).toBe(3);
  });
});

describe('DecryptionPipeline.decryptWithMessageKey', () => {
  test('decrypts a V2 AAD envelope round-trip', () => {
    const key = randomBytes(32);
    const conversationId = 'conv-1';
    const counter = 5;
    const ratchetKey = bytesToHex(randomBytes(32));
    const senderId = 'alice';
    const recipientId = 'bob';
    const aad = buildMessageAAD(conversationId, counter, ratchetKey, senderId, recipientId);
    const enc = encryptXChaCha20Poly1305(new TextEncoder().encode('hello'), key, aad);
    const parsed = { v: 2, n: bytesToHex(enc.nonce), c: bytesToHex(enc.ciphertext) };
    const out = DecryptionPipeline.decryptWithMessageKey({
      parsedEnvelope: parsed,
      messageKeyBytes: key,
      conversationId,
      messageCounter: counter,
      ratchetPublicKey: ratchetKey,
      senderId,
      recipientId,
    });
    expect(new TextDecoder().decode(out)).toBe('hello');
  });

  test('falls back to V1 AAD if V2 fails (legacy sender)', () => {
    const key = randomBytes(32);
    const conversationId = 'conv-1';
    const counter = 5;
    const ratchetKey = bytesToHex(randomBytes(32));
    // Encrypt with V1 AAD (no userIds).
    const aadV1 = buildMessageAAD(conversationId, counter, ratchetKey);
    const enc = encryptXChaCha20Poly1305(new TextEncoder().encode('legacy'), key, aadV1);
    const parsed = { v: 2, n: bytesToHex(enc.nonce), c: bytesToHex(enc.ciphertext) };
    const out = DecryptionPipeline.decryptWithMessageKey({
      parsedEnvelope: parsed,
      messageKeyBytes: key,
      conversationId,
      messageCounter: counter,
      ratchetPublicKey: ratchetKey,
      senderId: 'alice',
      recipientId: 'bob',
    });
    expect(new TextDecoder().decode(out)).toBe('legacy');
  });

  test('throws on tampered ciphertext (AEAD MAC fails for both V1 and V2)', () => {
    const key = randomBytes(32);
    const conversationId = 'conv-1';
    const counter = 5;
    const aad = buildMessageAAD(conversationId, counter);
    const enc = encryptXChaCha20Poly1305(new TextEncoder().encode('plain'), key, aad);
    const tampered = bytesToHex(enc.ciphertext).slice(0, -2) + '00';
    expect(() =>
      DecryptionPipeline.decryptWithMessageKey({
        parsedEnvelope: { v: 2, n: bytesToHex(enc.nonce), c: tampered },
        messageKeyBytes: key,
        conversationId,
        messageCounter: counter,
        senderId: 'a',
        recipientId: 'b',
      }),
    ).toThrow();
  });

  test('throws UNSUPPORTED_ENCRYPTION_VERSION on non-v2 envelope', () => {
    expect(() =>
      DecryptionPipeline.decryptWithMessageKey({
        parsedEnvelope: { v: 1 as any, n: '', c: '' },
        messageKeyBytes: randomBytes(32),
        conversationId: 'c',
        messageCounter: 0,
        senderId: 'a',
        recipientId: 'b',
      }),
    ).toThrow(/UNSUPPORTED_ENCRYPTION_VERSION/);
  });
});

describe('DecryptionPipeline.finalizePlaintext', () => {
  test('strips padding and unwraps a v2 envelope', () => {
    const inner = JSON.stringify({ v: 2, c: 'hello', t: 'IMAGE', m: ['url-1'] });
    const padded = new Uint8Array(1024);
    padded.set(new TextEncoder().encode(inner));
    padded[inner.length] = 0x80;
    const out = DecryptionPipeline.finalizePlaintext(padded);
    expect(out.plaintext).toBe('hello');
    expect(out.envelope).toEqual({
      messageType: 'IMAGE',
      mediaUrls: ['url-1'],
      metadata: null,
      replyToMessageUuid: null,
    });
  });

  test('returns plaintext + null envelope for v1 plain text', () => {
    const padded = new Uint8Array(1024);
    padded.set(new TextEncoder().encode('legacy text'));
    padded[11] = 0x80;
    const out = DecryptionPipeline.finalizePlaintext(padded);
    expect(out.plaintext).toBe('legacy text');
    expect(out.envelope).toBeNull();
  });
});

describe('DecryptionPipeline.cacheKey', () => {
  test('produces deterministic conv:counter:hash', () => {
    expect(DecryptionPipeline.cacheKey('c', 5, 'abc')).toBe('c:5:abc');
  });
});
