/**
 * DecryptionPipeline coverage tests.
 *
 * Pin down: validateInputs (every error code branch + boundary cases),
 * decryptWithMessageKey (V2→V1 AAD fallback, version mismatch),
 * finalizePlaintext, cacheKey, tryDecryptWithSkippedKey (XChaCha success,
 * AES-GCM fallback, both fail → null, parse error fall-through),
 * tryPreviousSessionFallback (chain walk, counter mismatch, AAD V2/V1/no-AAD
 * fallback, MAX_WALK limit).
 */

const mockHexToBytes = jest.fn();
const mockBytesToHex = jest.fn();
const mockDecryptXChaCha = jest.fn();
const mockSecureZero = jest.fn();
const mockBuildMessageAAD = jest.fn();
const mockMetadataRemovePadding = jest.fn();
const mockMetadataUnwrapEnvelope = jest.fn();
const mockDeriveMessageKey = jest.fn();
const mockDeriveNextChainKey = jest.fn();

jest.mock('../../../src/services/SodiumCrypto', () => ({
  hexToBytes: (h: string) => mockHexToBytes(h),
  bytesToHex: (b: Uint8Array) => mockBytesToHex(b),
  decryptXChaCha20Poly1305: (...args: any[]) => mockDecryptXChaCha(...args),
  secureZero: (b: Uint8Array) => mockSecureZero(b),
}));

jest.mock('../../../src/services/e2ee/E2EEMessageSerializer', () => ({
  buildMessageAAD: (...args: any[]) => mockBuildMessageAAD(...args),
}));

jest.mock('../../../src/services/e2ee/MetadataCipher', () => ({
  MetadataCipher: {
    removePadding: (b: Uint8Array) => mockMetadataRemovePadding(b),
    unwrapEnvelope: (s: string) => mockMetadataUnwrapEnvelope(s),
  },
}));

jest.mock('../../../src/services/e2ee/E2EEKeyDerivation', () => ({
  deriveMessageKey: (...args: any[]) => mockDeriveMessageKey(...args),
  deriveNextChainKey: (k: string) => mockDeriveNextChainKey(k),
}));

import { DecryptionPipeline, ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1 } from '../../../src/services/e2ee/DecryptionPipeline';

beforeEach(() => {
  jest.clearAllMocks();
  mockHexToBytes.mockImplementation((h: string) => new Uint8Array(h.length / 2));
  mockBytesToHex.mockImplementation((b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join(''));
  mockDecryptXChaCha.mockReturnValue(new Uint8Array([1, 2, 3]));
  mockBuildMessageAAD.mockReturnValue(new Uint8Array(16));
  mockMetadataRemovePadding.mockImplementation((b: Uint8Array) => b);
  mockMetadataUnwrapEnvelope.mockReturnValue({ content: 'plain', envelope: { v: 1 } });
  mockDeriveMessageKey.mockReturnValue('mk-hex');
  mockDeriveNextChainKey.mockReturnValue('next-chain');
});

const opts = {
  maxMessageSizeBytes: 5_000_000,
  maxFutureTimestampMs: 60_000,
  maxMessageAgeMs: 7 * 24 * 60 * 60 * 1000,
};

describe('validateInputs — every error code', () => {
  it('throws INVALID_COUNTER when undefined', () => {
    expect(() =>
      DecryptionPipeline.validateInputs(undefined, 'ct', 'iv', undefined, opts),
    ).toThrow(/INVALID_COUNTER/);
  });

  it('throws INVALID_COUNTER when null', () => {
    expect(() =>
      DecryptionPipeline.validateInputs(null, 'ct', 'iv', undefined, opts),
    ).toThrow(/INVALID_COUNTER/);
  });

  it('coerces string counter to integer', () => {
    expect(DecryptionPipeline.validateInputs('5', 'ct', 'iv', undefined, opts)).toBe(5);
  });

  it('throws INVALID_COUNTER for negative', () => {
    expect(() =>
      DecryptionPipeline.validateInputs(-1, 'ct', 'iv', undefined, opts),
    ).toThrow(/non-negative integer/);
  });

  it('throws INVALID_COUNTER for non-integer', () => {
    expect(() =>
      DecryptionPipeline.validateInputs(1.5, 'ct', 'iv', undefined, opts),
    ).toThrow(/non-negative integer/);
  });

  it('throws MESSAGE_TOO_LARGE when encoded size exceeds limit', () => {
    expect(() =>
      DecryptionPipeline.validateInputs(
        0, 'a'.repeat(100), 'b'.repeat(100), undefined,
        { ...opts, maxMessageSizeBytes: 50 },
      ),
    ).toThrow(/MESSAGE_TOO_LARGE/);
  });

  it('throws INVALID_TIMESTAMP for malformed date', () => {
    expect(() =>
      DecryptionPipeline.validateInputs(0, 'ct', 'iv', 'not-a-date', opts),
    ).toThrow(/INVALID_TIMESTAMP/);
  });

  it('throws FUTURE_MESSAGE for far-future timestamp', () => {
    const future = new Date(Date.now() + 10 * 60 * 60 * 1000).toISOString();
    expect(() =>
      DecryptionPipeline.validateInputs(0, 'ct', 'iv', future, opts),
    ).toThrow(/FUTURE_MESSAGE/);
  });

  it('throws EXPIRED_MESSAGE for too-old timestamp', () => {
    const old = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    expect(() =>
      DecryptionPipeline.validateInputs(0, 'ct', 'iv', old, opts),
    ).toThrow(/EXPIRED_MESSAGE/);
  });

  it('accepts valid inputs and returns counter', () => {
    expect(DecryptionPipeline.validateInputs(7, 'ct', 'iv', undefined, opts)).toBe(7);
  });

  it('accepts valid timestamp within window', () => {
    const recent = new Date(Date.now() - 60_000).toISOString();
    expect(DecryptionPipeline.validateInputs(7, 'ct', 'iv', recent, opts)).toBe(7);
  });
});

describe('decryptWithMessageKey', () => {
  it('throws UNSUPPORTED_ENCRYPTION_VERSION on wrong version', () => {
    expect(() =>
      DecryptionPipeline.decryptWithMessageKey({
        parsedEnvelope: { v: 99, n: '00', c: '00' },
        messageKeyBytes: new Uint8Array(32),
        conversationId: 'c1', messageCounter: 0,
        senderId: 's', recipientId: 'r',
      }),
    ).toThrow(/UNSUPPORTED_ENCRYPTION_VERSION/);
  });

  it('decrypts with V2 AAD on first try', () => {
    const result = DecryptionPipeline.decryptWithMessageKey({
      parsedEnvelope: { v: ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1, n: '00', c: '00' },
      messageKeyBytes: new Uint8Array(32),
      conversationId: 'c1', messageCounter: 0,
      senderId: 's', recipientId: 'r',
    });
    expect(result).toEqual(new Uint8Array([1, 2, 3]));
    expect(mockDecryptXChaCha).toHaveBeenCalled();
  });

  it('falls back to V1 AAD when V2 fails', () => {
    let callCount = 0;
    mockDecryptXChaCha.mockImplementation(() => {
      callCount++;
      if (callCount === 1) throw new Error('V2 AAD failed');
      return new Uint8Array([5, 6, 7]);
    });
    const result = DecryptionPipeline.decryptWithMessageKey({
      parsedEnvelope: { v: ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1, n: '00', c: '00' },
      messageKeyBytes: new Uint8Array(32),
      conversationId: 'c1', messageCounter: 0,
      senderId: 's', recipientId: 'r',
    });
    expect(result).toEqual(new Uint8Array([5, 6, 7]));
    expect(mockDecryptXChaCha).toHaveBeenCalledTimes(2);
  });
});

describe('finalizePlaintext', () => {
  it('removes padding + unwraps envelope', () => {
    const result = DecryptionPipeline.finalizePlaintext(new Uint8Array(16));
    expect(result.plaintext).toBe('plain');
    expect(result.envelope).toEqual({ v: 1 });
    expect(mockMetadataRemovePadding).toHaveBeenCalled();
    expect(mockMetadataUnwrapEnvelope).toHaveBeenCalled();
  });
});

describe('cacheKey', () => {
  it('builds canonical "convId:counter:hash" string', () => {
    expect(DecryptionPipeline.cacheKey('c1', 5, 'abc')).toBe('c1:5:abc');
  });
});

describe('tryDecryptWithSkippedKey', () => {
  const baseArgs = {
    encryptedContent: '',
    messageKeyHex: 'aa'.repeat(32),
    conversationId: 'c1',
    messageCounter: 0,
    senderId: 's',
    recipientId: 'r',
    decryptAESGCM: jest.fn(),
    deserializeCiphertext: jest.fn(),
    aesGcmVersion: 1,
  };

  it('returns null when neither XChaCha nor AES-GCM matches', async () => {
    const result = await DecryptionPipeline.tryDecryptWithSkippedKey({
      ...baseArgs,
      encryptedContent: 'not-json-not-aes',
      deserializeCiphertext: jest.fn(() => null),
    });
    expect(result).toBeNull();
  });

  it('returns XChaCha result on success', async () => {
    const result = await DecryptionPipeline.tryDecryptWithSkippedKey({
      ...baseArgs,
      encryptedContent: JSON.stringify({ v: ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1, n: 'aa', c: 'bb' }),
    });
    expect(result?.kind).toBe('xchacha');
  });

  it('throws when XChaCha decrypt fails (caller handles)', async () => {
    mockDecryptXChaCha.mockImplementation(() => { throw new Error('AEAD'); });
    await expect(
      DecryptionPipeline.tryDecryptWithSkippedKey({
        ...baseArgs,
        encryptedContent: JSON.stringify({ v: ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1, n: 'aa', c: 'bb' }),
      }),
    ).rejects.toThrow();
  });

  it('falls through to AES-GCM when not JSON', async () => {
    const decryptAESGCM = jest.fn().mockResolvedValue('aes-plain');
    const deserializeCiphertext = jest.fn(() => ({ version: 1, ciphertext: 'x' }));
    const result = await DecryptionPipeline.tryDecryptWithSkippedKey({
      ...baseArgs,
      encryptedContent: 'aes-encoded-content',
      decryptAESGCM,
      deserializeCiphertext,
    });
    expect(result?.kind).toBe('aesgcm');
    expect((result as any).plaintext).toBe('aes-plain');
  });

  it('returns null when AES-GCM version mismatch', async () => {
    const result = await DecryptionPipeline.tryDecryptWithSkippedKey({
      ...baseArgs,
      encryptedContent: 'aes',
      deserializeCiphertext: jest.fn(() => ({ version: 99 })),
    });
    expect(result).toBeNull();
  });

  it('throws when AES-GCM decrypt fails', async () => {
    const decryptAESGCM = jest.fn().mockRejectedValue(new Error('AES fail'));
    const deserializeCiphertext = jest.fn(() => ({ version: 1 }));
    await expect(
      DecryptionPipeline.tryDecryptWithSkippedKey({
        ...baseArgs,
        encryptedContent: 'aes',
        decryptAESGCM,
        deserializeCiphertext,
      }),
    ).rejects.toThrow('AES fail');
  });
});

describe('tryPreviousSessionFallback', () => {
  const baseArgs = {
    parsedEnvelope: { v: ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1, n: 'aa', c: 'bb' },
    previousChainKeyReceive: 'old-chain',
    previousReceiveCounter: 0,
    targetCounter: 5,
    conversationId: 'c1',
    senderId: 's',
    recipientId: 'r',
  };

  it('returns null when no previousChainKey', () => {
    const result = DecryptionPipeline.tryPreviousSessionFallback({
      ...baseArgs, previousChainKeyReceive: '',
    });
    expect(result).toBeNull();
  });

  it('returns null when targetCounter < previousReceiveCounter', () => {
    const result = DecryptionPipeline.tryPreviousSessionFallback({
      ...baseArgs, previousReceiveCounter: 10, targetCounter: 5,
    });
    expect(result).toBeNull();
  });

  it('decrypts with V2 AAD on first attempt', () => {
    mockDecryptXChaCha.mockReturnValue(new Uint8Array([9, 9, 9]));
    const result = DecryptionPipeline.tryPreviousSessionFallback(baseArgs);
    expect(result).toEqual(new Uint8Array([9, 9, 9]));
  });

  it('falls back to V1 AAD then no-AAD on AEAD failures', () => {
    let callCount = 0;
    mockDecryptXChaCha.mockImplementation(() => {
      callCount++;
      if (callCount <= 2) throw new Error('AEAD failed');
      return new Uint8Array([8]);
    });
    const result = DecryptionPipeline.tryPreviousSessionFallback(baseArgs);
    expect(result).toEqual(new Uint8Array([8]));
    expect(mockDecryptXChaCha).toHaveBeenCalledTimes(3);
  });

  it('returns null when all AEAD variants fail', () => {
    mockDecryptXChaCha.mockImplementation(() => { throw new Error('all fail'); });
    const result = DecryptionPipeline.tryPreviousSessionFallback(baseArgs);
    expect(result).toBeNull();
  });

  it('respects MAX_WALK limit (default 1000)', () => {
    const result = DecryptionPipeline.tryPreviousSessionFallback({
      ...baseArgs, targetCounter: 2000,
    });
    expect(result).toBeNull(); // walk doesn't reach target
  });

  it('honors custom maxWalk parameter', () => {
    const result = DecryptionPipeline.tryPreviousSessionFallback({
      ...baseArgs, targetCounter: 100, maxWalk: 5,
    });
    expect(result).toBeNull(); // walk capped at 5
  });

  it('zeros message key in finally block', () => {
    DecryptionPipeline.tryPreviousSessionFallback(baseArgs);
    expect(mockSecureZero).toHaveBeenCalled();
  });
});
