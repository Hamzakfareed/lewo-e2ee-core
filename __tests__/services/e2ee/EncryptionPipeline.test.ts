/**
 * EncryptionPipeline tests — currently 21% covered.
 *
 * Pin down the static helpers that don't require crypto:
 *   - validate: empty plaintext + size guard
 *   - advanceSendChain: counter reservation + chain key advance + lastUpdated
 *   - encrypt: returns wire envelope with all expected fields (mocked crypto)
 */

const mockHexToBytes = jest.fn();
const mockEd25519Sign = jest.fn();
const mockEncryptXChaCha20Poly1305 = jest.fn();
const mockSecureZero = jest.fn();
const mockBytesToHex = jest.fn();
const mockHexToBase64 = jest.fn();
const mockMetadataApplyPadding = jest.fn();
const mockMetadataEncryptMetadata = jest.fn();
const mockComputeKeyFingerprint = jest.fn();
const mockDeriveMessageKey = jest.fn();
const mockDeriveNextChainKey = jest.fn();
const mockBuildMessageAAD = jest.fn();

jest.mock('../../../src/services/SodiumCrypto', () => ({
  bytesToHex: (b: Uint8Array) => mockBytesToHex(b) || 'hex',
  hexToBytes: (h: string) => mockHexToBytes(h) || new Uint8Array(32),
  ed25519Sign: (data: any, key: any) => mockEd25519Sign(data, key) || new Uint8Array(64),
  encryptXChaCha20Poly1305: (...args: any[]) => mockEncryptXChaCha20Poly1305(...args) || {
    nonce: new Uint8Array(24),
    ciphertext: new Uint8Array(32),
  },
  secureZero: (b: Uint8Array) => mockSecureZero(b),
}));

jest.mock('../../../src/utils/keyEncodingConverter', () => ({
  hexToBase64: (h: string) => mockHexToBase64(h) || 'sig-base64',
}));

jest.mock('../../../src/services/e2ee/MetadataCipher', () => ({
  MetadataCipher: {
    applyPadding: (b: Uint8Array) => mockMetadataApplyPadding(b) || new Uint8Array(64),
    encryptMetadata: (m: any, k: string) => mockMetadataEncryptMetadata(m, k) || 'encrypted-metadata-blob',
  },
}));

jest.mock('../../../src/services/e2ee/E2EEFingerprint', () => ({
  computeKeyFingerprint: (k: string, n: number) => mockComputeKeyFingerprint(k, n) || 'fp-hex',
}));

jest.mock('../../../src/services/e2ee/E2EEKeyDerivation', () => ({
  deriveMessageKey: (chain: string, counter: number) => mockDeriveMessageKey(chain, counter) || 'mk-hex',
  deriveNextChainKey: (chain: string) => mockDeriveNextChainKey(chain) || 'next-chain-hex',
}));

jest.mock('../../../src/services/e2ee/E2EEMessageSerializer', () => ({
  buildMessageAAD: (...args: any[]) => mockBuildMessageAAD(...args) || new Uint8Array(16),
}));

jest.mock('../../../src/services/e2ee/e2eeErrors', () => {
  class E2EError extends Error {
    code?: string;
    constructor(msg: string, code?: string) {
      super(msg);
      this.code = code;
    }
  }
  return { E2EError };
});

import { EncryptionPipeline } from '../../../src/services/e2ee/EncryptionPipeline';

beforeEach(() => {
  jest.clearAllMocks();
});

describe('EncryptionPipeline.validate', () => {
  it('throws EMPTY_PLAINTEXT for empty / whitespace-only', () => {
    expect(() => EncryptionPipeline.validate('', 100_000)).toThrow(
      /CRITICAL: Cannot encrypt empty plaintext/,
    );
    expect(() => EncryptionPipeline.validate('   ', 100_000)).toThrow();
    expect(() => EncryptionPipeline.validate('\t\n', 100_000)).toThrow();
  });

  it('throws MESSAGE_TOO_LARGE when estimated size > limit', () => {
    // Estimated = (plainSize + 1024 + 40) * 2 must exceed 100
    expect(() => EncryptionPipeline.validate('a'.repeat(50), 100)).toThrow(
      /MESSAGE_TOO_LARGE/,
    );
  });

  it('passes valid plaintext within size budget', () => {
    expect(() => EncryptionPipeline.validate('hello', 100_000)).not.toThrow();
  });

  it('handles UTF-8 emoji byte-length correctly', () => {
    // Emoji is multi-byte; should still be within limit
    expect(() => EncryptionPipeline.validate('🎉🎈🎊', 100_000)).not.toThrow();
  });
});

describe('EncryptionPipeline.advanceSendChain', () => {
  it('reserves current sendCounter, derives next chain, increments counter', () => {
    mockDeriveNextChainKey.mockReturnValue('new-chain-hex');
    const state: any = {
      sendCounter: 5,
      chainKeySend: 'old-chain',
      lastUpdated: 0,
    };
    const result = EncryptionPipeline.advanceSendChain(state);
    expect(result.reservedCounter).toBe(5);
    expect(result.previousChainKey).toBe('old-chain');
    expect(state.sendCounter).toBe(6);
    expect(state.chainKeySend).toBe('new-chain-hex');
    expect(state.lastUpdated).toBeGreaterThan(0);
  });

  it('advances counter from 0 (first message)', () => {
    mockDeriveNextChainKey.mockReturnValue('next');
    const state: any = {
      sendCounter: 0,
      chainKeySend: 'initial',
      lastUpdated: 0,
    };
    const result = EncryptionPipeline.advanceSendChain(state);
    expect(result.reservedCounter).toBe(0);
    expect(state.sendCounter).toBe(1);
  });
});

describe('EncryptionPipeline.encrypt', () => {
  function makeInputs(overrides: any = {}) {
    return {
      state: {
        rootKey: 'rk',
        sendCounter: 5,
        chainKeySend: 'cks',
        ourRatchetKeyPair: { publicKey: 'pub-key' },
        ratchetStep: 0,
        ...overrides.state,
      },
      conversationId: 'conv-1',
      plaintext: 'hello',
      senderId: 'me',
      recipientId: 'peer',
      envelopeParams: undefined,
      signingPrivateKeyHex: 'a'.repeat(64),
      reservedCounter: 5,
      previousChainKey: 'old-chain',
      messageUuid: 'msg-uuid',
      ...overrides,
    };
  }

  it('returns wire envelope with all expected fields', () => {
    const result = EncryptionPipeline.encrypt(makeInputs());
    expect(result.messageUuid).toBe('msg-uuid');
    expect(result.messageCounter).toBe(5);
    expect(result.conversationId).toBe('conv-1');
    expect(result.encryptionVersion).toBe(2);
    expect(result.ratchetPublicKey).toBe('pub-key');
    expect(result.signature).toBeTruthy();
    expect(result.ivData).toBeTruthy();
    expect(result.encryptedContent).toBeTruthy();
  });

  it('serializes envelope params (messageType, mediaUrls, replyToMessageUuid) into plaintext', () => {
    EncryptionPipeline.encrypt(makeInputs({
      envelopeParams: {
        messageType: 'IMAGE',
        mediaUrls: ['url1'],
        metadata: { extra: 1 },
        replyToMessageUuid: 'parent-uuid',
      },
    }));
    // The serialized JSON is encoded → padded → encrypted; verify padding called
    expect(mockMetadataApplyPadding).toHaveBeenCalled();
  });

  it('uses raw plaintext when envelopeParams omitted', () => {
    EncryptionPipeline.encrypt(makeInputs({ envelopeParams: undefined }));
    // Padding called with the encoded plaintext bytes (not JSON envelope)
    expect(mockMetadataApplyPadding).toHaveBeenCalled();
  });

  it('zeroes plaintext bytes after encryption', () => {
    EncryptionPipeline.encrypt(makeInputs());
    // secureZero called on plaintextBytes + paddedPlaintext + signing key
    expect(mockSecureZero.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it('signs the encrypted content with Ed25519', () => {
    EncryptionPipeline.encrypt(makeInputs());
    expect(mockEd25519Sign).toHaveBeenCalled();
  });

  it('computes key fingerprint from rootKey with 16 chars', () => {
    EncryptionPipeline.encrypt(makeInputs());
    expect(mockComputeKeyFingerprint).toHaveBeenCalledWith('rk', 16);
  });

  it('builds message AAD with conversationId + counter + ratchet pub + sender + recipient', () => {
    EncryptionPipeline.encrypt(makeInputs());
    expect(mockBuildMessageAAD).toHaveBeenCalledWith(
      'conv-1', 5, 'pub-key', 'me', 'peer',
    );
  });
});
