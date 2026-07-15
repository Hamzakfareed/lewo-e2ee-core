/**
 * ChannelPostCipher tests — basic round-trip encrypt/decrypt and signature
 * tampering detection. All crypto primitives are stubbed.
 */

const sodiumMocks = {
  ed25519Sign: jest.fn(() => new Uint8Array([1, 2, 3])),
  ed25519Verify: jest.fn(() => true),
  encryptXChaCha20Poly1305: jest.fn((bytes: Uint8Array, _key: Uint8Array) => ({
    ciphertext: new Uint8Array([0xAA, ...bytes]),
    nonce: new Uint8Array([0x11, 0x22]),
  })),
  decryptXChaCha20Poly1305: jest.fn((ciphertext: Uint8Array) => ciphertext.slice(1)),
  bytesToHex: jest.fn((b: Uint8Array) => Buffer.from(b).toString('hex')),
  hexToBytes: jest.fn((s: string) => new Uint8Array(Buffer.from(s, 'hex'))),
  hash256: jest.fn(() => new Uint8Array([7, 7, 7])),
  secureZero: jest.fn(),
};

jest.mock('@/src/services/SodiumCrypto', () => sodiumMocks);

import {
  encryptChannelPostBody,
  decryptChannelPostBody,
} from '@/src/services/e2ee/ChannelPostCipher';

beforeEach(() => {
  Object.values(sodiumMocks).forEach((fn: any) => fn.mockClear?.());
});

describe('encryptChannelPostBody', () => {
  test('produces an encrypted envelope + signature for valid input', () => {
    const out = encryptChannelPostBody({
      postContentJson: '{"text":"hi"}',
      messageKeyHex: 'aa'.repeat(32),
      signingPrivateKeyHex: 'bb'.repeat(32),
      encryptionVersion: 2,
    });
    expect(out.signature).toBe('010203');
    expect(JSON.parse(out.encryptedContent)).toMatchObject({ v: 2 });
    expect(out.encryptedMediaKeys).toBeUndefined();
  });

  test('attaches encrypted media keys when provided', () => {
    const out = encryptChannelPostBody({
      postContentJson: '{"text":"hi"}',
      messageKeyHex: 'aa'.repeat(32),
      signingPrivateKeyHex: 'bb'.repeat(32),
      mediaKeys: ['k1', 'k2'],
      encryptionVersion: 2,
    });
    expect(out.encryptedMediaKeys).toBeDefined();
    const env = JSON.parse(out.encryptedMediaKeys!);
    expect(env.n).toBeDefined();
    expect(env.c).toBeDefined();
  });
});

describe('decryptChannelPostBody', () => {
  test('returns plaintext + media keys on successful verify', () => {
    sodiumMocks.ed25519Verify.mockReturnValue(true);
    sodiumMocks.decryptXChaCha20Poly1305
      .mockImplementationOnce((ct: Uint8Array) => new TextEncoder().encode('{"text":"hi"}'))
      .mockImplementationOnce(() => new TextEncoder().encode(JSON.stringify(['m1'])));

    const result = decryptChannelPostBody({
      encryptedContent: { n: 'aa', c: 'bb' },
      encryptedMediaKeys: JSON.stringify({ n: 'cc', c: 'dd' }),
      messageKeyHex: 'ee'.repeat(32),
      signatureHex: 'ff',
      signingPublicKeyHex: 'aa'.repeat(32),
    });

    expect(result.postContentJson).toBe('{"text":"hi"}');
    expect(result.mediaKeys).toEqual(['m1']);
  });

  test('throws when signature verification fails', () => {
    sodiumMocks.ed25519Verify.mockReturnValue(false);
    expect(() =>
      decryptChannelPostBody({
        encryptedContent: { n: 'aa', c: 'bb' },
        messageKeyHex: 'ee'.repeat(32),
        signatureHex: 'ff',
        signingPublicKeyHex: 'aa'.repeat(32),
      })
    ).toThrow(/signature verification failed/i);
  });

  test('skips media keys when not provided', () => {
    sodiumMocks.ed25519Verify.mockReturnValue(true);
    sodiumMocks.decryptXChaCha20Poly1305.mockImplementationOnce(
      () => new TextEncoder().encode('{"a":1}')
    );
    const result = decryptChannelPostBody({
      encryptedContent: { n: 'aa', c: 'bb' },
      messageKeyHex: 'ee'.repeat(32),
      signatureHex: 'ff',
      signingPublicKeyHex: 'aa'.repeat(32),
    });
    expect(result.postContentJson).toBe('{"a":1}');
    expect(result.mediaKeys).toBeUndefined();
  });
});
