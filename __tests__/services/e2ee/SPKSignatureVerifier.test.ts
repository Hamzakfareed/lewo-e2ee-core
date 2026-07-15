import { verifySPKSignature } from '@/src/services/e2ee/SPKSignatureVerifier';

const mockHexToBytes = jest.fn();
const mockEd25519Verify = jest.fn();

jest.mock('@/src/services/SodiumCrypto', () => ({
  hexToBytes: (...args: any[]) => mockHexToBytes(...args),
  ed25519Verify: (...args: any[]) => mockEd25519Verify(...args),
}));

beforeEach(() => {
  mockHexToBytes.mockReset();
  mockEd25519Verify.mockReset();
  mockHexToBytes.mockImplementation((hex: string) => `bytes(${hex})`);
});

const validBundle = {
  identityKey: 'idk',
  signedPreKey: 'spk',
  signature: 'a'.repeat(128),
  signingPublicKey: 'signpk',
};

describe('verifySPKSignature', () => {
  test('returns true when ed25519Verify says valid', () => {
    mockEd25519Verify.mockReturnValue(true);
    expect(verifySPKSignature(validBundle)).toBe(true);
    expect(mockEd25519Verify).toHaveBeenCalledWith(
      'bytes(spk)',
      `bytes(${validBundle.signature})`,
      'bytes(signpk)',
    );
  });

  test('returns false when ed25519Verify says invalid', () => {
    mockEd25519Verify.mockReturnValue(false);
    expect(verifySPKSignature(validBundle)).toBe(false);
  });

  test('returns false when signature is missing', () => {
    expect(verifySPKSignature({ ...validBundle, signature: undefined })).toBe(false);
    expect(mockEd25519Verify).not.toHaveBeenCalled();
  });

  test('returns false when identityKey is missing', () => {
    expect(verifySPKSignature({ ...validBundle, identityKey: undefined })).toBe(false);
  });

  test('returns false when signedPreKey is missing', () => {
    expect(verifySPKSignature({ ...validBundle, signedPreKey: undefined })).toBe(false);
  });

  test('returns false when signingPublicKey is missing', () => {
    expect(verifySPKSignature({ ...validBundle, signingPublicKey: undefined })).toBe(false);
  });

  test('returns false when signature is wrong length (not 128 hex chars)', () => {
    expect(
      verifySPKSignature({ ...validBundle, signature: 'a'.repeat(126) }),
    ).toBe(false);
    expect(
      verifySPKSignature({ ...validBundle, signature: 'a'.repeat(130) }),
    ).toBe(false);
  });

  test('returns false (not throws) on hexToBytes/ed25519Verify exceptions', () => {
    const errSpy = jest.spyOn(console, 'error').mockImplementation();
    try {
      mockHexToBytes.mockImplementation(() => {
        throw new Error('bad hex');
      });
      expect(verifySPKSignature(validBundle)).toBe(false);
    } finally {
      errSpy.mockRestore();
    }
  });
});
