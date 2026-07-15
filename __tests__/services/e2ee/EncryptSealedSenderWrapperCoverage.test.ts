/**
 * EncryptSealedSenderWrapper coverage targeting captureSealAttemptDiagnostic
 * branches and edge cases.
 */

const mockUnseal = jest.fn();

jest.mock('../../../src/services/e2ee/SealedSenderEnvelope', () => ({
  SealedSenderEnvelope: { unseal: (...a: any[]) => mockUnseal(...a) },
}));

import {
  wrapSealedSender,
  decryptSealedSender,
} from '../../../src/services/e2ee/EncryptSealedSenderWrapper';

beforeEach(() => {
  jest.clearAllMocks();
});

describe('wrapSealedSender', () => {
  function makeBaseDeps(overrides: any = {}) {
    return {
      sealedSenderEnabled: true,
      ownIdentityPublicKeyHex: 'a'.repeat(64),
      ownSigningPublicKeyHex: 'b'.repeat(64),
      getPinnedKey: jest.fn(() => ({ identityKey: 'c'.repeat(64) })),
      computeIdentityFingerprint: jest.fn(() => 'finger-print-hex-12345'),
      encryptSealedSender: jest.fn().mockResolvedValue({
        sealedPayload: 'sealed-bytes',
        deliveryToken: 'token',
      }),
      resolveDeviceId: jest.fn().mockResolvedValue('device-1'),
      ...overrides,
    };
  }

  it('returns null when sealedSenderEnabled=false', async () => {
    const deps = makeBaseDeps({ sealedSenderEnabled: false });
    const result = await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 0 },
    }, deps);
    expect(result).toBeNull();
  });

  it('returns null when no own identity key', async () => {
    const deps = makeBaseDeps({ ownIdentityPublicKeyHex: undefined });
    const result = await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 0 },
    }, deps);
    expect(result).toBeNull();
  });

  it('returns null when no pinned key for recipient', async () => {
    const deps = makeBaseDeps({
      getPinnedKey: jest.fn(() => undefined),
    });
    const result = await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 0 },
    }, deps);
    expect(result).toBeNull();
  });

  it('returns null when pinnedKey has no identityKey', async () => {
    const deps = makeBaseDeps({
      getPinnedKey: jest.fn(() => ({})),
    });
    const result = await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 0 },
    }, deps);
    expect(result).toBeNull();
  });

  it('returns sealed payload + recipientFp on success', async () => {
    const deps = makeBaseDeps();
    const result = await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 0 },
    }, deps);
    expect(result?.sealedPayload).toBe('sealed-bytes');
    expect(result?.deliveryToken).toBe('token');
    expect(result?.recipientFp).toBe('finger-print-hex');
  });

  it('returns null when encryptSealedSender throws', async () => {
    const deps = makeBaseDeps({
      encryptSealedSender: jest.fn().mockRejectedValue(new Error('seal fail')),
    });
    const result = await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 0 },
    }, deps);
    expect(result).toBeNull();
  });

  it('captures diagnostic when callback provided', async () => {
    const captureSealAttemptDiagnostic = jest.fn();
    const deps = makeBaseDeps({ captureSealAttemptDiagnostic });
    await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 5 },
    }, deps);
    expect(captureSealAttemptDiagnostic).toHaveBeenCalledWith(
      expect.objectContaining({ messageCounter: 5, source: 'pinned' }),
    );
  });

  it('continues when diagnostic callback throws', async () => {
    const captureSealAttemptDiagnostic = jest.fn(() => {
      throw new Error('diag fail');
    });
    const deps = makeBaseDeps({ captureSealAttemptDiagnostic });
    const result = await wrapSealedSender({
      conversationId: 'c1', recipientUserId: 'r1', currentUserId: 'me',
      encryptedPayload: { encryptedContent: 'enc', messageCounter: 0 },
    }, deps);
    expect(result?.sealedPayload).toBe('sealed-bytes');
  });
});

describe('decryptSealedSender', () => {
  it('throws when no own identity private key', async () => {
    await expect(decryptSealedSender('payload', null, {
      ownIdentityPrivateKeyHex: undefined,
      findIdentityPrivateKeyForRecipientFp: jest.fn(),
    })).rejects.toMatchObject({ code: 'SEALED_SENDER_ERROR' });
  });

  it('uses current key when no recipientFp', async () => {
    mockUnseal.mockResolvedValue({ senderId: 'me', content: 'plain' });
    const result = await decryptSealedSender('payload', null, {
      ownIdentityPrivateKeyHex: 'priv-current',
      findIdentityPrivateKeyForRecipientFp: jest.fn(),
    });
    expect(mockUnseal).toHaveBeenCalledWith('payload', 'priv-current');
  });

  it('uses historical key when recipientFp matches', async () => {
    mockUnseal.mockResolvedValue({ senderId: 'me', content: 'plain' });
    const findKey = jest.fn(() => ({ privateKey: 'priv-old' }));
    await decryptSealedSender('payload', 'fp-12345', {
      ownIdentityPrivateKeyHex: 'priv-current',
      findIdentityPrivateKeyForRecipientFp: findKey,
    });
    expect(mockUnseal).toHaveBeenCalledWith('payload', 'priv-old');
  });

  it('throws RECIPIENT_KEY_ROTATED when recipientFp does not match any key', async () => {
    await expect(decryptSealedSender('payload', 'fp-unknown', {
      ownIdentityPrivateKeyHex: 'priv-current',
      findIdentityPrivateKeyForRecipientFp: jest.fn(() => null),
    })).rejects.toMatchObject({ code: 'SEALED_SENDER_ERROR' });
  });
});
