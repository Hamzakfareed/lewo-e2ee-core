import {
  wrapSealedSender,
  decryptSealedSender,
} from '@/src/services/e2ee/EncryptSealedSenderWrapper';

jest.mock('@/src/services/e2ee/SealedSenderEnvelope', () => ({
  SealedSenderEnvelope: {
    unseal: jest.fn(),
  },
}));

import { SealedSenderEnvelope } from '@/src/services/e2ee/SealedSenderEnvelope';

const mockUnseal = SealedSenderEnvelope.unseal as jest.MockedFunction<
  typeof SealedSenderEnvelope.unseal
>;

const baseInputs = () => ({
  conversationId: 'conv-1',
  recipientUserId: 'bob',
  currentUserId: 'alice',
  encryptedPayload: {
    encryptedContent: 'cipher',
    messageCounter: 5,
  },
});

const baseDeps = () => ({
  sealedSenderEnabled: true,
  ownIdentityPublicKeyHex: 'aabb',
  ownSigningPublicKeyHex: 'ccdd',
  getPinnedKey: jest.fn().mockReturnValue({ identityKey: 'recipient-key' }),
  computeIdentityFingerprint: jest.fn().mockReturnValue('0123456789abcdef0000000000000000'),
  encryptSealedSender: jest
    .fn()
    .mockResolvedValue({ sealedPayload: 'sp', deliveryToken: 'dt' }),
  resolveDeviceId: jest.fn().mockResolvedValue('dev-1'),
});

describe('wrapSealedSender', () => {
  test('returns null when sealed-sender is disabled', async () => {
    const out = await wrapSealedSender(baseInputs(), {
      ...baseDeps(),
      sealedSenderEnabled: false,
    });
    expect(out).toBeNull();
  });

  test('returns null when no pinned identity key for recipient is available', async () => {
    const out = await wrapSealedSender(baseInputs(), {
      ...baseDeps(),
      getPinnedKey: jest.fn().mockReturnValue(undefined),
    });
    expect(out).toBeNull();
  });

  test('returns sealed payload + 16-char recipient fingerprint on success', async () => {
    const deps = baseDeps();

    const out = await wrapSealedSender(baseInputs(), deps);

    expect(out).toEqual({
      sealedPayload: 'sp',
      deliveryToken: 'dt',
      recipientFp: '0123456789abcdef',
    });
    expect(deps.encryptSealedSender).toHaveBeenCalledTimes(1);
    const [payload, recipientKey, senderInfo] = deps.encryptSealedSender.mock.calls[0];
    expect(payload.conversationId).toBe('conv-1');
    expect(recipientKey).toBe('recipient-key');
    expect(senderInfo.deviceId).toBe('dev-1');
    expect(senderInfo.identityKeyHex).toBe('aabb');
  });
});

describe('decryptSealedSender', () => {
  beforeEach(() => {
    mockUnseal.mockReset();
  });

  test('throws SEALED_SENDER_ERROR when our identity private key is missing', async () => {
    await expect(
      decryptSealedSender('payload', null, {
        ownIdentityPrivateKeyHex: undefined,
        findIdentityPrivateKeyForRecipientFp: jest.fn(),
      }),
    ).rejects.toMatchObject({ code: 'SEALED_SENDER_ERROR' });
  });

  test('throws when recipientFp does not match any of our identity keys', async () => {
    await expect(
      decryptSealedSender('payload', 'fp', {
        ownIdentityPrivateKeyHex: 'priv',
        findIdentityPrivateKeyForRecipientFp: jest.fn().mockReturnValue(null),
      }),
    ).rejects.toMatchObject({ code: 'SEALED_SENDER_ERROR' });
  });

  test('uses the matching historical private key when recipientFp is provided', async () => {
    mockUnseal.mockResolvedValue('inner-payload' as any);
    const find = jest.fn().mockReturnValue({ privateKey: 'old-priv' });

    const out = await decryptSealedSender('payload', 'fp', {
      ownIdentityPrivateKeyHex: 'current-priv',
      findIdentityPrivateKeyForRecipientFp: find,
    });

    expect(out).toBe('inner-payload');
    expect(mockUnseal).toHaveBeenCalledWith('payload', 'old-priv');
  });
});
