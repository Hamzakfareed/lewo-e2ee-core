import { SealedSenderEnvelope } from './SealedSenderEnvelope';
import { E2EError } from './e2eeErrors';

interface PinnedKeyView {
  identityKey?: string;
}

export interface SealedSenderEncryptedPayload {
  encryptedContent: string;
  messageCounter: number;
  ratchetHeader?: string;
  keyFingerprint?: string;
  ratchetPublicKey?: string;
  ratchetStep?: number;
  signature?: string;
  ephemeralKey?: string;
  usedSignedPreKeyId?: number;
  usedOneTimePreKeyId?: number;
  dhCount?: number;
}

export interface WrapSealedSenderInputs {
  conversationId: string;
  recipientUserId: string;
  currentUserId: string;
  encryptedPayload: SealedSenderEncryptedPayload;
}

export interface WrapSealedSenderDeps {
  sealedSenderEnabled: boolean;
  ownIdentityPublicKeyHex?: string;
  ownSigningPublicKeyHex?: string;
  getPinnedKey: (recipientUserId: string) => PinnedKeyView | undefined;
  computeIdentityFingerprint: (identityKey: string) => string;
  encryptSealedSender: (
    payload: SealedSenderEncryptedPayload & { conversationId: string },
    recipientIdentityKeyHex: string,
    senderInfo: {
      userId: string;
      deviceId: string;
      identityKeyHex: string;
      signingPublicKeyHex?: string;
    },
  ) => Promise<{ sealedPayload: string; deliveryToken: string }>;
  resolveDeviceId: () => Promise<string>;
  captureSealAttemptDiagnostic?: (info: {
    conversationId: string;
    senderId: string;
    recipientId: string;
    messageCounter: number;
    recipientIdentityKeyHex: string;
    senderOwnIdentityHex: string | null;
    source: string;
  }) => void;
}

/**
 * Builds a sealed-sender envelope around an already-Double-Ratchet-encrypted
 * one-to-one payload. Returns `null` (rather than throwing) when:
 *
 *  - sealed-sender is disabled by the security config,
 *  - we don't yet have our own identity key,
 *  - we have no pinned identity key for the recipient,
 *  - or the underlying SealedSenderEnvelope.seal() throws (network /
 *    crypto failure, etc).
 *
 * On success returns `{ sealedPayload, deliveryToken, recipientFp }`
 * where `recipientFp` is the truncated (16-hex) fingerprint of the
 * recipient's pinned identity key — used as the routing key for the
 * server-side fan-out.
 *
 * Pulled out of `E2EEncryptionService.wrapSealedSender` so the
 * orchestrator only owns the dependency wiring; the
 * pinned-key-lookup + fingerprint-derivation + diagnostic-emit
 * sequence lives here.
 */
export async function wrapSealedSender(
  inputs: WrapSealedSenderInputs,
  deps: WrapSealedSenderDeps,
): Promise<{ sealedPayload: string; deliveryToken: string; recipientFp: string } | null> {
  if (!deps.sealedSenderEnabled) return null;
  if (!deps.ownIdentityPublicKeyHex) return null;

  const pinnedKey = deps.getPinnedKey(inputs.recipientUserId);
  if (!pinnedKey?.identityKey) return null;

  const recipientFp = deps.computeIdentityFingerprint(pinnedKey.identityKey).slice(0, 16);

  try {
    const deviceId = await deps.resolveDeviceId();

    if (deps.captureSealAttemptDiagnostic) {
      try {
        deps.captureSealAttemptDiagnostic({
          conversationId: inputs.conversationId,
          senderId: inputs.currentUserId,
          recipientId: inputs.recipientUserId,
          messageCounter: inputs.encryptedPayload.messageCounter,
          recipientIdentityKeyHex: pinnedKey.identityKey,
          senderOwnIdentityHex: deps.ownIdentityPublicKeyHex,
          source: 'pinned',
        });
      } catch {
        /* never throw from diagnostic */
      }
    }

    const sealResult = await deps.encryptSealedSender(
      { conversationId: inputs.conversationId, ...inputs.encryptedPayload },
      pinnedKey.identityKey,
      {
        userId: inputs.currentUserId,
        deviceId,
        identityKeyHex: deps.ownIdentityPublicKeyHex,
        signingPublicKeyHex: deps.ownSigningPublicKeyHex,
      },
    );
    return { ...sealResult, recipientFp };
  } catch {
    return null;
  }
}

export interface DecryptSealedSenderDeps {
  ownIdentityPrivateKeyHex?: string;
  findIdentityPrivateKeyForRecipientFp: (
    recipientFp: string,
  ) => { privateKey: string } | null;
}

/**
 * Decrypts a sealed-sender envelope. Picks which of our identity keys
 * to use:
 *
 *  - If `recipientFp` was provided, looks up the matching key from
 *    history (current + previous identity keys). This handles the
 *    case where the sender encrypted to an older identity key while
 *    we were rotating.
 *  - Otherwise falls back to the current identity key.
 *
 * Throws SEALED_SENDER_ERROR when no usable private key is found.
 *
 * Pulled out of `E2EEncryptionService.decryptSealedSender` so the
 * orchestrator only owns the dependency wiring.
 */
export async function decryptSealedSender(
  sealedPayload: string,
  recipientFp: string | null | undefined,
  deps: DecryptSealedSenderDeps,
): Promise<ReturnType<typeof SealedSenderEnvelope.unseal>> {
  if (!deps.ownIdentityPrivateKeyHex) {
    throw new E2EError(
      'SEALED_SENDER_ERROR: No identity key pair available for decryption',
      'SEALED_SENDER_ERROR',
    );
  }
  let recipientPrivateKeyHex = deps.ownIdentityPrivateKeyHex;
  if (recipientFp && typeof recipientFp === 'string') {
    const match = deps.findIdentityPrivateKeyForRecipientFp(recipientFp);
    if (!match) {
      throw new E2EError(
        'SEALED_SENDER_ERROR: RECIPIENT_KEY_ROTATED — sender encrypted to an identity key we no longer hold',
        'SEALED_SENDER_ERROR',
      );
    }
    recipientPrivateKeyHex = match.privateKey;
  }
  return SealedSenderEnvelope.unseal(sealedPayload, recipientPrivateKeyHex);
}
