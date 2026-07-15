import {
  bytesToHex,
  hexToBytes,
  ed25519Sign,
  encryptXChaCha20Poly1305,
  secureZero,
} from '../SodiumCrypto';
import { hexToBase64 } from '../../utils/keyEncodingConverter';
import type { ConversationState, EncryptedMessage } from '../E2EEncryptionService.types';
import type { EncryptedMetadataPayload } from './MetadataCipher';
import { E2EError } from './e2eeErrors';
import { MetadataCipher } from './MetadataCipher';
import { computeKeyFingerprint } from './E2EEFingerprint';
import { deriveMessageKey, deriveNextChainKey } from './E2EEKeyDerivation';
import { buildMessageAAD } from './E2EEMessageSerializer';

const ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1 = 2;

export interface EnvelopeParams {
  messageType?: string;
  mediaUrls?: string[] | null;
  metadata?: Record<string, unknown> | null;
  replyToMessageUuid?: string | null;
}

export interface EncryptInput {
  state: ConversationState;
  conversationId: string;
  plaintext: string;
  senderId: string;
  recipientId: string;
  envelopeParams?: EnvelopeParams;
  signingPrivateKeyHex: string;
  reservedCounter: number;
  previousChainKey: string;
  messageUuid: string;
}

export class EncryptionPipeline {
  /**
   * Pure-ish encrypt step: derives the message key from the input chain key
   * and counter, applies padding + AAD, runs XChaCha20-Poly1305 + Ed25519
   * signature, returns the wire envelope. Counter advancement and
   * persistence are the caller's responsibility (write-ahead pattern).
   */
  static encrypt(input: EncryptInput): EncryptedMessage {
    const {
      state,
      conversationId,
      plaintext,
      senderId,
      recipientId,
      envelopeParams,
      signingPrivateKeyHex,
      reservedCounter,
      previousChainKey,
      messageUuid,
    } = input;

    const messageKeyHex = deriveMessageKey(previousChainKey, reservedCounter);
    const plaintextToEncrypt = envelopeParams
      ? JSON.stringify({
          v: 2,
          t: envelopeParams.messageType || 'TEXT',
          c: plaintext,
          m: envelopeParams.mediaUrls || null,
          meta: envelopeParams.metadata || null,
          replyTo: envelopeParams.replyToMessageUuid || null,
        })
      : plaintext;

    const messageKeyBytes = hexToBytes(messageKeyHex);
    const plaintextBytes = new TextEncoder().encode(plaintextToEncrypt);
    const paddedPlaintext = MetadataCipher.applyPadding(plaintextBytes);

    let encryptedContent: string;
    let ivData: string;
    try {
      const aad = buildMessageAAD(
        conversationId,
        reservedCounter,
        state.ourRatchetKeyPair?.publicKey,
        senderId,
        recipientId,
      );
      const encrypted = encryptXChaCha20Poly1305(paddedPlaintext, messageKeyBytes, aad);
      encryptedContent = JSON.stringify({
        v: ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1,
        n: bytesToHex(encrypted.nonce),
        c: bytesToHex(encrypted.ciphertext),
      });
      ivData = bytesToHex(encrypted.nonce);
    } finally {
      secureZero(plaintextBytes);
      secureZero(paddedPlaintext);
    }

    const signingKey = hexToBytes(signingPrivateKeyHex);
    const signatureBytes = ed25519Sign(new TextEncoder().encode(encryptedContent), signingKey);
    const signature = hexToBase64(bytesToHex(signatureBytes));
    secureZero(signingKey);

    const metadata: EncryptedMetadataPayload = {
      senderId,
      messageType: 'TEXT',
      timestamp: Date.now(),
    };
    const encryptedMetadata = MetadataCipher.encryptMetadata(metadata, messageKeyHex);
    secureZero(messageKeyBytes);

    // Anchor on the session's X3DH root, not the live root: a `dh` session
    // ratchets the root on every reply, so a live-root fingerprint would never
    // match the peer's. `legacy` states carry no anchor and keep the old value.
    // `dh` ratchets the root on every reply, so the two ends' live roots are
    // deliberately one step apart — a live-root fingerprint could never match.
    // Anchor those sessions on the immutable X3DH root instead. `legacy` sessions
    // keep the live root (which never advances), byte-for-byte as before.
    const keyFingerprint =
      state.ratchetMode === 'dh' && state.x3dhRootKeyFingerprint
        ? state.x3dhRootKeyFingerprint
        : computeKeyFingerprint(state.rootKey, 16);

    return {
      messageUuid,
      encryptedContent,
      messageCounter: reservedCounter,
      keyFingerprint,
      ivData,
      conversationId,
      encryptionVersion: ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1,
      ratchetPublicKey: state.ourRatchetKeyPair?.publicKey,
      ratchetStep: state.ratchetStep,
      encryptedMetadata,
      signature,
    };
  }

  /**
   * Validate plaintext and estimate encrypted size. Throws structured E2EError
   * for empty plaintext or too-large messages. Caller invokes BEFORE counter
   * reservation so a failed validation doesn't burn a counter slot.
   */
  static validate(plaintext: string, maxBytes: number): void {
    if (!plaintext || plaintext.trim() === '') {
      throw new E2EError('CRITICAL: Cannot encrypt empty plaintext', 'EMPTY_PLAINTEXT');
    }
    const plaintextSize = new TextEncoder().encode(plaintext).length;
    // padding (≤PADDING_BLOCK_SIZE) + nonce (24) + tag (16); hex doubles size
    const estimatedEncryptedSize = (plaintextSize + 1024 + 40) * 2;
    if (estimatedEncryptedSize > maxBytes) {
      throw new E2EError(
        `MESSAGE_TOO_LARGE: Estimated encrypted size ${estimatedEncryptedSize} bytes exceeds maximum`,
        'MESSAGE_TOO_LARGE',
      );
    }
  }

  /**
   * Advance the chain key + counter on the state. Persisted by the caller
   * BEFORE encryption (write-ahead — a crash after persist but before encrypt
   * just wastes a counter slot, harmless).
   */
  static advanceSendChain(state: ConversationState): { reservedCounter: number; previousChainKey: string } {
    const reservedCounter = state.sendCounter;
    const previousChainKey = state.chainKeySend;
    state.chainKeySend = deriveNextChainKey(state.chainKeySend);
    state.sendCounter++;
    state.lastUpdated = Date.now();
    return { reservedCounter, previousChainKey };
  }
}
