import {
  hexToBytes,
  bytesToHex,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  ed25519Sign,
  ed25519Verify,
  secureZero,
} from '../SodiumCrypto';
import {
  decryptAESGCM,
  serializeCiphertext,
  deserializeCiphertext,
  ENCRYPTION_VERSION,
} from '../AuthenticatedEncryption';
import { deriveMessageKey, deriveNextChainKey } from './E2EEKeyDerivation';
import { MAX_ALLOWED_GROUP_COUNTER_GAP } from './GroupCounterReplayGuard';
import { E2EError } from './e2eeErrors';
import type { SenderKeyRecord, EncryptedMessage } from '../E2EEncryptionService.types';

export interface GroupEncryptInput {
  conversationId: string;
  plaintext: string;
  senderKeyRecord: SenderKeyRecord;
  signingPrivateKeyHex?: string;
  messageUuid: string;
}

export interface GroupEncryptResult {
  encryptedMessage: EncryptedMessage;
  nextChainKey: string;
}

export interface GroupDecryptInput {
  conversationId: string;
  senderKeyRecord: SenderKeyRecord;
  expectedSenderKeyId: number;
  encryptedContent: string;
  ivData: string;
  messageCounter: number;
  signature?: string;
  senderSigningKey?: string;
  requireSignature: boolean;
}

export interface GroupDecryptResult {
  plaintext: string;
  newChainKey: string;
  newCounter: number;
  /**
   * Message keys for every counter the fast-forward loop skipped
   * over (delivered-out-of-order gaps). The caller MUST park these in the
   * group skipped-key cache BEFORE persisting the advanced chain — once
   * the chain moves past them they are underivable (one-way KDF).
   */
  skippedKeys?: Array<{ counter: number; messageKeyHex: string }>;
}

/** Input for the cached-key decrypt path. No chain state is read or written. */
export interface GroupDecryptWithKeyInput {
  conversationId: string;
  senderKeyRecord: SenderKeyRecord;
  expectedSenderKeyId: number;
  encryptedContent: string;
  signature?: string;
  senderSigningKey?: string;
  requireSignature: boolean;
  messageKeyHex: string;
}

export class GroupMessageCipher {
  static encrypt(input: GroupEncryptInput): GroupEncryptResult {
    const messageKeyHex = deriveMessageKey(
      input.senderKeyRecord.senderKeyChainKey,
      input.senderKeyRecord.senderKeyNextId,
    );
    const messageKeyBytes = hexToBytes(messageKeyHex);
    const plaintextBytes = new TextEncoder().encode(input.plaintext);
    try {
      const aadBytes = new TextEncoder().encode(input.conversationId);
      const encrypted = encryptXChaCha20Poly1305(plaintextBytes, messageKeyBytes, aadBytes);
      const encryptedContent = JSON.stringify({
        v: ENCRYPTION_VERSION.XCHACHA20_POLY1305_V1,
        n: bytesToHex(encrypted.nonce),
        c: bytesToHex(encrypted.ciphertext),
        aad: 1,
      });
      const ivData = bytesToHex(encrypted.nonce);

      let signature: string | undefined;
      if (input.signingPrivateKeyHex) {
        const signingKey = hexToBytes(input.signingPrivateKeyHex);
        const contentToSign = new TextEncoder().encode(encryptedContent);
        const signatureBytes = ed25519Sign(contentToSign, signingKey);
        signature = bytesToHex(signatureBytes);
        secureZero(signingKey);
      }

      const nextChainKey = deriveNextChainKey(input.senderKeyRecord.senderKeyChainKey);

      return {
        nextChainKey,
        encryptedMessage: {
          messageUuid: input.messageUuid,
          encryptedContent,
          messageCounter: input.senderKeyRecord.senderKeyNextId,
          ivData,
          conversationId: input.conversationId,
          senderKeyId: input.senderKeyRecord.senderKeyId,
          encryptionVersion: ENCRYPTION_VERSION.XCHACHA20_POLY1305_V1,
          signature,
        },
      };
    } finally {
      secureZero(messageKeyBytes);
      secureZero(plaintextBytes);
    }
  }

  /**
   * keyId-equality + Ed25519 signature gate shared by `decrypt` and
   * `decryptWithMessageKey` — one implementation so the cached-key path can
   * never drift weaker than the forward path.
   */
  private static verifyKeyIdAndSignature(input: {
    senderKeyRecord: SenderKeyRecord;
    expectedSenderKeyId: number;
    encryptedContent: string;
    signature?: string;
    senderSigningKey?: string;
    requireSignature: boolean;
  }): void {
    if (input.senderKeyRecord.senderKeyId !== input.expectedSenderKeyId) {
      const error = new E2EError(
        'Group message key mismatch. Key rotation may have occurred.',
        'KEY_MISMATCH',
      );
      throw error;
    }

    if (input.signature && input.senderSigningKey) {
      const signingKeyBytes = hexToBytes(input.senderSigningKey);
      const signatureBytes = hexToBytes(input.signature);
      const contentToVerify = new TextEncoder().encode(input.encryptedContent);
      const isValid = ed25519Verify(contentToVerify, signatureBytes, signingKeyBytes);
      if (!isValid) {
        const error = new E2EError(
          'Group message signature verification failed.',
          'SIGNATURE_INVALID',
        );
        throw error;
      }
    } else if (input.requireSignature) {
      const error = new E2EError(
        'Group message signature verification required. Either signature or sender signing key is missing. Sender must be a pinned contact (TOFU) for group messages.',
        'SIGNATURE_REQUIRED',
      );
      (error as any).hasSignature = !!input.signature;
      (error as any).hasSenderKey = !!input.senderSigningKey;
      throw error;
    }
  }

  /**
   * Decrypt a group message body with an already-derived message key.
   * Runs the SAME keyId + signature gate as `decrypt` (shared
   * `verifyKeyIdAndSignature`) and NEVER reads or mutates chain state —
   * this is the consume path for keys parked by the skipped-key cache.
   */
  static async decryptWithMessageKey(input: GroupDecryptWithKeyInput): Promise<string> {
    GroupMessageCipher.verifyKeyIdAndSignature(input);
    return GroupMessageCipher.decryptBody(
      input.encryptedContent,
      input.conversationId,
      input.messageKeyHex,
    );
  }

  static async decrypt(input: GroupDecryptInput): Promise<GroupDecryptResult> {
    GroupMessageCipher.verifyKeyIdAndSignature(input);

    let chainKeyToUse = input.senderKeyRecord.senderKeyChainKey;
    let currentCounter = input.senderKeyRecord.senderKeyNextId;

    if (input.messageCounter < currentCounter) {
      if (__DEV__) {
        // Round-9 (H3): the silent-loss signature — wire counter BEHIND the
        // installed chain offset. Recoverability is decided upstream
        // (never-rendered check); this log makes the condition visible.
        console.warn(
          `⏮️ [GROUP] OUT_OF_ORDER — wire counter ${input.messageCounter} < installed nextId ${currentCounter} (keyId=${input.senderKeyRecord.senderKeyId})`,
        );
      }
      throw new E2EError('OUT_OF_ORDER: Group message already processed or too old.', 'OUT_OF_ORDER');
    }
    // Bound the fast-forward: a malicious or corrupt counter could otherwise
    // force unbounded KDF work. Mirrors the 1:1 lane's EXCESSIVE_GAP guard;
    // recoverable upstream via group rekey.
    if (input.messageCounter - currentCounter > MAX_ALLOWED_GROUP_COUNTER_GAP) {
      throw new E2EError(
        `Group counter gap ${input.messageCounter - currentCounter} exceeds maximum ${MAX_ALLOWED_GROUP_COUNTER_GAP}.`,
        'COUNTER_GAP_EXCEEDED',
      );
    }
    // Derive-and-KEEP each skipped counter's message key before advancing —
    // the old loop derived-then-discarded, which made any late-arriving body
    // behind the chain head permanently undecryptable.
    const skippedKeys: Array<{ counter: number; messageKeyHex: string }> = [];
    while (currentCounter < input.messageCounter) {
      skippedKeys.push({
        counter: currentCounter,
        messageKeyHex: deriveMessageKey(chainKeyToUse, currentCounter),
      });
      chainKeyToUse = deriveNextChainKey(chainKeyToUse);
      currentCounter++;
    }

    const messageKeyHex = deriveMessageKey(chainKeyToUse, input.messageCounter);
    const plaintext = await GroupMessageCipher.decryptBody(
      input.encryptedContent,
      input.conversationId,
      messageKeyHex,
    );

    return {
      plaintext,
      newChainKey: deriveNextChainKey(chainKeyToUse),
      newCounter: input.messageCounter + 1,
      skippedKeys,
    };
  }

  /** AEAD body decrypt shared by the forward and cached-key paths. */
  private static async decryptBody(
    encryptedContent: string,
    conversationId: string,
    messageKeyHex: string,
  ): Promise<string> {
    const messageKeyBytes = hexToBytes(messageKeyHex);
    let plaintext: string;
    try {
      let parsed: any = null;
      try {
        parsed = JSON.parse(encryptedContent);
      } catch {
        /* fall through to AES-GCM via deserializeCiphertext below */
      }

      if (parsed?.v === ENCRYPTION_VERSION.XCHACHA20_POLY1305_V1) {
        const nonce = hexToBytes(parsed.n);
        const ciphertext = hexToBytes(parsed.c);
        const aadBytes = parsed.aad ? new TextEncoder().encode(conversationId) : undefined;
        const plaintextBytes = decryptXChaCha20Poly1305(
          { nonce, ciphertext },
          messageKeyBytes,
          aadBytes,
        );
        plaintext = new TextDecoder().decode(plaintextBytes);
      } else if (parsed?.v === ENCRYPTION_VERSION.AES_GCM_V1) {
        const authenticatedCiphertext = deserializeCiphertext(encryptedContent);
        if (!authenticatedCiphertext) {
          throw new E2EError('Invalid AES-GCM ciphertext', 'KEY_MISMATCH');
        }
        plaintext = await decryptAESGCM(authenticatedCiphertext, messageKeyHex);
      } else {
        const authenticatedCiphertext = deserializeCiphertext(encryptedContent);
        if (authenticatedCiphertext) {
          try {
            plaintext = await decryptAESGCM(authenticatedCiphertext, messageKeyHex);
          } catch {
            throw new E2EError('Decryption failed - message may have been tampered', 'KEY_MISMATCH');
          }
        } else {
          throw new E2EError(
            'Legacy CBC encryption is no longer supported. Message must use authenticated encryption.',
            'LEGACY_ENCRYPTION_REJECTED',
          );
        }
      }
    } finally {
      secureZero(messageKeyBytes);
    }

    if (!plaintext) {
      throw new E2EError('Decryption failed (empty result). Key might be out of sync.', 'COUNTER_MISMATCH');
    }

    return plaintext;
  }
}
