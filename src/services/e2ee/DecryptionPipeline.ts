import {
  hexToBytes,
  bytesToHex,
  decryptXChaCha20Poly1305,
  secureZero,
} from '../SodiumCrypto';
import { E2EError } from './e2eeErrors';
import { buildMessageAAD } from './E2EEMessageSerializer';
import { MetadataCipher } from './MetadataCipher';
import { deriveMessageKey, deriveNextChainKey } from './E2EEKeyDerivation';

const ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1 = 2;

export interface DecryptInputValidationOptions {
  maxMessageSizeBytes: number;
  maxFutureTimestampMs: number;
  maxMessageAgeMs: number;
}

export class DecryptionPipeline {
  /**
   * Coerce + validate the wire-side message inputs. Throws structured
   * E2EError with the specific failure code; caller decides on the
   * recovery path. Side-effect free.
   */
  static validateInputs(
    messageCounter: unknown,
    encryptedContent: string,
    ivData: string,
    messageSentAt: string | undefined,
    options: DecryptInputValidationOptions,
  ): number {
    if (messageCounter === undefined || messageCounter === null) {
      throw new E2EError('INVALID_COUNTER: messageCounter is required', 'INVALID_COUNTER');
    }
    const counter =
      typeof messageCounter === 'string' ? Number(messageCounter) : (messageCounter as number);
    if (!Number.isInteger(counter) || counter < 0) {
      throw new E2EError(
        `INVALID_COUNTER: messageCounter must be a non-negative integer, got: ${messageCounter}`,
        'INVALID_COUNTER',
      );
    }

    const encodedSize = encryptedContent.length + ivData.length;
    if (encodedSize > options.maxMessageSizeBytes) {
      throw new E2EError(
        `MESSAGE_TOO_LARGE: Message size ${encodedSize} exceeds maximum ${options.maxMessageSizeBytes}`,
        'MESSAGE_TOO_LARGE',
      );
    }

    if (messageSentAt) {
      const messageTime = new Date(messageSentAt).getTime();
      const now = Date.now();
      // NaN guard: `NaN > X` and `X > NaN` are both false, so without this
      // a malformed timestamp would silently bypass replay protection.
      if (Number.isNaN(messageTime)) {
        throw new E2EError(
          `INVALID_TIMESTAMP: messageSentAt '${messageSentAt}' is not a valid date`,
          'INVALID_TIMESTAMP',
        );
      }
      if (messageTime > now + options.maxFutureTimestampMs) {
        throw new E2EError(
          `FUTURE_MESSAGE: Message timestamp ${messageSentAt} is too far in the future`,
          'FUTURE_MESSAGE',
        );
      }
      if (now - messageTime > options.maxMessageAgeMs) {
        throw new E2EError(
          `EXPIRED_MESSAGE: Message timestamp ${messageSentAt} is too old (>${options.maxMessageAgeMs / (24 * 60 * 60 * 1000)} days)`,
          'EXPIRED_MESSAGE',
        );
      }
    }

    return counter;
  }

  /**
   * Decrypt an XChaCha20-Poly1305 v1 envelope using the supplied message
   * key. Tries the V2 AAD (with sender + recipient userIds) first, then
   * falls back to V1 (no userIds) so messages from older senders still
   * decrypt. Both formats authenticate conv/counter/ratchetKey — the V1
   * fallback only relaxes the user-id binding, never the rest of the
   * header. NEVER falls back to no-AAD: that would let an attacker swap
   * conv/counter/ratchetKey undetected.
   */
  static decryptWithMessageKey(args: {
    parsedEnvelope: { v: number; n: string; c: string };
    messageKeyBytes: Uint8Array;
    conversationId: string;
    messageCounter: number;
    ratchetPublicKey?: string;
    senderId: string;
    recipientId: string;
  }): Uint8Array {
    const { parsedEnvelope, messageKeyBytes, conversationId, messageCounter, ratchetPublicKey, senderId, recipientId } = args;
    if (parsedEnvelope.v !== ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1) {
      throw new E2EError(
        `UNSUPPORTED_ENCRYPTION_VERSION: ${parsedEnvelope.v}`,
        'UNSUPPORTED_ENCRYPTION_VERSION',
      );
    }
    const nonceBytes = hexToBytes(parsedEnvelope.n);
    const ciphertextBytes = hexToBytes(parsedEnvelope.c);
    const aadV2 = buildMessageAAD(
      conversationId,
      messageCounter,
      ratchetPublicKey,
      senderId,
      recipientId,
    );
    try {
      return decryptXChaCha20Poly1305(
        { nonce: nonceBytes, ciphertext: ciphertextBytes },
        messageKeyBytes,
        aadV2,
      );
    } catch {
      const aadV1 = buildMessageAAD(conversationId, messageCounter, ratchetPublicKey);
      return decryptXChaCha20Poly1305(
        { nonce: nonceBytes, ciphertext: ciphertextBytes },
        messageKeyBytes,
        aadV1,
      );
    }
  }

  /**
   * Decrypt + remove padding + unwrap the v2 envelope (if present) in one
   * step. Returns the inner content string and any envelope metadata.
   * Throws on AAD failure or padding failure — caller decides how to
   * recover (e.g. roll back ratchet, request resend).
   */
  static finalizePlaintext(paddedPlaintextBytes: Uint8Array): {
    plaintext: string;
    envelope: ReturnType<typeof MetadataCipher.unwrapEnvelope>['envelope'];
  } {
    const plaintextBytes = MetadataCipher.removePadding(paddedPlaintextBytes);
    const rawPlaintext = new TextDecoder().decode(plaintextBytes);
    const { content, envelope } = MetadataCipher.unwrapEnvelope(rawPlaintext);
    return { plaintext: content, envelope };
  }

  /** Cache key shape for the in-memory dedup of decrypted messages. */
  static cacheKey(conversationId: string, messageCounter: number, contentHash: string): string {
    return `${conversationId}:${messageCounter}:${contentHash}`;
  }

  /**
   * Decrypt an out-of-order message using a previously-stored skipped
   * message key. Tries XChaCha20-Poly1305 first, then AES-GCM. Returns
   * the padded plaintext bytes (XChaCha) or the unwrapped plaintext
   * string (AES-GCM) wrapped in a tagged result, or null if neither
   * format succeeds. Caller is responsible for the final padding-strip
   * + envelope-unwrap on the XChaCha branch.
   */
  static async tryDecryptWithSkippedKey(args: {
    encryptedContent: string;
    messageKeyHex: string;
    conversationId: string;
    messageCounter: number;
    ratchetPublicKey?: string;
    senderId: string;
    recipientId: string;
    decryptAESGCM: (authenticatedCiphertext: any, messageKeyHex: string) => Promise<string>;
    deserializeCiphertext: (encryptedContent: string) => any;
    aesGcmVersion: number;
  }): Promise<{ kind: 'xchacha'; padded: Uint8Array } | { kind: 'aesgcm'; plaintext: string } | null> {
    const messageKeyBytes = hexToBytes(args.messageKeyHex);
    let parsed: any = null;
    try {
      parsed = JSON.parse(args.encryptedContent);
    } catch {
      /* fall through to AES-GCM attempt */
    }

    if (parsed && parsed.v === ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1) {
      try {
        const padded = DecryptionPipeline.decryptWithMessageKey({
          parsedEnvelope: parsed,
          messageKeyBytes,
          conversationId: args.conversationId,
          messageCounter: args.messageCounter,
          ratchetPublicKey: args.ratchetPublicKey,
          senderId: args.senderId,
          recipientId: args.recipientId,
        });
        secureZero(messageKeyBytes);
        return { kind: 'xchacha', padded };
      } catch (err) {
        secureZero(messageKeyBytes);
        throw err;
      }
    }

    const authenticatedCiphertext = args.deserializeCiphertext(args.encryptedContent);
    if (authenticatedCiphertext && authenticatedCiphertext.version === args.aesGcmVersion) {
      try {
        const rawPlaintext = await args.decryptAESGCM(authenticatedCiphertext, args.messageKeyHex);
        secureZero(messageKeyBytes);
        return { kind: 'aesgcm', plaintext: rawPlaintext };
      } catch (err) {
        secureZero(messageKeyBytes);
        throw err;
      }
    }
    secureZero(messageKeyBytes);
    return null;
  }

  /**
   * Walk the previousSession chain forward to a target counter and try
   * to decrypt the supplied envelope. Used as a last-resort fallback
   * after the current chain failed (e.g. after a DH ratchet step that
   * happened in the middle of an in-flight message). Returns the raw
   * padded plaintext bytes on success; null if the walk fails or the
   * AAD doesn't match. Caller still has to remove padding + unwrap.
   */
  static tryPreviousSessionFallback(args: {
    parsedEnvelope: { v: number; n: string; c: string };
    previousChainKeyReceive: string;
    previousReceiveCounter: number;
    targetCounter: number;
    conversationId: string;
    ratchetPublicKey?: string;
    senderId: string;
    recipientId: string;
    maxWalk?: number;
  }): Uint8Array | null {
    const {
      parsedEnvelope,
      previousChainKeyReceive,
      previousReceiveCounter,
      targetCounter,
      conversationId,
      ratchetPublicKey,
      senderId,
      recipientId,
    } = args;
    const MAX_WALK = args.maxWalk ?? 1000;

    if (!previousChainKeyReceive || targetCounter < previousReceiveCounter) return null;

    let chain = previousChainKeyReceive;
    let counter = previousReceiveCounter;
    let steps = 0;
    while (counter < targetCounter && steps < MAX_WALK) {
      chain = deriveNextChainKey(chain);
      counter++;
      steps++;
    }
    if (counter !== targetCounter) return null;

    const messageKeyHex = deriveMessageKey(chain, targetCounter);
    const messageKeyBytes = hexToBytes(messageKeyHex);
    try {
      const nonceBytes = hexToBytes(parsedEnvelope.n);
      const ciphertextBytes = hexToBytes(parsedEnvelope.c);
      const aadV2 = buildMessageAAD(
        conversationId,
        targetCounter,
        ratchetPublicKey,
        senderId,
        recipientId,
      );
      const aadV1 = buildMessageAAD(conversationId, targetCounter, ratchetPublicKey);

      try {
        return decryptXChaCha20Poly1305(
          { nonce: nonceBytes, ciphertext: ciphertextBytes },
          messageKeyBytes,
          aadV2,
        );
      } catch {
        try {
          return decryptXChaCha20Poly1305(
            { nonce: nonceBytes, ciphertext: ciphertextBytes },
            messageKeyBytes,
            aadV1,
          );
        } catch {
          return decryptXChaCha20Poly1305(
            { nonce: nonceBytes, ciphertext: ciphertextBytes },
            messageKeyBytes,
          );
        }
      }
    } catch {
      return null;
    } finally {
      secureZero(messageKeyBytes);
    }
  }
}

export { ENCRYPTION_VERSION_XCHACHA20_POLY1305_V1 };
