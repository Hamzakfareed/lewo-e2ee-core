import {
  bytesToHex,
  hexToBytes,
  hash256,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  deriveKey,
  secureZero,
} from '../SodiumCrypto';
import { E2EError } from './e2eeErrors';

export const PADDING_BLOCK_SIZE = 1024;
export const PADDING_MAGIC = 0x80;
const ENCRYPTION_VERSION_XCHACHA = 'xchacha20-poly1305-v1';
const METADATA_VERSION = 2;

export interface EncryptedMetadataPayload {
  conversationId?: string;
  recipientUserId?: string;
  senderUserId?: string;
  timestamp?: number;
  messageType?: string;
  [k: string]: unknown;
}

export interface UnwrappedEnvelope {
  content: string;
  envelope: {
    messageType: string;
    mediaUrls: string[] | null;
    metadata: Record<string, unknown> | null;
    replyToMessageUuid: string | null;
  } | null;
}

export class MetadataCipher {
  static encryptMetadata(metadata: EncryptedMetadataPayload, messageKeyHex: string): string {
    const messageKeyBytes = hexToBytes(messageKeyHex);
    const metadataKeyBytes = MetadataCipher.deriveMetadataKey(messageKeyBytes);
    const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
    try {
      const encrypted = encryptXChaCha20Poly1305(metadataBytes, metadataKeyBytes);
      return JSON.stringify({
        v: ENCRYPTION_VERSION_XCHACHA,
        mv: METADATA_VERSION,
        n: bytesToHex(encrypted.nonce),
        c: bytesToHex(encrypted.ciphertext),
      });
    } finally {
      secureZero(messageKeyBytes);
      secureZero(metadataKeyBytes);
      secureZero(metadataBytes);
    }
  }

  static decryptMetadata(
    encryptedMetadata: string,
    messageKeyHex: string,
  ): EncryptedMetadataPayload | null {
    const messageKeyBytes = hexToBytes(messageKeyHex);
    let metadataKeyBytes: Uint8Array | null = null;
    try {
      const parsed = JSON.parse(encryptedMetadata);
      if (parsed.v !== ENCRYPTION_VERSION_XCHACHA) return null;
      const nonce = hexToBytes(parsed.n);
      const ciphertext = hexToBytes(parsed.c);
      // mv≥2 derives a metadata-specific subkey; older envelopes used the message key directly.
      const useDerived = parsed.mv && parsed.mv >= METADATA_VERSION;
      const keyForDecrypt = useDerived
        ? (metadataKeyBytes = MetadataCipher.deriveMetadataKey(messageKeyBytes))
        : messageKeyBytes;
      const plaintextBytes = decryptXChaCha20Poly1305({ nonce, ciphertext }, keyForDecrypt);
      return JSON.parse(new TextDecoder().decode(plaintextBytes));
    } catch {
      return null;
    } finally {
      secureZero(messageKeyBytes);
      if (metadataKeyBytes) secureZero(metadataKeyBytes);
    }
  }

  /** ISO/IEC 7816-4: append 0x80 then zero-fill to next PADDING_BLOCK_SIZE multiple. */
  static applyPadding(plaintext: Uint8Array): Uint8Array {
    const paddedLength = Math.ceil((plaintext.length + 1) / PADDING_BLOCK_SIZE) * PADDING_BLOCK_SIZE;
    const padded = new Uint8Array(paddedLength);
    padded.set(plaintext);
    padded[plaintext.length] = PADDING_MAGIC;
    return padded;
  }

  /**
   * Strip ISO/IEC 7816-4 padding. A length-aligned payload missing the 0x80
   * marker means the ciphertext is corrupt — throws INVALID_PADDING. Unaligned
   * lengths (legacy unpadded messages) are returned as-is for back-compat.
   */
  static removePadding(padded: Uint8Array): Uint8Array {
    let paddingStart = padded.length - 1;
    while (paddingStart >= 0 && padded[paddingStart] === 0x00) paddingStart--;
    if (paddingStart < 0 || padded[paddingStart] !== PADDING_MAGIC) {
      if (padded.length > 0 && padded.length % PADDING_BLOCK_SIZE === 0) {
        throw new E2EError(
          `INVALID_PADDING: expected ISO 7816-4 padding marker in ${padded.length}-byte aligned payload`,
          'INVALID_PADDING',
        );
      }
      return padded;
    }
    return padded.slice(0, paddingStart);
  }

  static unwrapEnvelope(plaintext: string): UnwrappedEnvelope {
    try {
      const parsed = JSON.parse(plaintext);
      if (parsed && parsed.v === 2 && typeof parsed.c === 'string') {
        return {
          content: parsed.c,
          envelope: {
            messageType: parsed.t || 'TEXT',
            mediaUrls: parsed.m || null,
            metadata: parsed.meta || null,
            replyToMessageUuid: parsed.replyTo || null,
          },
        };
      }
    } catch {
      /* v1 plain text */
    }
    return { content: plaintext, envelope: null };
  }

  /** Keyed BLAKE2b MAC for legacy signature paths. Hashes oversized keys. */
  static computeKeyedMAC(message: string, key: string): string {
    const messageBytes = MetadataCipher.bestEffortHexOrUtf8(message);
    let keyBytes = MetadataCipher.bestEffortHexOrUtf8(key);
    if (keyBytes.length > 64) keyBytes = hash256(keyBytes);
    return bytesToHex(deriveKey(messageBytes, keyBytes, new Uint8Array(0), 32));
  }

  /**
   * BLAKE2b(messageKey || 0x02 || "metadata"). Mirrors the chain-key derivation
   * (0x01 = message key, 0x02 = metadata) so metadata never reuses the message key.
   */
  private static deriveMetadataKey(messageKeyBytes: Uint8Array): Uint8Array {
    const domain = new TextEncoder().encode('metadata');
    const input = new Uint8Array(messageKeyBytes.length + 1 + domain.length);
    input.set(messageKeyBytes, 0);
    input[messageKeyBytes.length] = 0x02;
    input.set(domain, messageKeyBytes.length + 1);
    const derived = hash256(input);
    secureZero(input);
    return derived;
  }

  private static bestEffortHexOrUtf8(s: string): Uint8Array {
    try {
      return hexToBytes(s);
    } catch {
      return new TextEncoder().encode(s);
    }
  }
}
