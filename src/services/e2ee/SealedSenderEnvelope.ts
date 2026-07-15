import {
  generateX25519KeyPair,
  x25519ECDH,
  ed25519Sign,
  ed25519Verify,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  bytesToHex,
  hexToBytes,
  hash256,
  randomBytes,
  deriveKey,
  secureZero,
} from '../SodiumCrypto';
import { E2EError } from './e2eeErrors';

const KDF_INFO = new TextEncoder().encode('SealedSender');
const CERT_FUTURE_TOLERANCE_MS = 60_000;

export interface InnerEncryptedPayload {
  conversationId: string;
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

export interface SenderCertificateInfo {
  userId: string;
  deviceId: string;
  identityKeyHex: string;
  signingPublicKeyHex?: string;
  signingPrivateKeyHex?: string;
  certExpiryMs?: number;
}

export interface SealedSenderResult {
  sealedPayload: string;
  deliveryToken: string;
}

export interface UnsealedMessage {
  senderUserId: string;
  senderDeviceId: string;
  senderIdentityKey: string;
  senderSigningKey?: string;
  senderTimestamp: number;
  encryptedMessage: InnerEncryptedPayload;
}

export class SealedSenderEnvelope {
  /**
   * Wrap an inner encrypted payload + sender certificate in an
   * X25519+XChaCha20-Poly1305 envelope addressed to recipient's
   * identity public key. The ephemeral public key is the AAD so a
   * tampered envelope fails AEAD verification.
   */
  static seal(
    inner: InnerEncryptedPayload,
    recipientIdentityKeyHex: string,
    sender: SenderCertificateInfo,
  ): SealedSenderResult {
    const certPayload: Record<string, unknown> = {
      u: sender.userId,
      d: sender.deviceId,
      k: sender.identityKeyHex,
      t: Date.now(),
    };
    if (sender.signingPublicKeyHex) certPayload.sk = sender.signingPublicKeyHex;
    const senderCert = JSON.stringify(certPayload);

    let certSignature: string | undefined;
    if (sender.signingPrivateKeyHex) {
      const certBytes = new TextEncoder().encode(senderCert);
      const signingKey = hexToBytes(sender.signingPrivateKeyHex);
      const signatureBytes = ed25519Sign(certBytes, signingKey);
      certSignature = bytesToHex(signatureBytes);
      secureZero(signingKey);
    }

    const innerJson = JSON.stringify({
      cert: senderCert,
      ...(certSignature ? { sig: certSignature } : {}),
      msg: inner,
    });

    const ephemeral = generateX25519KeyPair();
    const recipientPub = hexToBytes(recipientIdentityKeyHex);
    const sharedSecret = x25519ECDH(ephemeral.privateKey, recipientPub);
    const derivedKey = deriveKey(sharedSecret, null, KDF_INFO, 32);

    const innerBytes = new TextEncoder().encode(innerJson);
    const sealed = encryptXChaCha20Poly1305(innerBytes, derivedKey, ephemeral.publicKey);
    secureZero(innerBytes);

    const sealedPayload =
      bytesToHex(ephemeral.publicKey) +
      bytesToHex(sealed.nonce) +
      bytesToHex(sealed.ciphertext);

    const tokenInput = new TextEncoder().encode(
      inner.conversationId + bytesToHex(randomBytes(16)),
    );
    const deliveryToken = bytesToHex(hash256(tokenInput));

    secureZero(sharedSecret);
    secureZero(derivedKey);
    secureZero(ephemeral.privateKey);
    secureZero(recipientPub);

    return { sealedPayload, deliveryToken };
  }

  /**
   * Unwrap a sealed envelope using the recipient's identity private
   * key. Verifies the embedded sender certificate signature when
   * present. Returns the decoded sender info + inner encrypted
   * payload that the caller still needs to run through Double Ratchet
   * decrypt.
   *
   * `recipientPrivateKeyHex` is chosen by the caller — typically the
   * current identity key, falling back to the previous-generation
   * key inside the rotation grace window. If the caller can't find a
   * matching private key, it should throw RECIPIENT_KEY_ROTATED
   * BEFORE calling this function rather than passing junk.
   */
  static unseal(sealedPayload: string, recipientPrivateKeyHex: string): UnsealedMessage {
    if (!recipientPrivateKeyHex) {
      throw new E2EError(
        'SEALED_SENDER_ERROR: No identity key pair available for decryption',
        'SEALED_SENDER_ERROR',
      );
    }
    if (sealedPayload.length < (32 + 24 + 1) * 2) {
      throw new E2EError('SEALED_SENDER_ERROR: Payload too short', 'SEALED_SENDER_ERROR');
    }

    const ephPubHex = sealedPayload.slice(0, 64);
    const nonceHex = sealedPayload.slice(64, 64 + 48);
    const ciphertextHex = sealedPayload.slice(64 + 48);

    const ephPub = hexToBytes(ephPubHex);
    const recipientPriv = hexToBytes(recipientPrivateKeyHex);
    const sharedSecret = x25519ECDH(recipientPriv, ephPub);
    const derivedKey = deriveKey(sharedSecret, null, KDF_INFO, 32);

    const nonce = hexToBytes(nonceHex);
    const ciphertext = hexToBytes(ciphertextHex);

    let plaintextBytes: Uint8Array;
    try {
      plaintextBytes = decryptXChaCha20Poly1305({ nonce, ciphertext }, derivedKey, ephPub);
    } catch {
      secureZero(sharedSecret);
      secureZero(derivedKey);
      secureZero(recipientPriv);
      throw new E2EError(
        'SEALED_SENDER_ERROR: Decryption failed — invalid sealed envelope',
        'SEALED_SENDER_ERROR',
      );
    }
    secureZero(sharedSecret);
    secureZero(derivedKey);
    secureZero(recipientPriv);

    const innerJson = new TextDecoder().decode(plaintextBytes);
    secureZero(plaintextBytes);
    const inner = JSON.parse(innerJson) as { cert: string; sig?: string; msg: InnerEncryptedPayload };
    if (!inner.cert || !inner.msg) {
      throw new E2EError(
        'SEALED_SENDER_ERROR: Invalid inner payload structure',
        'SEALED_SENDER_ERROR',
      );
    }

    const senderCert = JSON.parse(inner.cert) as {
      u: string;
      d?: string;
      k: string;
      sk?: string;
      t?: number;
    };
    if (!senderCert.u || !senderCert.k) {
      throw new E2EError(
        'SEALED_SENDER_ERROR: Invalid sender certificate — missing userId or identityKey',
        'SEALED_SENDER_ERROR',
      );
    }

    if (inner.sig) {
      if (!senderCert.sk) {
        throw new E2EError(
          'SEALED_SENDER_ERROR: Certificate signature present but signing public key (sk) missing from certificate',
          'SEALED_SENDER_ERROR',
        );
      }
      const certBytes = new TextEncoder().encode(inner.cert);
      const signatureBytes = hexToBytes(inner.sig);
      const signingPubBytes = hexToBytes(senderCert.sk);
      const valid = ed25519Verify(certBytes, signatureBytes, signingPubBytes);
      if (!valid) {
        throw new E2EError(
          'SEALED_SENDER_ERROR: Sender certificate signature verification failed — possible tampering',
          'SEALED_SENDER_ERROR',
        );
      }
    }

    const issuedAt = senderCert.t ?? Date.now();
    if (Date.now() - issuedAt > 7 * 24 * 60 * 60 * 1000) {
      throw new E2EError('SEALED_SENDER_ERROR: Sender certificate expired', 'SEALED_SENDER_ERROR');
    }
    if (issuedAt - Date.now() > CERT_FUTURE_TOLERANCE_MS) {
      throw new E2EError(
        'SEALED_SENDER_ERROR: Sender certificate timestamp too far in future',
        'SEALED_SENDER_ERROR',
      );
    }

    return {
      senderUserId: senderCert.u,
      senderDeviceId: senderCert.d || 'primary',
      senderIdentityKey: senderCert.k,
      senderSigningKey: senderCert.sk,
      senderTimestamp: issuedAt,
      encryptedMessage: inner.msg,
    };
  }
}
