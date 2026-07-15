/**
 * ChannelPostCipher
 *
 * The encrypt/decrypt body for `ChannelE2EEncryptionService.encryptPost` /
 * `decryptPost`. Pulled out of the service so:
 *   - the AEAD + Ed25519 sign/verify paths are testable in isolation
 *   - the service is left as orchestration (key lookup, key version policy,
 *     persistence) without the inline crypto soup
 *
 * Inputs are already-resolved key material; the caller still owns key store
 * loading, ratchet advancement, and admin-roster bookkeeping.
 */

import {
  ed25519Sign,
  ed25519Verify,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  bytesToHex,
  hexToBytes,
  hash256,
  secureZero,
} from '../SodiumCrypto';

export interface ChannelEncryptedBody {
  /** Hex-encoded ciphertext + nonce JSON envelope (channel format). */
  encryptedContent: string;
  /** Hex-encoded Ed25519 signature over hash(nonce|ciphertext). */
  signature: string;
  /** Optional encrypted media-key payload (channel envelope). */
  encryptedMediaKeys?: string;
}

/**
 * Encrypt a serialized channel post payload, sign the (nonce|ciphertext)
 * digest, and optionally encrypt media keys with the same per-message key.
 * Zeros all sensitive byte buffers before returning.
 */
export function encryptChannelPostBody(args: {
  /** Already-JSON-stringified post content (channel layer decides shape). */
  postContentJson: string;
  /** Hex-encoded per-message symmetric key. */
  messageKeyHex: string;
  /** Hex-encoded Ed25519 admin signing private key. */
  signingPrivateKeyHex: string;
  /** Optional plaintext media keys to encrypt under the same message key. */
  mediaKeys?: string[];
  /** Encryption version constant to embed in the envelope. */
  encryptionVersion: number;
}): ChannelEncryptedBody {
  const postBytes = new TextEncoder().encode(args.postContentJson);
  const messageKeyBytes = hexToBytes(args.messageKeyHex);
  const signingKeyBytes = hexToBytes(args.signingPrivateKeyHex);

  try {
    const { ciphertext, nonce } = encryptXChaCha20Poly1305(postBytes, messageKeyBytes);

    let encryptedMediaKeys: string | undefined;
    if (args.mediaKeys && args.mediaKeys.length > 0) {
      const mediaKeysJson = JSON.stringify(args.mediaKeys);
      const mediaKeysBytes = new TextEncoder().encode(mediaKeysJson);
      const mediaEncrypted = encryptXChaCha20Poly1305(mediaKeysBytes, messageKeyBytes);
      encryptedMediaKeys = JSON.stringify({
        n: bytesToHex(mediaEncrypted.nonce),
        c: bytesToHex(mediaEncrypted.ciphertext),
      });
    }

    const contentToSign = new Uint8Array([...nonce, ...ciphertext]);
    const contentHash = hash256(contentToSign);
    const signature = ed25519Sign(contentHash, signingKeyBytes);

    secureZero(contentHash);

    return {
      encryptedContent: JSON.stringify({
        v: args.encryptionVersion,
        n: bytesToHex(nonce),
        c: bytesToHex(ciphertext),
      }),
      signature: bytesToHex(signature),
      encryptedMediaKeys,
    };
  } finally {
    secureZero(messageKeyBytes);
    secureZero(signingKeyBytes);
    secureZero(postBytes);
  }
}

export interface ChannelDecryptedPayload {
  postContentJson: string;
  mediaKeys?: string[];
}

/**
 * Verify the post signature, then decrypt the post body and (if present)
 * the encrypted media keys. Throws on signature failure or AEAD failure.
 *
 * Caller is responsible for the encryption-version check, post-size limit,
 * timestamp check, counter ratchet advance, and chain-key derivation. This
 * helper just runs the inner crypto.
 */
/**
 * Verify a channel post's Ed25519 signature over hash(nonce|ciphertext) WITHOUT
 * decrypting or deriving any key. Cheap (~µs) + authenticated: callers hoist this
 * BEFORE the forward-ratchet catch-up loop so a FORGED post (bad signature) is
 * rejected before running up to the DoS-ceiling of pure-JS HKDF iterations
 * (unauthenticated-forward-ratchet DoS). Throws on mismatch.
 */
export function verifyChannelPostSignature(args: {
  encryptedContent: { n: string; c: string };
  signatureHex: string;
  signingPublicKeyHex: string;
}): void {
  const nonce = hexToBytes(args.encryptedContent.n);
  const ciphertext = hexToBytes(args.encryptedContent.c);
  const signatureBytes = hexToBytes(args.signatureHex);
  const signingKeyBytes = hexToBytes(args.signingPublicKeyHex);
  const contentToVerify = new Uint8Array([...nonce, ...ciphertext]);
  const contentHash = hash256(contentToVerify);
  const isVerified = ed25519Verify(contentHash, signatureBytes, signingKeyBytes);
  if (!isVerified) {
    throw new Error('Post signature verification failed. Post may be tampered or from unauthorized source.');
  }
}

export function decryptChannelPostBody(args: {
  /** JSON envelope `{ v, n, c }` produced by encryptChannelPostBody. */
  encryptedContent: { n: string; c: string };
  /** Optional `{ n, c }` envelope for encrypted media keys. */
  encryptedMediaKeys?: string;
  /** Hex-encoded per-message symmetric key derived by the caller. */
  messageKeyHex: string;
  /** Hex-encoded Ed25519 signature attached to the post. */
  signatureHex: string;
  /** Hex-encoded admin signing public key the caller verified is theirs. */
  signingPublicKeyHex: string;
}): ChannelDecryptedPayload {
  // Verify signature first — never decrypt unauthenticated content. (Callers on
  // the channel path also hoist this ahead of the ratchet loop; re-verifying here
  // keeps this function safe to call standalone — defense-in-depth, ~µs.)
  verifyChannelPostSignature({
    encryptedContent: args.encryptedContent,
    signatureHex: args.signatureHex,
    signingPublicKeyHex: args.signingPublicKeyHex,
  });

  const nonce = hexToBytes(args.encryptedContent.n);
  const ciphertext = hexToBytes(args.encryptedContent.c);
  const messageKeyBytes = hexToBytes(args.messageKeyHex);
  try {
    const plaintext = decryptXChaCha20Poly1305(ciphertext, nonce, messageKeyBytes);
    const postContentJson = new TextDecoder().decode(plaintext);

    let mediaKeys: string[] | undefined;
    if (args.encryptedMediaKeys) {
      const mediaParsed = JSON.parse(args.encryptedMediaKeys);
      const mediaNonce = hexToBytes(mediaParsed.n);
      const mediaCiphertext = hexToBytes(mediaParsed.c);
      const mediaPlaintext = decryptXChaCha20Poly1305(mediaCiphertext, mediaNonce, messageKeyBytes);
      mediaKeys = JSON.parse(new TextDecoder().decode(mediaPlaintext));
    }

    return { postContentJson, mediaKeys };
  } finally {
    secureZero(messageKeyBytes);
  }
}
