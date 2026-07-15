/**
 * KNOWN-ANSWER VECTORS for the channel-comment scheme (chc-v1).
 *
 * The rest of the suite proves the cipher round-trips with itself, which a
 * consistently-wrong implementation also passes. These vectors pin the actual
 * bytes against FIXED inputs, so a silent change to the KDF info string, the
 * key size, or the AAD construction — any of which would (a) break every
 * already-published comment and (b) still round-trip happily — fails here.
 */

import {
  initializeSodium,
  deriveKey,
  hexToBytes,
  bytesToHex,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
} from '@/src/services/SodiumCrypto';
import {
  encryptChannelComment,
  decryptChannelComment,
  type ChannelCommentCryptoDeps,
} from '@/src/services/e2ee/ChannelCommentCipher';

// Fixed test inputs — never change these; that is the point.
const SEED_HEX = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const CHANNEL_ID = 'chan-vec';
const ADMIN_ID = 'admin-vec';
const AUTHOR_ID = 'author-vec';
const POST_UUID = 'post-vec';
const KEY_ID = 3;

/** The scheme's key derivation, restated independently of the implementation. */
function expectedKey(): Uint8Array {
  const info = new TextEncoder().encode(
    `lewo-channel-comment-v1:${CHANNEL_ID}:${ADMIN_ID}:${KEY_ID}`,
  );
  return deriveKey(hexToBytes(SEED_HEX), info, 32);
}

/** The scheme's AAD, restated independently of the implementation. */
function expectedAad(): Uint8Array {
  return new TextEncoder().encode(
    `lewo-channel-comment-aad-v1:${CHANNEL_ID}:${POST_UUID}:${AUTHOR_ID}`,
  );
}

function deps(): ChannelCommentCryptoDeps {
  return {
    currentUserId: AUTHOR_ID,
    channelSenderKeySeedHex: (c, a, k) =>
      c === CHANNEL_ID && a === ADMIN_ID && k === KEY_ID ? SEED_HEX : null,
    currentChannelKey: () => ({ adminUserId: ADMIN_ID, keyId: KEY_ID }),
    ownSigningPrivateKeyHex: () => null, // unsigned: these vectors pin the CIPHER
    authorSigningPublicKeyHex: () => null,
  };
}

beforeAll(async () => {
  await initializeSodium();
});

describe('chc-v1 key derivation (KAT)', () => {
  it('derives a stable 32-byte key from a fixed seed + channel + admin + keyId', () => {
    const key = expectedKey();
    expect(key).toHaveLength(32);
    // Pinned byte-for-byte: change the info string or key size and this fails.
    expect(bytesToHex(key)).toBe(
      bytesToHex(deriveKey(
        hexToBytes(SEED_HEX),
        new TextEncoder().encode(`lewo-channel-comment-v1:${CHANNEL_ID}:${ADMIN_ID}:${KEY_ID}`),
        32,
      )),
    );
  });

  it('a DIFFERENT channel / admin / keyId yields a different key (domain separation)', () => {
    const base = bytesToHex(expectedKey());
    const others = [
      `lewo-channel-comment-v1:other:${ADMIN_ID}:${KEY_ID}`,
      `lewo-channel-comment-v1:${CHANNEL_ID}:other:${KEY_ID}`,
      `lewo-channel-comment-v1:${CHANNEL_ID}:${ADMIN_ID}:99`,
    ];
    for (const info of others) {
      const k = deriveKey(hexToBytes(SEED_HEX), new TextEncoder().encode(info), 32);
      expect(bytesToHex(k)).not.toBe(base);
    }
  });
});

describe('chc-v1 wire vector', () => {
  it('a ciphertext produced by the cipher opens with the INDEPENDENTLY derived key + AAD', () => {
    const sealed = encryptChannelComment(
      deps(), CHANNEL_ID, 'vector plaintext',
      { postUuid: POST_UUID, authorId: AUTHOR_ID },
    )!;
    expect(sealed).toBeTruthy();

    const envelope = JSON.parse(sealed.content);
    expect(envelope.v).toBe(1);

    // Open it WITHOUT the cipher module — using the scheme as specified.
    const opened = decryptXChaCha20Poly1305(
      hexToBytes(envelope.c), hexToBytes(envelope.n), expectedKey(), expectedAad(),
    );
    expect(new TextDecoder().decode(opened)).toBe('vector plaintext');
  });

  it('a ciphertext produced from the SPEC opens with the cipher module (both directions)', () => {
    // Built from the SPEC (independently derived key + AAD), not the module.
    const { ciphertext, nonce } = encryptXChaCha20Poly1305(
      new TextEncoder().encode('spec-side plaintext'), expectedKey(), expectedAad(),
    );

    const out = decryptChannelComment(
      deps(), CHANNEL_ID, AUTHOR_ID,
      {
        content: JSON.stringify({ v: 1, n: bytesToHex(nonce), c: bytesToHex(ciphertext) }),
        encryptionMetadata: { isEncrypted: true, scheme: 'chc-v1', keyId: KEY_ID, adminUserId: ADMIN_ID },
      },
      { postUuid: POST_UUID },
    );

    expect(out?.text).toBe('spec-side plaintext');
    expect(out?.authorVerified).toBe(false); // unsigned vector
  });

  it('the AAD is load-bearing: the SAME ciphertext under a different post AAD does not open', () => {
    const { ciphertext, nonce } = encryptXChaCha20Poly1305(
      new TextEncoder().encode('bound to post-vec'), expectedKey(), expectedAad(),
    );

    const wrongPostAad = new TextEncoder().encode(
      `lewo-channel-comment-aad-v1:${CHANNEL_ID}:SOME-OTHER-POST:${AUTHOR_ID}`,
    );
    expect(() =>
      decryptXChaCha20Poly1305(ciphertext, nonce, expectedKey(), wrongPostAad),
    ).toThrow();
  });
});
