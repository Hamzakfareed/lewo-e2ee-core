/**
 * ChannelCommentCipher — E2EE for channel post COMMENTS.
 *
 * Post bodies were already sealed (Sender Key chain, ChannelPostCipher) but
 * comments travelled PLAINTEXT — the loudest hole in the "fully E2EE
 * channels" claim. Comments get their own scheme rather than reusing the
 * post chain because:
 *   - encryptPost requires the ADMIN sender+signing keys; subscribers can't
 *     call it, and comments come from any member;
 *   - the post chain RATCHETS per message — comments from many members would
 *     race the counter and desync every reader.
 *
 * Scheme ('chc-v1'):
 *   key      = HKDF(adminSenderKeySeed, "lewo-channel-comment-v1:{channelId}:
 *              {adminUserId}:{keyId}") — STATIC per channel key generation, so
 *              decrypt is freely repeatable (no ratchet bookkeeping) and every
 *              subscriber already holds the input via key distribution.
 *   body     = XChaCha20-Poly1305(comment text)
 *   wire     = content: JSON {"v":1,"n":hex,"c":hex}  (the exact shape the
 *              backend's channel ciphertext validator enforces)
 *              encryptionMetadata: {isEncrypted, scheme, keyId, adminUserId,
 *              sig?} — location fields the server relays but cannot use.
 *   aad      = "lewo-channel-comment-aad-v1:{channelId}:{postUuid}:{authorId}"
 *              — binds the ciphertext to its post and author, so a sealed
 *              comment cannot be replayed onto a DIFFERENT post (every member
 *              derives the same static key, so without this a malicious server
 *              or member could re-attach Alice's words under any post).
 *   sig      = Ed25519(author's LONG-TERM signing key, over ciphertext).
 *              Verification is OPPORTUNISTIC and NON-FATAL: channel members
 *              don't mutually TOFU-pin, so an unknown or MISMATCHED key renders
 *              "unverified" — it never erases the comment. (A strict reject
 *              destroyed history: the moment a member reinstalled or rotated
 *              their identity key, every comment they had ever written became
 *              permanently unreadable for everyone, even though the AEAD key
 *              was perfectly available. Confidentiality never depended on the
 *              signature — the AEAD key is the shared channel key.)
 *
 * Deps-injected and pure, mirroring ControlMessageCrypto — the facade on
 * ChannelE2EEncryptionService supplies key lookups (rotation-aware, same
 * live+history resolution as posts use).
 */

import {
  deriveKey,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  ed25519Sign,
  ed25519Verify,
  hexToBytes,
  bytesToHex,
} from '../SodiumCrypto';

const COMMENT_KEY_SIZE = 32;
const COMMENT_VERSION = 1;
const HEX64 = /^[0-9a-f]{64}$/i;

export interface ChannelCommentCryptoDeps {
  currentUserId: string | null;
  /**
   * The admin's channel sender-key seed for the exact (channelId,
   * adminUserId, keyId) — live or historical. Null when this client doesn't
   * hold it (non-member / keys not yet distributed).
   */
  channelSenderKeySeedHex: (
    channelId: string,
    adminUserId: string,
    keyId: number,
  ) => string | null;
  /** The key a NEW comment should be sealed under; null → composer must block. */
  currentChannelKey: (
    channelId: string,
  ) => { adminUserId: string; keyId: number } | null;
  /** Author's long-term Ed25519 signing private key (hex); null → send unsigned. */
  ownSigningPrivateKeyHex: () => string | null;
  /** Claimed author's pinned/known signing public key (hex); null → unverified. */
  authorSigningPublicKeyHex: (authorId: string) => string | null;
}

export interface EncryptedChannelComment {
  /** JSON {"v":1,"n":hex,"c":hex} — backend-validated ciphertext envelope. */
  content: string;
  /** Server-relayed location + authenticity fields (never secret). */
  encryptionMetadata: Record<string, unknown>;
}

/**
 * AAD binding. Without it the sealed comment is a free-floating
 * ciphertext: every channel member derives the SAME static key, so a comment
 * could be lifted onto a different post (or re-attributed) and still decrypt.
 */
function commentAad(channelId: string, postUuid: string, authorId: string): Uint8Array {
  return new TextEncoder().encode(
    `lewo-channel-comment-aad-v1:${channelId}:${postUuid}:${authorId}`,
  );
}

function infoComment(channelId: string, adminUserId: string, keyId: number): Uint8Array {
  return new TextEncoder().encode(
    `lewo-channel-comment-v1:${channelId}:${adminUserId}:${keyId}`,
  );
}

function deriveCommentKey(
  seedHex: string | null,
  channelId: string,
  adminUserId: string,
  keyId: number,
): Uint8Array | null {
  if (!HEX64.test(seedHex ?? '')) return null;
  try {
    return deriveKey(hexToBytes(seedHex!), infoComment(channelId, adminUserId, keyId), COMMENT_KEY_SIZE);
  } catch {
    return null;
  }
}

/**
 * Seal a comment. Null when this client holds no channel key — the caller
 * must BLOCK the send (keys-syncing state), never fall back to plaintext.
 */
export function encryptChannelComment(
  deps: ChannelCommentCryptoDeps,
  channelId: string,
  plaintext: string,
  /** Binds the ciphertext to its post + author. */
  binding?: { postUuid: string; authorId: string },
): EncryptedChannelComment | null {
  try {
    const keyRef = deps.currentChannelKey(channelId);
    if (!keyRef) return null;
    const key = deriveCommentKey(
      deps.channelSenderKeySeedHex(channelId, keyRef.adminUserId, keyRef.keyId),
      channelId, keyRef.adminUserId, keyRef.keyId,
    );
    if (!key) return null;

    const aad = binding
      ? commentAad(channelId, binding.postUuid, binding.authorId)
      : undefined;
    const { ciphertext, nonce } = encryptXChaCha20Poly1305(
      new TextEncoder().encode(plaintext), key, aad,
    );

    let sig: string | undefined;
    const signingPriv = deps.ownSigningPrivateKeyHex();
    if (signingPriv) {
      try {
        sig = bytesToHex(ed25519Sign(ciphertext, hexToBytes(signingPriv)));
      } catch { /* unsigned is acceptable; forgery is then only server-attributed */ }
    }

    const encryptionMetadata: Record<string, unknown> = {
      isEncrypted: true,
      scheme: 'chc-v1',
      keyId: keyRef.keyId,
      adminUserId: keyRef.adminUserId,
    };
    if (sig) encryptionMetadata.sig = sig;

    return {
      content: JSON.stringify({
        v: COMMENT_VERSION,
        n: bytesToHex(nonce),
        c: bytesToHex(ciphertext),
      }),
      encryptionMetadata,
    };
  } catch {
    return null;
  }
}

/**
 * Open a sealed comment. Returns null when the key is missing (render a
 * tombstone), the ciphertext is tampered or REPLAYED onto another post, or the
 * envelope is malformed. A signature that does not verify against the author's
 * currently-known key yields {@code authorVerified: false} — never a reject
 * (see the scheme note above: strict rejection erased history on key rotation).
 */
export function decryptChannelComment(
  deps: ChannelCommentCryptoDeps,
  channelId: string,
  authorId: string,
  args: { content: string; encryptionMetadata: unknown },
  /** Must match the binding used at encrypt time. */
  binding?: { postUuid: string },
): { text: string; authorVerified: boolean } | null {
  try {
    const meta = args.encryptionMetadata as Record<string, unknown> | null;
    if (!meta || typeof meta !== 'object') return null;
    const keyId = typeof meta.keyId === 'number' ? meta.keyId : Number(meta.keyId);
    const adminUserId = typeof meta.adminUserId === 'string' ? meta.adminUserId : null;
    if (!Number.isFinite(keyId) || !adminUserId) return null;

    let envelope: { v?: unknown; n?: unknown; c?: unknown };
    try {
      envelope = JSON.parse(args.content);
    } catch {
      return null;
    }
    if (envelope.v !== COMMENT_VERSION
        || typeof envelope.n !== 'string' || typeof envelope.c !== 'string') {
      return null;
    }

    const key = deriveCommentKey(
      deps.channelSenderKeySeedHex(channelId, adminUserId, keyId),
      channelId, adminUserId, keyId,
    );
    if (!key) return null;

    const ciphertext = hexToBytes(envelope.c);

    // Authenticity is a HINT, not a gate: a mismatch marks the comment
    // unverified rather than erasing it, so an author's key rotation doesn't
    // wipe their entire comment history for every reader.
    let authorVerified = false;
    const sig = typeof meta.sig === 'string' ? meta.sig : null;
    const authorPub = deps.authorSigningPublicKeyHex(authorId);
    if (sig && authorPub) {
      try {
        authorVerified = ed25519Verify(
          ciphertext, hexToBytes(sig), hexToBytes(authorPub),
        );
      } catch {
        authorVerified = false;
      }
    }

    // The AAD binds this ciphertext to (channel, post, author). A comment
    // replayed onto a different post fails the tag here and decrypts to null.
    const aad = binding
      ? commentAad(channelId, binding.postUuid, authorId)
      : undefined;
    const plaintext = decryptXChaCha20Poly1305(
      ciphertext, hexToBytes(envelope.n), key, aad,
    );
    return { text: new TextDecoder().decode(plaintext), authorVerified };
  } catch {
    return null; // AEAD reject / malformed input → tombstone, never throw
  }
}
