/**
 * E2EE message serialization primitives — AAD construction + helpers
 * for envelope assembly/parsing.
 *
 * EXTRACTED FROM `E2EEncryptionService.ts` (Path B Phase A.4). Pure
 * functions; no state.
 *
 * AAD (Additional Authenticated Data) is the part of the envelope
 * that isn't encrypted but IS authenticated by the AEAD construction.
 * If the AAD differs between sender and receiver, decryption fails —
 * so AAD assembly is protocol-critical and MUST be byte-identical
 * across sender + receiver implementations.
 *
 * AAD format (legacy V1):
 *   conversationId (UTF-8) || counter (4-byte little-endian uint32) || ratchetPublicKey (raw bytes)
 *
 * AAD format (V2 — Tier 1 B5, Signal-style sender/recipient binding):
 *   <V1 bytes> || 0x1E || senderUserId (UTF-8) || 0x1E || recipientUserId (UTF-8)
 *
 * V2 is opt-in per call: pass both `senderUserId` and `recipientUserId`
 * to enable. Otherwise the function emits V1, byte-identical to the
 * pre-fix output. The 0x1E (Record Separator, ASCII 30) byte is the
 * V2 prefix marker and never appears in user-id strings (which are
 * UUIDs / alphanumerics). Receivers attempt V2 first then fall back
 * to V1 to keep in-flight messages decryptable across the rollout.
 *
 * If `ratchetPublicKey` is missing, the V1 trailing segment is empty
 * (used by legacy / non-ratchet messages).
 */

import { hexToBytes } from '../SodiumCrypto';

/** ASCII 30 — "Record Separator". Used as the V2 user-id binding marker. */
const AAD_USERID_SEPARATOR = 0x1e;

/**
 * Build the AEAD-AAD for a message. Same input → same output, byte
 * for byte. Sender and receiver MUST call this with identical
 * arguments or decryption fails.
 *
 * @param conversationId - UTF-8 conversation identifier
 * @param messageCounter - non-negative integer (uint32 wire format)
 * @param ratchetPublicKey - optional hex-encoded sender's ratchet pubkey
 * @param senderUserId - optional sender user id (V2 binding); requires recipientUserId
 * @param recipientUserId - optional recipient user id (V2 binding); requires senderUserId
 */
export function buildMessageAAD(
  conversationId: string,
  messageCounter: number,
  ratchetPublicKey?: string,
  senderUserId?: string,
  recipientUserId?: string,
): Uint8Array {
  const conversationIdBytes = new TextEncoder().encode(conversationId);

  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, messageCounter, true);

  const ratchetKeyBytes = ratchetPublicKey
    ? hexToBytes(ratchetPublicKey)
    : new Uint8Array(0);

  // V2 user-id binding requires BOTH ids. A single id is treated as no
  // binding (V1 layout) — keeps callers that only have one side from
  // accidentally producing a half-bound AAD that would never match.
  const v2Enabled = !!senderUserId && !!recipientUserId;
  const senderBytes = v2Enabled ? new TextEncoder().encode(senderUserId!) : new Uint8Array(0);
  const recipientBytes = v2Enabled ? new TextEncoder().encode(recipientUserId!) : new Uint8Array(0);
  const v2Suffix = v2Enabled ? 1 + senderBytes.length + 1 + recipientBytes.length : 0;

  const aad = new Uint8Array(
    conversationIdBytes.length + 4 + ratchetKeyBytes.length + v2Suffix,
  );
  aad.set(conversationIdBytes, 0);
  aad.set(counterBytes, conversationIdBytes.length);
  aad.set(ratchetKeyBytes, conversationIdBytes.length + 4);

  if (v2Enabled) {
    let offset = conversationIdBytes.length + 4 + ratchetKeyBytes.length;
    aad[offset++] = AAD_USERID_SEPARATOR;
    aad.set(senderBytes, offset);
    offset += senderBytes.length;
    aad[offset++] = AAD_USERID_SEPARATOR;
    aad.set(recipientBytes, offset);
  }

  return aad;
}
