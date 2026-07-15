/**
 * Shared types and module-level constants for the E2EE encryption service.
 */

import { generateX25519KeyPair } from './SodiumCrypto';
import { bytesToHex } from './SodiumCrypto';

export class E2EError extends Error {
  code?: string;
  conversationId?: string;
  sessionAgeDays?: number;
  originalError?: unknown;
  senderFingerprint?: string;
  ourFingerprint?: string;
  isRecoverable?: boolean;
  messageCounter?: number;
  receiveCounter?: number;
  gap?: number;
  maxAllowed?: number;
  counter?: number;
  reason?: string;
  recipientId?: string;
  newIdentityKey?: string;
  /**
   * Round-22 P0-A (additive): structured discriminator for the X3DH
   * responder's "OPK keyId=N not found locally" failure. `.code` stays
   * 'KEY_MISMATCH' for that throw (legacy consumers string/code-match it);
   * new channel-distribution recovery keys on this field instead.
   */
  x3dhFailure?: 'OPK_NOT_FOUND';
  /** The initiator-cited OPK id that was missing locally (evidence). */
  usedOPKId?: number;

  constructor(message: string, code?: string) {
    super(message);
    this.name = 'E2EError';
    if (code) this.code = code;
  }
}

export const STORAGE_KEYS = {
  IDENTITY_KEY: 'e2e_identity_key',
  SIGNED_PREKEY: 'e2e_signed_prekey',
  SIGNED_PREKEY_PREVIOUS: 'e2e_signed_prekey_previous',
  ONETIME_PREKEYS: 'e2e_onetime_prekeys',
  CONVERSATION_STATES: 'e2e_conversation_states',
  MESSAGE_KEYS: 'e2e_message_keys',
  SENDER_KEYS: 'e2e_sender_keys',
};

/**
 * The ratchet variant every NEWLY ESTABLISHED session uses.
 *
 * ⚠️ Both ends of a session must agree. There is no per-message version on the
 * wire, so a `dh` initiator talking to a `legacy` responder derives a different
 * sending chain and the message fails AEAD (visibly — KEY_MISMATCH → resend
 * recovery — never silently). Flip this only when every client can speak `dh`.
 * Existing persisted sessions are unaffected: they carry their own mode.
 */
export const RATCHET_MODE_FOR_NEW_SESSIONS: 'legacy' | 'dh' = 'dh';

/**
 * Post-compromise security is what this buys: `legacy` never advances the root,
 * so one theft of a session's state decrypts that conversation forever. Under
 * `dh` the root absorbs fresh DH output on every direction change, and a stolen
 * state is locked out after one full ratchet turnover. See
 * `PostCompromiseSecurity.test.ts` — both of its assertions FAIL under `legacy`.
 */

export const SECURITY_CONFIG = {
  STRICT_SPK_VERIFICATION: true,
  REQUIRE_AUTHENTICATED_ENCRYPTION: true,
  LOG_SECURITY_EVENTS: true,
  WARN_ON_LEGACY_CBC: false,
  TRACK_LEGACY_CBC_USAGE: false,
  REQUIRE_GROUP_SIGNATURE_VERIFICATION: true,
  STRICT_TOFU_MODE: true,
  BLOCK_ON_KEY_CHANGE: true,
  MARK_UNVERIFIED_KEY_CHANGES: true,
  MAX_MESSAGE_SIZE_BYTES: 1024 * 1024,
  MAX_FUTURE_TIMESTAMP_MS: 60 * 1000,
  // 30 days. Chat apps buffer messages on the backend for offline users; a
  // 24h cutoff (the old value) rejected entire backlogs the instant the user
  // signed in after a few days away — producing a flood of EXPIRED_MESSAGE
  // errors and a false-positive "targeted attack" alert from the crypto
  // monitor. The Signal-style monotonic counter remains the authoritative
  // replay defense; the timestamp window is just a stale-message belt.
  // 30 days matches WhatsApp / Signal server-buffer retention.
  MAX_MESSAGE_AGE_MS: 30 * 24 * 60 * 60 * 1000,
  MAX_SESSION_AGE_MS: 14 * 24 * 60 * 60 * 1000,
  PADDING_BLOCK_SIZE: 1024,
  PADDING_MAGIC: 0x80,
  SEALED_SENDER_ENABLED: true,
};

export const v5KeyGen = {
  generate: () => {
    const kp = generateX25519KeyPair();
    return {
      publicKey: bytesToHex(kp.publicKey),
      privateKey: bytesToHex(kp.privateKey),
    };
  },
};

export const legacyCBCMessageCount = 0;
export const aadFallbackCount = 0;

// Constant-time comparison for fingerprints/signatures — prevents timing leaks.
export function constantTimeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  const maxLen = Math.max(bufA.length, bufB.length);
  const paddedA = new Uint8Array(maxLen);
  const paddedB = new Uint8Array(maxLen);
  paddedA.set(bufA);
  paddedB.set(bufB);
  let result = 0;
  for (let i = 0; i < maxLen; i++) {
    result |= paddedA[i] ^ paddedB[i];
  }
  result |= bufA.length ^ bufB.length;
  return result === 0;
}

export interface EncryptedMetadata {
  senderId: string;
  messageType: string;
  timestamp: number;
  replyToId?: string;
}

export interface EncryptedMessage {
  messageUuid: string;
  encryptedContent: string;
  messageCounter: number;
  ivData: string;
  conversationId: string;
  keyFingerprint?: string;
  senderKeyId?: number;
  encryptionVersion?: number;
  ratchetPublicKey?: string;
  ratchetStep?: number;
  encryptedMetadata?: string;
  signature?: string;

  ephemeralKey?: string;

  usedOneTimePreKeyId?: number;

  dhCount?: number;
}

export interface KeyBundle {
  identityKey: string;
  signedPreKey: string;
  oneTimePreKey?: string;
  signature: string;
  signingPublicKey?: string;
  timestamp?: number;
  nonce?: string;
  bundleVersion?: number;

  oneTimePreKeyId?: number;
  /** keyId of `signedPreKey` (SPK-by-id). Stamped onto the message as usedSignedPreKeyId. */
  signedPreKeyId?: number;
}

export interface SenderKeyRecord {
  senderKeyId: number;
  senderKey: string;
  senderKeyChainKey: string;
  senderKeyNextId: number;
  createdAt: number;
  /**
   * The EARLIEST chain offset this receiver has ever held
   * key material for (the wire SKD snapshot's senderKeyNextId at install,
   * kept at the MIN across keep-min re-installs of the same key). A wire
   * counter below this floor is mathematically underivable here — chains
   * only derive forward — so it classifies OUT_OF_ORDER_PERMANENT instead
   * of looping SKD-reissue recovery that can never converge. Absent on
   * legacy records → treated as 0 (no permanence claims).
   */
  chainStartId?: number;
  /**
   * Chains this sender retired by rotating their sender key, newest first.
   *
   * A rotation (member departure, reinstall) installs a record with a new
   * `senderKeyId`. Without a record of the old chain, any message the sender
   * had already put on the wire before rotating becomes undecryptable the
   * instant the new key lands: `GroupMessageCipher.verifyKeyIdAndSignature`
   * rejects a wire keyId that no longer matches the installed record. Those
   * messages are in flight through no fault of the receiver.
   *
   * Retaining them costs no forward secrecy against the rotation's target: a
   * departed member already held this chain — that is precisely why it was
   * rotated away. What it does expose is undelivered old-chain messages to a
   * LATER compromise of this device, so the history is bounded on both axes
   * (`MAX_RETIRED_CHAINS`, `RETIRED_CHAIN_TTL_MS`) and entries never nest.
   */
  retiredChains?: SenderKeyRecord[];
  /** When this chain was superseded. Only set on entries inside `retiredChains`. */
  retiredAt?: number;
}

export interface SenderKeyDistributionMessage {
  id: number;
  iteration: number;
  chainKey: string;
  signingKey: string;
}

export interface PinnedIdentityKey {
  recipientId: string;
  fingerprint: string;
  identityKey: string;
  firstSeen: number;
  lastVerified: number;
  verified: boolean;
  trustLevel: 'tofu' | 'verified' | 'untrusted';
  signingPublicKey?: string;
  keyChangedAt?: number;
}

export interface IdentityKeyChangeEvent {
  recipientId: string;
  oldFingerprint: string;
  newFingerprint: string;
  oldKey: string;
  newKey: string;
  timestamp: number;
  /**
   * Trust level of the pin that was just overwritten. `'verified'`
   * means the user previously verified safety numbers in person —
   * silent rotation here is a high-severity event and the UI MUST
   * present a non-dismissable banner. `'tofu'` is the auto-trust-on-
   * first-use case and gets a softer toast. Optional so older event
   * emitters that don't set this field still type-check.
   */
  priorTrustLevel?: 'tofu' | 'verified' | 'untrusted';
}

export type VerificationMethod =
  | 'qr_code_scan'
  | 'safety_number'
  | 'fingerprint'
  | 'trusted_device'
  | 'auto_accepted'
  | 'external_channel';

export interface VerificationHistoryEntry {
  id: string;
  recipientId: string;
  recipientFingerprint: string;
  timestamp: number;
  method: VerificationMethod;
  result: 'success' | 'failed' | 'rejected';
  ourFingerprint: string;
  safetyNumber?: string;
  notes?: string;
  deviceInfo?: {
    platform: string;
    appVersion: string;
  };
}

/**
 * Which Double-Ratchet variant a session runs.
 *
 * - `legacy`: both chain keys are pre-derived from the X3DH shared secret and
 *   assigned by a send/receive tiebreak. The DH ratchet can never fire: nobody's
 *   ratchet key ever changes, so `needsDHRatchet` is never true. Forward secrecy
 *   holds (the chain KDF is one-way) but there is NO post-compromise security —
 *   one theft of the session state decrypts that conversation forever.
 * - `dh`: Signal's scheme. The initiator seeds `DHr` with the responder's signed
 *   pre-key and derives its sending chain through a DH ratchet; the responder's
 *   first receive ratchets in turn. From then on every reply advances the root
 *   key with fresh DH output, so a compromise heals after one round trip.
 *
 * Sessions are created in pairs, so the mode is a property of the SESSION, not of
 * the client: an existing `legacy` session keeps running `legacy` forever, and a
 * newly established session runs whatever {@link RATCHET_MODE_FOR_NEW_SESSIONS}
 * says. Absent on states persisted before this field existed → `legacy`.
 */
export type RatchetMode = 'legacy' | 'dh';

export interface ConversationState {
  conversationId: string;
  participantA: string;
  participantB: string;
  rootKey: string;
  chainKeySend: string;
  /**
   * Empty string means "not derived yet" — a `dh` initiator has no receiving
   * chain until the peer's first reply ratchets one in.
   */
  chainKeyReceive: string;
  ratchetMode?: RatchetMode;
  /**
   * Fingerprint of the session's ORIGINAL X3DH root key — an immutable anchor.
   *
   * The wire's `keyFingerprint` used to be taken from the LIVE root key, which
   * worked only because `legacy` never advanced it. A `dh` session ratchets the
   * root on every reply and the two ends are deliberately one step apart, so a
   * live-root comparison always mismatches and the receiver wrongly concludes the
   * peer re-handshaked (dropping the session and re-running X3DH against an
   * already-consumed one-time pre-key). Anchoring on the X3DH root keeps the
   * "did my peer start a new session?" check meaningful across ratchets.
   * Absent on pre-existing states → fall back to the live root (legacy behaviour).
   */
  x3dhRootKeyFingerprint?: string;
  sendCounter: number;
  receiveCounter: number;
  lastUpdated: number;
  createdAt?: number;
  stateVersion?: number;
  serverStateVersion?: number;
  remoteSignedPreKeyFingerprint?: string;
  remoteIdentityKeyFingerprint?: string;
  resetTimestamp?: number;
  previousSession?: {
    rootKey: string;
    chainKeyReceive: string;
    receiveCounter: number;
    remoteSignedPreKeyFingerprint?: string;
    ourRatchetKeyPair?: {
      publicKey: string;
      privateKey: string;
    };
  };
  // RATCHET-02: the peer ratchet key we most recently ratcheted PAST. A message
  // arriving under this key is out-of-order on the previous chain, NOT a new ratchet —
  // used to suppress the spurious ratchet that would otherwise thrash the ratchet and
  // overwrite the previousSession slot. Optional (undefined for pre-RATCHET-02 states).
  previousTheirRatchetKey?: string;

  ourRatchetKeyPair?: {
    publicKey: string;
    privateKey: string;
  };
  theirRatchetKey?: string;
  ratchetStep?: number;

  x3dhRole?: 'initiator' | 'responder';
  x3dhEphemeralKey?: string;
  /** keyId of the peer's SPK we sealed to — carried on the wire as usedSignedPreKeyId. */
  x3dhUsedSPKId?: number;
  x3dhUsedOPKId?: number;
  x3dhDhCount?: number;
  pendingOPKConsumption?: number;
  /**
   * Timestamp of the last X3DH responder build for this conversation.
   * `handleKeyMismatchOnEncryptedConversation` consults this before wiping
   * state — a session built within `FRESH_RESPONDER_SESSION_GRACE_MS` is
   * given a chance to self-heal via the resend path instead of being
   * nuked on its very first decrypt failure (which kicks every subsequent
   * send into NO_STATE because the sender has already stopped emitting
   * X3DH init data — see `applyPeerLivenessBookkeeping`).
   */
  freshResponderSessionAt?: number;

  unrespondedSendCount?: number;
}
