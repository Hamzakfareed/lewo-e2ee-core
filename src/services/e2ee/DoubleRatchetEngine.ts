/**
 * Pure-function module for the Double Ratchet's DH-step transition.
 *
 * EXTRACTED FROM `E2EEncryptionService.ts` (Path B Phase B.7). The
 * orchestrator's `performDHRatchetStep` and `needsDHRatchet` methods
 * are now thin wrappers that delegate here so the transition logic
 * can be tested in isolation against synthetic ConversationState
 * inputs.
 *
 * The Double Ratchet has two independent ratchets:
 *   - DH ratchet: every received message with a NEW peer ratchet key
 *     triggers a fresh DH exchange that derives a new root key + new
 *     send/receive chain keys. This is what `performStep` does.
 *   - Symmetric ratchet: each message advances the chain key (KDF
 *     chain step) without a DH exchange. That is `deriveNextChainKey`
 *     in `E2EEKeyDerivation`.
 *
 * `performStep` is a pure transformation: it takes a state + a new
 * peer ratchet key, returns a new state. Side effects are limited to
 * `secureZero` calls on the local Uint8Array buffers it allocates —
 * the caller's input state is never mutated.
 */

import {
  generateX25519KeyPair,
  x25519ECDH,
  bytesToHex,
  hexToBytes,
  secureZero,
  deriveRatchetKeys,
} from '../SodiumCrypto';
import type { ConversationState } from '../E2EEncryptionService.types';
import { E2EError } from './e2eeErrors';

export class DoubleRatchetEngine {
  /**
   * Decide whether an inbound message's ratchet key requires a full
   * DH-ratchet step on our side.
   *
   *   - No `receivedRatchetKey` → no ratchet (legacy / same-key
   *     message, e.g. the very first ciphertext after X3DH).
   *   - We have no peer ratchet key yet (`!state.theirRatchetKey`) →
   *     STORE the received key but don't ratchet. A full ratchet
   *     here would derive new chain keys that don't match the
   *     sender's current sending chain (still the X3DH-initial
   *     keys), breaking decryption.
   *   - Stored key differs from received → ratchet.
   */
  static needsDHRatchet(state: ConversationState, receivedRatchetKey?: string): boolean {
    if (!receivedRatchetKey) return false;
    // A `dh` session with no peer key yet is the RESPONDER's very first receive
    // (Signal's RatchetInitBob leaves DHr unset and both chains empty). It MUST
    // ratchet here: that step derives the receiving chain matching the
    // initiator's sending chain, and mints the responder's own sending chain.
    // The `legacy` scheme cannot do this — its chains are pre-derived from the
    // shared secret, so ratcheting on first contact would desync the pair.
    if (state.ratchetMode === 'dh' && !state.theirRatchetKey) return true;
    if (!state.theirRatchetKey) return false;
    // Current chain — no ratchet.
    if (state.theirRatchetKey === receivedRatchetKey) return false;
    // RATCHET-02: a key we already ratcheted PAST is a delayed out-of-order message
    // from the previous chain, NOT a new ratchet. Ratcheting on it would thrash the
    // ratchet (K2→K1→K2…) and overwrite the single previousSession slot — losing the
    // real previous-chain state and mislabeling the message KEY_MISMATCH. Suppress it;
    // the message falls through to failure→resend recovery rather than corrupting state.
    if (state.previousTheirRatchetKey && receivedRatchetKey === state.previousTheirRatchetKey) {
      return false;
    }
    // Genuinely new peer key → real DH ratchet.
    return true;
  }

  /**
   * Perform a single DH-ratchet step.
   *
   * Pre-condition: `state.ourRatchetKeyPair` is non-null. (The X3DH
   * initiator + responder paths both set this on session
   * initialization; if it's null the conversation state is
   * irrecoverably corrupt and we must surface that to the caller
   * rather than silently re-using zeroes.)
   *
   * Behaviour:
   *  1. DH(ourCurrentPriv, theirNewPub) → receiving-chain seed
   *  2. Derive newRootKey + newReceiveChainKey
   *  3. Generate fresh ourRatchetKeyPair
   *  4. DH(ourNewPriv, theirNewPub) → sending-chain seed
   *  5. Derive finalRootKey + newSendChainKey
   *  6. Archive previous {rootKey, chainKeyReceive, receiveCounter,
   *     remoteSignedPreKeyFingerprint} as `previousSession` for
   *     out-of-order messages from the previous chain.
   *  7. Reset both counters to 0 (Signal-style — replay protection
   *     comes from the new chain keys, NOT counter monotonicity
   *     across ratchet steps).
   *  8. Bump `ratchetStep` and `lastUpdated`.
   *
   * Counters reset is deliberate: the previous "epoch * 1000000"
   * scheme triggered a MAX_ALLOWED_GAP rejection on the FIRST message
   * after every DH ratchet step.
   */
  static performStep(
    state: ConversationState,
    newTheirRatchetKey: string,
  ): ConversationState {
    if (!state.ourRatchetKeyPair) {
      throw new E2EError('DH Ratchet failed: No local ratchet key pair', 'INVALID_STATE');
    }

    // 1. DH with current ratchet pair → receive-chain seed.
    const ourPrivateKeyBytes = hexToBytes(state.ourRatchetKeyPair.privateKey);
    const theirPublicKeyBytes = hexToBytes(newTheirRatchetKey);
    const dhOutput1 = x25519ECDH(ourPrivateKeyBytes, theirPublicKeyBytes);

    // 2. Derive newRootKey1 + newReceiveChainKey from rootKey + DH1.
    const rootKeyBytes = hexToBytes(state.rootKey);
    const { newRootKey: newRootKey1, chainKey: newReceiveChainKey } = deriveRatchetKeys(
      rootKeyBytes,
      dhOutput1,
    );

    // 3. Fresh ratchet pair on our side.
    const newRatchetKeyPair = generateX25519KeyPair();
    const newOurRatchetKeyPair = {
      publicKey: bytesToHex(newRatchetKeyPair.publicKey),
      privateKey: bytesToHex(newRatchetKeyPair.privateKey),
    };

    // 4. DH with the NEW ratchet private + their key → send-chain seed.
    const dhOutput2 = x25519ECDH(newRatchetKeyPair.privateKey, theirPublicKeyBytes);

    // 5. Derive finalRootKey + newSendChainKey from newRootKey1 + DH2.
    const { newRootKey: finalRootKey, chainKey: newSendChainKey } = deriveRatchetKeys(
      newRootKey1,
      dhOutput2,
    );

    // 6. Archive the previous receive chain for out-of-order messages.
    const previousSession = state.chainKeyReceive
      ? {
          rootKey: state.rootKey,
          chainKeyReceive: state.chainKeyReceive,
          receiveCounter: state.receiveCounter,
          remoteSignedPreKeyFingerprint: state.remoteSignedPreKeyFingerprint,
        }
      : undefined;

    const newRatchetStep = (state.ratchetStep || 0) + 1;

    const newState: ConversationState = {
      ...state,
      rootKey: bytesToHex(finalRootKey),
      chainKeySend: bytesToHex(newSendChainKey),
      chainKeyReceive: bytesToHex(newReceiveChainKey),
      // 7. Reset counters — each ratchet step starts a fresh chain.
      sendCounter: 0,
      receiveCounter: 0,
      ourRatchetKeyPair: newOurRatchetKeyPair,
      theirRatchetKey: newTheirRatchetKey,
      // RATCHET-02: remember the key we just ratcheted past so a delayed message on
      // the previous chain is recognized as out-of-order (not a spurious new ratchet).
      previousTheirRatchetKey: state.theirRatchetKey,
      ratchetStep: newRatchetStep,
      lastUpdated: Date.now(),
      previousSession,
    };

    // SECURITY: Zero every intermediate Uint8Array — these can hold
    // raw key material that survives the function's lexical scope
    // until JS GC reclaims them. The hex strings on `newState` are
    // immutable so we can't zero them; defense-in-depth limits.
    secureZero(ourPrivateKeyBytes);
    secureZero(theirPublicKeyBytes);
    secureZero(dhOutput1);
    secureZero(dhOutput2);
    secureZero(rootKeyBytes);
    secureZero(newRootKey1);
    secureZero(newReceiveChainKey);
    secureZero(newSendChainKey);
    secureZero(finalRootKey);
    secureZero(newRatchetKeyPair.privateKey);

    return newState;
  }
}
