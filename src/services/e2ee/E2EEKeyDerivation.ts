/**
 * E2EE key derivation primitives — Signal-protocol-compatible KDFs.
 *
 * EXTRACTED FROM `E2EEncryptionService.ts` (Path B Phase A.1) so the
 * derivation logic can be tested in isolation, audited as a single
 * unit, and reused without dragging in the 9000-line orchestrator.
 *
 * Pure functions only. No state, no I/O, no logging beyond explicit
 * error throws. Inputs are hex strings; outputs are hex strings. All
 * sensitive byte arrays produced internally are `secureZero`'d before
 * return.
 *
 * Functions:
 *   deriveMessageKey(chainKey, counter)  → hex(messageKey)
 *     messageKey = BLAKE2b(chainKey || 0x01 || counter_LE32)
 *
 *   deriveNextChainKey(chainKey)         → hex(nextChainKey)
 *     nextChainKey = BLAKE2b(chainKey || 0x02)
 *
 * Both constants (0x01 / 0x02) are the Signal protocol's
 * domain-separation tags — DO NOT CHANGE.
 */

import { hexToBytes, bytesToHex, hash256, secureZero } from '../SodiumCrypto';
import { E2EError } from './e2eeErrors';

/**
 * Maximum counter value before re-keying is required.
 * Counter is wire-encoded as 4-byte little-endian uint32 — max 2^32 - 1.
 * Beyond this, the session MUST re-key.
 */
export const MAX_MESSAGE_COUNTER = 0xffffffff; // 4294967295

/**
 * Domain-separation byte for message-key derivation.
 * Signal-protocol convention: 0x01 = leaf key (one-shot, per-message).
 */
const MESSAGE_KEY_DERIVATION_TAG = 0x01;

/**
 * Domain-separation byte for next-chain-key derivation.
 * Signal-protocol convention: 0x02 = chain advance.
 */
const CHAIN_KEY_DERIVATION_TAG = 0x02;

/**
 * Derive a one-time-use message key from a chain key and a counter.
 *
 * Signal-protocol-compatible:
 *   messageKey = BLAKE2b-256(chainKey || 0x01 || counter_LE32)
 *
 * @param chainKey - Hex-encoded current chain key.
 * @param counter  - Non-negative integer ≤ 2^32 - 1.
 * @returns Hex-encoded 32-byte message key.
 * @throws E2EError(INVALID_PARAMS) if `counter` is null/undefined.
 * @throws E2EError(INVALID_STATE)  if `chainKey` is missing.
 * @throws E2EError(COUNTER_OVERFLOW) if `counter` exceeds the wire bound.
 */
export function deriveMessageKey(chainKey: string, counter: number): string {
  if (counter === undefined || counter === null) {
    throw new E2EError('deriveMessageKey: counter is undefined or null', 'INVALID_PARAMS');
  }
  if (!chainKey) {
    throw new E2EError('deriveMessageKey: chainKey is undefined or empty', 'INVALID_STATE');
  }
  if (
    counter < 0 ||
    counter > MAX_MESSAGE_COUNTER ||
    !Number.isInteger(counter)
  ) {
    const error = new E2EError(
      `COUNTER_OVERFLOW: Counter ${counter} is out of valid range [0, ${MAX_MESSAGE_COUNTER}]`,
      'COUNTER_OVERFLOW',
    );
    if (__DEV__) {
      console.error('🚨 [SECURITY] Counter overflow detected - session needs re-keying');
    }
    throw error;
  }

  const chainKeyBytes = hexToBytes(chainKey);

  // counter encoded as 4-byte little-endian (matches sender + receiver wire format)
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, true);

  const input = new Uint8Array(chainKeyBytes.length + 1 + 4);
  input.set(chainKeyBytes, 0);
  input[chainKeyBytes.length] = MESSAGE_KEY_DERIVATION_TAG;
  input.set(counterBytes, chainKeyBytes.length + 1);

  const messageKeyBytes = hash256(input);
  const result = bytesToHex(messageKeyBytes);

  secureZero(chainKeyBytes);
  secureZero(input);
  secureZero(messageKeyBytes);

  return result;
}

/**
 * Advance a chain key by one step.
 *
 * Signal-protocol-compatible:
 *   nextChainKey = BLAKE2b-256(chainKey || 0x02)
 *
 * @param chainKey - Hex-encoded current chain key.
 * @returns Hex-encoded 32-byte next chain key.
 * @throws E2EError(INVALID_STATE) if `chainKey` is missing.
 */
export function deriveNextChainKey(chainKey: string): string {
  if (!chainKey) {
    throw new E2EError('deriveNextChainKey: chainKey is undefined or empty', 'INVALID_STATE');
  }

  const chainKeyBytes = hexToBytes(chainKey);

  const input = new Uint8Array(chainKeyBytes.length + 1);
  input.set(chainKeyBytes, 0);
  input[chainKeyBytes.length] = CHAIN_KEY_DERIVATION_TAG;

  const nextChainKeyBytes = hash256(input);
  const result = bytesToHex(nextChainKeyBytes);

  secureZero(chainKeyBytes);
  secureZero(input);
  secureZero(nextChainKeyBytes);

  return result;
}
