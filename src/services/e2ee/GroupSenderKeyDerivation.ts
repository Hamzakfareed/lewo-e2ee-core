import { hexToBytes, bytesToHex, deriveKey, hash256, secureZero } from '../SodiumCrypto';

const KDF_INFO_MK = new Uint8Array([0x4d, 0x4b]); // "MK"
const KDF_INFO_CK = new Uint8Array([0x43, 0x4b]); // "CK"
const KDF_LABEL_MK = 0x01;
const KDF_LABEL_CK = 0x02;

/**
 * Advances a Sender Key chain one step. Same shape as the Signal-style
 * chain ratchet: a single chain key produces both the message key for the
 * current send and the next chain key for the next send. The two outputs
 * are domain-separated by a single-byte label (`0x01` for MK, `0x02` for
 * CK) and KDF info ("MK" / "CK") so neither output reveals the other.
 *
 * Pure — secure-zeroes its temp buffers but doesn't touch any state.
 */
export function ratchetGroupChainKey(chainKeyHex: string): {
  messageKey: string;
  newChainKey: string;
} {
  const chainKeyBytes = hexToBytes(chainKeyHex);

  const messageKeyInput = new Uint8Array([...chainKeyBytes, KDF_LABEL_MK]);
  const messageKey = deriveKey(messageKeyInput, KDF_INFO_MK, 32);

  const chainKeyInput = new Uint8Array([...chainKeyBytes, KDF_LABEL_CK]);
  const newChainKey = deriveKey(chainKeyInput, KDF_INFO_CK, 32);

  secureZero(chainKeyBytes);
  secureZero(messageKeyInput);
  secureZero(chainKeyInput);

  return {
    messageKey: bytesToHex(messageKey),
    newChainKey: bytesToHex(newChainKey),
  };
}

/**
 * Hashes a public key and formats the first `byteLength` bytes as a
 * dash-separated, uppercase-hex fingerprint string in 4-char groups. Used
 * by safety-number UI surfaces and by debug logs to identify a member at
 * a glance.
 *
 * - Group identity uses 8 bytes → "XXXX-XXXX-XXXX-XXXX" (16 hex chars)
 * - Channel identity uses 16 bytes → 8 4-char groups (32 hex chars) for
 *   stronger collision resistance against a larger subscriber pool.
 */
export function computeGroupKeyFingerprint(publicKeyHex: string, byteLength = 8): string {
  const keyBytes = hexToBytes(publicKeyHex);
  const hash = hash256(keyBytes);
  const hex = Array.from(hash.slice(0, byteLength))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < hex.length; i += 4) {
    groups.push(hex.slice(i, i + 4));
  }
  return groups.join('-');
}
