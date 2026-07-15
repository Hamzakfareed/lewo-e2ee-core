import { hexToBytes, bytesToHex, hash256, secureCompare } from '../SodiumCrypto';
import { computeKeyFingerprint } from './E2EEFingerprint';

const SAFETY_NUMBER_FP_PREFIX_HEX_LEN = 60;
const GROUP_SIZE = 5;

export class SafetyNumber {
  /**
   * Signal-style safety number: hash of (sorted) {ourId||ourKey}∪{theirId||theirKey}
   * → 60-char fingerprint → twelve 5-digit decimal groups split into two rows.
   */
  static compute(args: {
    ourUserId: string;
    ourIdentityKeyHex: string;
    theirUserId: string;
    theirIdentityKeyHex: string;
  }): string {
    const ourHash = SafetyNumber.hashUserKey(args.ourUserId, args.ourIdentityKeyHex);
    const theirHash = SafetyNumber.hashUserKey(args.theirUserId, args.theirIdentityKeyHex);
    const sorted = [ourHash, theirHash].sort();
    const combined = sorted.join('');
    const combinedFp = computeKeyFingerprint(combined, 64);
    return SafetyNumber.formatToDigits(combinedFp);
  }

  /**
   * Format the safety number for display: two rows of six 5-digit groups,
   * separated by single spaces and a newline between rows.
   */
  static formatForDisplay(safetyNumber: string): string {
    const firstHalf = safetyNumber.substring(0, 30);
    const secondHalf = safetyNumber.substring(30);
    const formatRow = (row: string): string => {
      const groups: string[] = [];
      for (let i = 0; i < row.length; i += GROUP_SIZE) {
        groups.push(row.substring(i, i + GROUP_SIZE));
      }
      return groups.join(' ');
    };
    return formatRow(firstHalf) + '\n' + formatRow(secondHalf);
  }

  /**
   * Constant-time compare of a scanned safety number against the local one,
   * with whitespace + newlines stripped from both. Returns false on any
   * format mismatch — caller should NOT leak which character differed.
   */
  static verify(localSafetyNumber: string, scannedSafetyNumber: string): boolean {
    const a = localSafetyNumber.replace(/[\s\n]/g, '');
    const b = scannedSafetyNumber.replace(/[\s\n]/g, '');
    if (a.length !== b.length) return false;
    return secureCompare(new TextEncoder().encode(a), new TextEncoder().encode(b));
  }

  /**
   * Legacy display format used by the older `getSafetyNumber()` API:
   * pinned-key fingerprint → twelve 5-digit groups in two rows.
   * Kept distinct from `compute()` to preserve the on-screen format
   * presented in older app versions.
   */
  static computeFromFingerprint(fingerprintHex: string): string {
    const fp = fingerprintHex.substring(0, SAFETY_NUMBER_FP_PREFIX_HEX_LEN);
    const groups: string[] = [];
    for (let i = 0; i < fp.length; i += GROUP_SIZE) {
      const chunk = fp.substring(i, i + GROUP_SIZE);
      const num = parseInt(chunk, 16) % 100000;
      groups.push(num.toString().padStart(GROUP_SIZE, '0'));
    }
    return groups.slice(0, 6).join(' ') + '\n' + groups.slice(6, 12).join(' ');
  }

  private static hashUserKey(userId: string, identityKeyHex: string): string {
    const encoder = new TextEncoder();
    const userIdBytes = encoder.encode(userId);
    const keyBytes = hexToBytes(identityKeyHex);
    const input = new Uint8Array(userIdBytes.length + keyBytes.length);
    input.set(userIdBytes, 0);
    input.set(keyBytes, userIdBytes.length);
    return bytesToHex(hash256(input));
  }

  private static formatToDigits(fingerprintHex: string): string {
    const fp = fingerprintHex.substring(0, SAFETY_NUMBER_FP_PREFIX_HEX_LEN);
    let result = '';
    for (let i = 0; i < fp.length; i += GROUP_SIZE) {
      const chunk = fp.substring(i, i + GROUP_SIZE);
      const num = parseInt(chunk, 16) % 100000;
      result += num.toString().padStart(GROUP_SIZE, '0');
    }
    return result;
  }
}
