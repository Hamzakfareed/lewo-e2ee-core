/**
 * Utility functions for converting between HEX and Base64 key encodings
 *
 * Our local keys are generated as HEX strings (64 chars for 32 bytes)
 * But the backend API might expect/return Base64 (44 chars for 32 bytes)
 *
 * Supports multiple key sizes:
 * - 32-byte keys (X25519, Ed25519 public keys): 64 hex chars / 44 Base64 chars
 * - 64-byte signatures (Ed25519 signatures): 128 hex chars / 88 Base64 chars
 */

/**
 * Convert HEX string to Base64
 * @param hex - Hex string (e.g., "abc123def456...")
 * @returns Base64 string
 */
export function hexToBase64(hex: string): string {
  if (!hex || hex.length === 0) {
    return hex;
  }

  // Check if already Base64
  if (!/^[0-9a-f]+$/i.test(hex)) {
    console.warn('⚠️ hexToBase64: Input does not look like HEX, returning as-is');
    return hex;
  }

  // Convert hex to bytes
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }

  // Convert bytes to Base64
  // Note: Using btoa with binary string for React Native compatibility
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

/**
 * Convert Base64 string to HEX
 * @param base64 - Base64 string
 * @returns Hex string
 */
export function base64ToHex(base64: string): string {
  if (!base64 || base64.length === 0) {
    return base64;
  }

  // Check if already HEX (any even-length string of only hex characters)
  if (/^[0-9a-f]+$/i.test(base64) && base64.length % 2 === 0) {
    console.warn('⚠️ base64ToHex: Input looks like HEX already, returning as-is');
    return base64;
  }

  try {
    // Decode Base64 to binary string
    const binary = atob(base64);

    // Convert binary string to hex
    let hex = '';
    for (let i = 0; i < binary.length; i++) {
      const byte = binary.charCodeAt(i);
      hex += byte.toString(16).padStart(2, '0');
    }

    return hex;
  } catch (error) {
    console.error('❌ base64ToHex: Failed to decode Base64:', error);
    return base64; // Return as-is if conversion fails
  }
}

/**
 * Detect the encoding of a key string.
 * Supports multiple key sizes:
 * - 32-byte keys: 64 hex chars / 44 Base64 chars
 * - 64-byte signatures: 128 hex chars / 88 Base64 chars
 * @param key - Key string to analyze
 * @returns 'HEX', 'BASE64', or 'UNKNOWN'
 */
export function detectKeyEncoding(key: string): 'HEX' | 'BASE64' | 'UNKNOWN' {
  if (!key || key.length === 0) {
    return 'UNKNOWN';
  }

  // Check for HEX (only 0-9, a-f, A-F, even length)
  const isHex = /^[0-9a-f]+$/i.test(key) && key.length % 2 === 0;

  // Check for Base64 characters (contains +, /, or = which are not valid hex)
  const hasBase64OnlyChars = /[+/=]/.test(key);

  // Known hex lengths: 64 (32-byte key), 128 (64-byte signature)
  const knownHexLengths = [64, 128];

  // Known Base64 lengths: 44 (32-byte key), 88 (64-byte signature)
  // Also accept without padding: 43, 86
  const knownBase64Lengths = [43, 44, 86, 88];

  if (isHex && knownHexLengths.includes(key.length)) {
    return 'HEX';
  }

  // If it has Base64-only characters (+, /, =), it's definitely Base64
  if (hasBase64OnlyChars) {
    return 'BASE64';
  }

  // Ambiguous: all hex characters but could also be Base64 (a-f overlap with Base64 charset)
  // Use length heuristic
  if (isHex) {
    // Even-length hex string of a reasonable key size
    return 'HEX';
  }

  // Check if it's a valid Base64 string by length
  if (/^[A-Za-z0-9+/=]+$/.test(key) && knownBase64Lengths.includes(key.length)) {
    return 'BASE64';
  }

  return 'UNKNOWN';
}

/**
 * Normalize a key to HEX format (our internal standard)
 * Converts Base64 to HEX if needed, otherwise returns as-is
 * @param key - Key in any format
 * @returns Key in HEX format
 */
export function normalizeKeyToHex(key: string): string {
  const encoding = detectKeyEncoding(key);

  if (__DEV__) {
    console.log(`🔄 [KEY NORMALIZE] Detected encoding: ${encoding} (length: ${key.length})`);
  }

  if (encoding === 'BASE64') {
    if (__DEV__) console.log('🔄 [KEY NORMALIZE] Converting Base64 → HEX');
    const hexKey = base64ToHex(key);
    if (__DEV__) console.log(`🔄 [KEY NORMALIZE] Result: ${hexKey.substring(0, 40)}... (length: ${hexKey.length})`);
    return hexKey;
  } else if (encoding === 'HEX') {
    if (__DEV__) console.log('🔄 [KEY NORMALIZE] Already HEX, no conversion needed');
    return key;
  } else {
    console.warn('⚠️ [KEY NORMALIZE] Unknown encoding, returning as-is');
    return key;
  }
}

/**
 * Normalize a key bundle to HEX format
 * Converts all keys from Base64 to HEX if needed
 */
export function normalizeKeyBundle(keyBundle: {
  identityKey: string;
  signedPreKey: string;
  signature: string;
  oneTimePreKey?: string;
}): {
  identityKey: string;
  signedPreKey: string;
  signature: string;
  oneTimePreKey?: string;
} {
  if (__DEV__) {
    console.log('========================================');
    console.log('🔄 [KEY BUNDLE NORMALIZE] Normalizing key bundle to HEX');
    console.log('========================================');
  }

  return {
    identityKey: normalizeKeyToHex(keyBundle.identityKey),
    signedPreKey: normalizeKeyToHex(keyBundle.signedPreKey),
    signature: normalizeKeyToHex(keyBundle.signature),
    oneTimePreKey: keyBundle.oneTimePreKey ? normalizeKeyToHex(keyBundle.oneTimePreKey) : undefined,
  };
}
