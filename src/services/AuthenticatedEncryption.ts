/**
 * AuthenticatedEncryption - AES-256-GCM Authenticated Encryption
 *
 * SECURITY: This module provides authenticated encryption using AES-256-GCM
 * via the Web Crypto API. This replaces the insecure AES-CBC mode.
 *
 * AES-GCM provides:
 * - Confidentiality (encryption)
 * - Integrity (authentication tag detects tampering)
 * - Protection against padding oracle attacks
 *
 * Note: The primary E2EE path uses XChaCha20-Poly1305 via the @noble libraries (see SodiumCrypto).
 * for better security margins and nonce-misuse resistance.
 */

// Constants for AES-256-GCM
const AES_GCM_CONFIG = {
  ALGORITHM: 'AES-GCM',
  KEY_LENGTH: 256, // bits
  IV_LENGTH: 12, // 96 bits - recommended for GCM
  TAG_LENGTH: 128, // bits - maximum authentication strength
} as const;

/**
 * SECURITY: Algorithm version byte for ciphertext format identification
 *
 * This versioning system enables:
 * 1. Backward compatibility - can decrypt old formats
 * 2. Forward migration - can upgrade to new algorithms without breaking
 * 3. Graceful deprecation - can phase out old algorithms
 *
 * Version byte is included in all ciphertext as the `v` field in the JSON envelope.
 *
 * Migration path:
 * - v0 (AES-CBC): DEPRECATED - Vulnerable to padding oracle attacks
 * - v1 (AES-GCM): LEGACY - Secure but 96-bit nonce limits
 * - v2 (XChaCha20-Poly1305): CURRENT - 192-bit nonce, nonce-misuse resistant
 * - v3: RESERVED for future post-quantum algorithms (e.g., ML-KEM/Kyber hybrid)
 *
 * Adding new algorithms:
 * 1. Add new version constant below
 * 2. Implement encrypt/decrypt functions in appropriate service
 * 3. Update E2EEncryptionService to handle new version in decryption
 * 4. Gradually migrate by encrypting with new version, decrypting all versions
 */
const ENCRYPTION_VERSION = {
  AES_CBC_LEGACY: 0x00, // Legacy CBC (no auth tag) - DEPRECATED, DO NOT USE
  AES_GCM_V1: 0x01, // AES-256-GCM (Web Crypto API) - Legacy but supported
  XCHACHA20_POLY1305_V1: 0x02, // XChaCha20-Poly1305 (@noble/ciphers) - RECOMMENDED
  // RESERVED for future:
  // PQ_HYBRID_V1: 0x03, // Post-quantum hybrid (e.g., X25519+ML-KEM + XChaCha20-Poly1305)
} as const;

export interface AuthenticatedCiphertext {
  version: number;
  iv: string; // hex encoded
  ciphertext: string; // base64 encoded
  tag: string; // hex encoded (GCM auth tag)
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert Uint8Array to base64 string
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Import a raw key for AES-GCM operations
 */
async function importKey(keyHex: string): Promise<CryptoKey> {
  const keyBytes = hexToBytes(keyHex);

  if (keyBytes.length !== 32) {
    throw new Error(`Invalid key length: expected 32 bytes, got ${keyBytes.length}`);
  }

  // Use .slice() to get a fresh ArrayBuffer — .buffer may include extra bytes
  // when keyBytes is a view into a larger ArrayBuffer (I10 fix)
  return await crypto.subtle.importKey(
    'raw',
    keyBytes.slice().buffer as ArrayBuffer,
    { name: AES_GCM_CONFIG.ALGORITHM },
    false, // not extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate a cryptographically secure IV for AES-GCM
 */
function generateIV(): Uint8Array {
  const iv = new Uint8Array(AES_GCM_CONFIG.IV_LENGTH);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * Encrypt plaintext using AES-256-GCM
 *
 * @param plaintext - The message to encrypt (UTF-8 string)
 * @param keyHex - The 256-bit key as hex string (64 characters)
 * @returns AuthenticatedCiphertext with version, IV, ciphertext, and auth tag
 */
export async function encryptAESGCM(
  plaintext: string,
  keyHex: string
): Promise<AuthenticatedCiphertext> {
  if (!plaintext) {
    throw new Error('Cannot encrypt empty plaintext');
  }

  // Import the key
  const cryptoKey = await importKey(keyHex);

  // Generate random IV
  const iv = generateIV();

  // Encode plaintext to bytes
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // Encrypt with AES-GCM
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: AES_GCM_CONFIG.ALGORITHM,
      iv: iv.buffer as ArrayBuffer,
      tagLength: AES_GCM_CONFIG.TAG_LENGTH,
    },
    cryptoKey,
    plaintextBytes.buffer as ArrayBuffer
  );

  // AES-GCM appends the auth tag to the ciphertext
  // Extract ciphertext and tag
  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const tagLength = AES_GCM_CONFIG.TAG_LENGTH / 8; // bytes
  const ciphertextBytes = encryptedBytes.slice(0, -tagLength);
  const tagBytes = encryptedBytes.slice(-tagLength);

  return {
    version: ENCRYPTION_VERSION.AES_GCM_V1,
    iv: bytesToHex(iv),
    ciphertext: bytesToBase64(ciphertextBytes),
    tag: bytesToHex(tagBytes),
  };
}

/**
 * Decrypt ciphertext using AES-256-GCM
 *
 * @param encrypted - The authenticated ciphertext object
 * @param keyHex - The 256-bit key as hex string (64 characters)
 * @returns Decrypted plaintext string
 * @throws Error if decryption fails or authentication tag is invalid
 */
export async function decryptAESGCM(
  encrypted: AuthenticatedCiphertext,
  keyHex: string
): Promise<string> {
  if (encrypted.version !== ENCRYPTION_VERSION.AES_GCM_V1) {
    throw new Error(`Unsupported encryption version: ${encrypted.version}`);
  }

  // Import the key
  const cryptoKey = await importKey(keyHex);

  // Decode IV, ciphertext, and tag
  const iv = hexToBytes(encrypted.iv);
  const ciphertextBytes = base64ToBytes(encrypted.ciphertext);
  const tagBytes = hexToBytes(encrypted.tag);

  // Reconstruct the encrypted buffer (ciphertext + tag)
  const encryptedBytes = new Uint8Array(ciphertextBytes.length + tagBytes.length);
  encryptedBytes.set(ciphertextBytes, 0);
  encryptedBytes.set(tagBytes, ciphertextBytes.length);

  // Decrypt with AES-GCM (will throw if auth tag is invalid)
  let decryptedBuffer: ArrayBuffer;
  try {
    decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: AES_GCM_CONFIG.ALGORITHM,
        iv: iv.buffer as ArrayBuffer,
        tagLength: AES_GCM_CONFIG.TAG_LENGTH,
      },
      cryptoKey,
      encryptedBytes.buffer as ArrayBuffer
    );
  } catch (error) {
    // Authentication failure - ciphertext was tampered with or wrong key
    throw new Error('Decryption failed: authentication tag mismatch (message may have been tampered)');
  }

  // Decode plaintext
  const plaintext = new TextDecoder().decode(decryptedBuffer);

  if (!plaintext) {
    throw new Error('Decryption produced empty result');
  }

  return plaintext;
}

/**
 * Serialize authenticated ciphertext to a single string for storage/transmission
 * Format: version|iv|ciphertext|tag (all base64 encoded except version)
 */
export function serializeCiphertext(encrypted: AuthenticatedCiphertext): string {
  return JSON.stringify({
    v: encrypted.version,
    i: encrypted.iv,
    c: encrypted.ciphertext,
    t: encrypted.tag,
  });
}

/**
 * Deserialize a ciphertext string back to AuthenticatedCiphertext
 */
export function deserializeCiphertext(serialized: string): AuthenticatedCiphertext | null {
  try {
    // Try to parse as new JSON format
    const parsed = JSON.parse(serialized);
    if (typeof parsed === 'object' && 'v' in parsed) {
      return {
        version: parsed.v,
        iv: parsed.i,
        ciphertext: parsed.c,
        tag: parsed.t,
      };
    }
  } catch {
    // Not JSON - might be legacy CBC format
  }

  // Return null to indicate legacy format
  return null;
}

/**
 * Check if a ciphertext string is in the new authenticated format
 */
export function isAuthenticatedFormat(serialized: string): boolean {
  return deserializeCiphertext(serialized) !== null;
}

/**
 * Check if ciphertext uses XChaCha20-Poly1305 (recommended format)
 */
export function isXChaCha20Format(serialized: string): boolean {
  const ciphertext = deserializeCiphertext(serialized);
  return ciphertext !== null && ciphertext.version === ENCRYPTION_VERSION.XCHACHA20_POLY1305_V1;
}

/**
 * Export version constants for external use
 */
export { ENCRYPTION_VERSION, AES_GCM_CONFIG };
