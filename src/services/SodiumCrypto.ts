/**
 * SodiumCrypto - Pure JavaScript cryptographic primitives for E2EE
 *
 * SECURITY: This module provides Signal Protocol compatible cryptographic operations:
 * - X25519 ECDH for key agreement
 * - Ed25519 for digital signatures (for SPK verification)
 * - XChaCha20-Poly1305 for authenticated encryption
 * - BLAKE2b for key derivation (Signal Protocol compatible)
 *
 * IMPLEMENTATION: Uses @noble/* libraries which are:
 * - Pure JavaScript (NO WebAssembly required - works with Hermes!)
 * - Audited and battle-tested (used by Ethereum ecosystem)
 * - Constant-time implementations to prevent timing attacks
 * - Compatible with libsodium output formats
 *
 * This replaces libsodium-wrappers which requires WebAssembly (not supported by Hermes).
 */

import { x25519, ed25519, edwardsToMontgomeryPub } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { blake2b } from '@noble/hashes/blake2b';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { randomBytes as nobleRandomBytes, bytesToHex as nobleBytesToHex, hexToBytes as nobleHexToBytes } from '@noble/hashes/utils';

// Declare __DEV__ for React Native
declare const __DEV__: boolean;

// Track initialization state (instant for pure JS - no async loading needed)
let isInitialized = false;

// In-flight init promise. Cached at module scope so concurrent callers dedupe
// onto the same RNG-health retry chain instead of starting independent ones.
// Reset to null on failure so a subsequent call can retry from scratch.
let initPromise: Promise<void> | null = null;

// RNG health check result
let rngHealthy = false;

/**
 * SECURITY: Verify the Random Number Generator is providing proper entropy.
 * This detects broken/predictable RNG implementations that would compromise all crypto.
 *
 * Tests:
 * 1. Non-zero output (detects all-zero bug)
 * 2. Different outputs on consecutive calls (detects stuck RNG)
 * 3. Reasonable distribution (detects severely biased RNG)
 *
 * @throws Error if RNG fails health check
 */
function verifyRNGHealth(): void {
  const SAMPLE_SIZE = 32;
  const NUM_SAMPLES = 3;

  const samples: Uint8Array[] = [];

  // Collect multiple samples
  for (let i = 0; i < NUM_SAMPLES; i++) {
    samples.push(nobleRandomBytes(SAMPLE_SIZE));
  }

  // Test 1: Check for all-zero output (catastrophic failure)
  for (let i = 0; i < NUM_SAMPLES; i++) {
    const isAllZero = samples[i].every(byte => byte === 0);
    if (isAllZero) {
      throw new Error('CRITICAL: RNG health check failed - all-zero output detected. Cryptographic operations are UNSAFE.');
    }
  }

  // Test 2: Check that consecutive outputs are different (stuck RNG)
  for (let i = 1; i < NUM_SAMPLES; i++) {
    const prev = samples[i - 1];
    const curr = samples[i];
    let identical = true;
    for (let j = 0; j < SAMPLE_SIZE; j++) {
      if (prev[j] !== curr[j]) {
        identical = false;
        break;
      }
    }
    if (identical) {
      throw new Error('CRITICAL: RNG health check failed - identical consecutive outputs. RNG may be stuck.');
    }
  }

  // Test 3: Basic distribution check - count unique bytes
  // A healthy 32-byte random sample should have many unique values
  const uniqueBytes = new Set<number>();
  for (const sample of samples) {
    for (const byte of sample) {
      uniqueBytes.add(byte);
    }
  }
  // With 96 random bytes (3 samples × 32 bytes), we expect ~60+ unique values
  // Threshold of 20 is very conservative to avoid false positives
  if (uniqueBytes.size < 20) {
    throw new Error(`CRITICAL: RNG health check failed - poor entropy (only ${uniqueBytes.size} unique bytes in ${NUM_SAMPLES * SAMPLE_SIZE} bytes). RNG may be biased.`);
  }

  if (__DEV__) console.log(`✅ [SodiumCrypto] RNG health check passed (${uniqueBytes.size} unique bytes across ${NUM_SAMPLES * SAMPLE_SIZE} sampled bytes)`);
}

/**
 * Check if RNG passed health verification
 */
export function isRNGHealthy(): boolean {
  return rngHealthy;
}

/**
 * Initialize crypto - For pure JS, this is instant (no WebAssembly to load)
 * Kept for API compatibility with the previous libsodium version
 *
 * SECURITY: Includes RNG health verification on startup.
 * Retries the health check a few times to absorb transient entropy issues
 * seen on real iOS devices during cold start (the `react-native-get-random-values`
 * polyfill can be momentarily unavailable on the first call). Without retries,
 * a single transient failure permanently disables E2EE for the session.
 */
export function initializeSodium(): Promise<void> {
  if (isInitialized) return Promise.resolve();
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const MAX_ATTEMPTS = 3;
    let lastError: unknown;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        verifyRNGHealth();
        rngHealthy = true;
        isInitialized = true;
        if (__DEV__) {
          console.log(
            `🔐 [SodiumCrypto] Initialized on attempt ${attempt}/${MAX_ATTEMPTS}`
          );
        }
        return;
      } catch (error) {
        lastError = error;
        if (attempt < MAX_ATTEMPTS) {
          await new Promise((resolve) => setTimeout(resolve, 50 * attempt));
        }
      }
    }

    // Reset so a future call can retry from scratch instead of being stuck
    // on a permanently-rejected promise.
    initPromise = null;
    // Bubble up so callers can react instead of silently treating crypto as ready.
    throw lastError instanceof Error
      ? lastError
      : new Error('SodiumCrypto initialization failed after retries');
  })();

  return initPromise;
}

/**
 * Resolves once SodiumCrypto is safe to use. Idempotent and concurrent-safe.
 * If init has not yet been kicked off by the app, kicks it off — relies on
 * the deduped initPromise to ensure only one RNG-health retry chain runs.
 */
export function whenSodiumReady(): Promise<void> {
  if (isInitialized) return Promise.resolve();
  if (initPromise) return initPromise;
  return initializeSodium();
}

/**
 * Ensure crypto is initialized before operations
 */
function ensureInitialized(): void {
  if (!isInitialized) {
    throw new Error(
      'SodiumCrypto not initialized. Call initializeSodium() at app startup.'
    );
  }
}

// ============================================
// X25519 ECDH Key Agreement (Signal Protocol X3DH)
// ============================================

export interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generate an X25519 key pair for ECDH key agreement
 * Used for: Identity Keys (IK), Signed Pre-Keys (SPK), One-Time Pre-Keys (OPK), Ephemeral Keys (EK)
 */
export function generateX25519KeyPair(): X25519KeyPair {
  ensureInitialized();

  // Generate 32-byte random private key
  const privateKey = nobleRandomBytes(32);
  // Derive public key from private key
  const publicKey = x25519.getPublicKey(privateKey);

  return {
    publicKey,
    privateKey,
  };
}

/**
 * Perform X25519 ECDH to compute shared secret
 * This is the core of Signal Protocol's X3DH key agreement
 *
 * @param ourPrivateKey - Our X25519 private key (must be 32 bytes)
 * @param theirPublicKey - Their X25519 public key (must be 32 bytes)
 * @returns 32-byte shared secret
 * @throws Error if keys are invalid size
 */
export function x25519ECDH(
  ourPrivateKey: Uint8Array,
  theirPublicKey: Uint8Array
): Uint8Array {
  ensureInitialized();

  // SECURITY: Validate key sizes to prevent undefined behavior
  if (!ourPrivateKey || ourPrivateKey.length !== CONSTANTS.X25519_PRIVATE_KEY_BYTES) {
    throw new Error(
      `Invalid private key: expected ${CONSTANTS.X25519_PRIVATE_KEY_BYTES} bytes, got ${ourPrivateKey?.length ?? 0}`
    );
  }
  if (!theirPublicKey || theirPublicKey.length !== CONSTANTS.X25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `Invalid public key: expected ${CONSTANTS.X25519_PUBLIC_KEY_BYTES} bytes, got ${theirPublicKey?.length ?? 0}`
    );
  }

  // Compute shared secret using X25519 scalar multiplication
  const shared = x25519.getSharedSecret(ourPrivateKey, theirPublicKey);

  // SECURITY: Validate shared secret is not all zeros (low-order point attack)
  const isZero = shared.every((b: number) => b === 0);
  if (isZero) {
    // SECURITY FIX (M10): Wipe the invalid shared secret before throwing
    secureZero(shared);
    throw new Error('ECDH_INVALID: low-order point detected — possible small-subgroup attack');
  }

  // SECURITY FIX (M10): Return a copy so caller owns it; the original
  // intermediate is wiped. Caller is responsible for wiping the returned copy.
  const result = new Uint8Array(shared);
  secureZero(shared);
  return result;
}

// ============================================
// Ed25519 Digital Signatures (for SPK signing)
// ============================================

export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array; // 64 bytes (includes public key) for libsodium compat
}

/**
 * Generate an Ed25519 key pair for digital signatures
 * Used for: Identity Key signing operations
 */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  ensureInitialized();

  // Generate 32-byte seed/private key
  const seed = nobleRandomBytes(32);
  // Get public key
  const publicKey = ed25519.getPublicKey(seed);

  // Create 64-byte private key format (seed + public key) for libsodium compatibility
  const privateKey = new Uint8Array(64);
  privateKey.set(seed, 0);
  privateKey.set(publicKey, 32);

  return {
    publicKey,
    privateKey,
  };
}

/**
 * Convert X25519 private key to Ed25519 signing key
 * Signal Protocol uses a single identity key for both ECDH and signing
 *
 * SECURITY: The correct conversion uses SHA-512 to hash the X25519 private key
 * (which acts as the seed), then applies Ed25519 clamping to the first 32 bytes.
 * This matches the standard Ed25519 key derivation from RFC 8032:
 *   1. Hash the seed with SHA-512 to get 64 bytes
 *   2. Clamp the lower 32 bytes (clear bits 0,1,2,255; set bit 254)
 *   3. Use the clamped scalar as the Ed25519 private scalar
 *
 * The @noble/curves ed25519.getPublicKey() internally performs this SHA-512 +
 * clamping when given a 32-byte seed, so we use the X25519 private key
 * directly as the Ed25519 seed.
 *
 * @param x25519Private - X25519 private key (must be 32 bytes)
 * @returns 64-byte Ed25519 private key (seed + public key)
 * @throws Error if input key is invalid size
 */
export function x25519PrivateToEd25519(x25519Private: Uint8Array): Uint8Array {
  ensureInitialized();

  // SECURITY: Validate input key size
  if (!x25519Private || x25519Private.length !== CONSTANTS.X25519_PRIVATE_KEY_BYTES) {
    throw new Error(
      `Invalid X25519 private key: expected ${CONSTANTS.X25519_PRIVATE_KEY_BYTES} bytes, got ${x25519Private?.length ?? 0}`
    );
  }

  // Use the X25519 private key directly as the Ed25519 seed.
  // ed25519.getPublicKey() internally performs SHA-512 hashing and clamping
  // per RFC 8032 to derive the Ed25519 public key from this seed.
  const seed = x25519Private;
  const publicKey = ed25519.getPublicKey(seed);

  // Create 64-byte private key format (seed + public key) for libsodium compatibility
  const privateKey = new Uint8Array(64);
  privateKey.set(seed, 0);
  privateKey.set(publicKey, 32);

  return privateKey;
}

/**
 * Convert an Ed25519 public key to an X25519 public key
 *
 * SECURITY: Ed25519 keys (used for signing) and X25519 keys (used for ECDH)
 * live on different curves. This function performs the birational map from the
 * Edwards curve to the Montgomery curve so that an Ed25519 identity/signing
 * public key can be used for X25519 key agreement.
 *
 * @param ed25519PublicKey - Ed25519 public key (must be 32 bytes)
 * @returns 32-byte X25519 public key suitable for ECDH
 * @throws Error if input key is invalid size
 */
export function ed25519PublicKeyToX25519(ed25519PublicKey: Uint8Array): Uint8Array {
  ensureInitialized();

  if (!ed25519PublicKey || ed25519PublicKey.length !== 32) {
    throw new Error(
      `Invalid Ed25519 public key: expected 32 bytes, got ${ed25519PublicKey?.length ?? 0}`
    );
  }

  return edwardsToMontgomeryPub(ed25519PublicKey);
}

/**
 * Sign a message using Ed25519
 * Used for: Signing Signed Pre-Keys with Identity Key
 *
 * @param message - Message to sign (must not be null/undefined)
 * @param privateKey - Ed25519 private key (64 bytes: seed + pubkey, or 32-byte seed)
 * @returns 64-byte signature
 * @throws Error if message or private key is invalid
 */
export function ed25519Sign(
  message: Uint8Array,
  privateKey: Uint8Array
): Uint8Array {
  ensureInitialized();

  // SECURITY: Validate inputs
  if (!message) {
    throw new Error('Message is required for signing');
  }
  if (!privateKey) {
    throw new Error('Private key is required for signing');
  }
  if (privateKey.length !== 32 && privateKey.length !== CONSTANTS.ED25519_PRIVATE_KEY_BYTES) {
    throw new Error(
      `Invalid Ed25519 private key: expected 32 or ${CONSTANTS.ED25519_PRIVATE_KEY_BYTES} bytes, got ${privateKey.length}`
    );
  }

  // Extract 32-byte seed from 64-byte private key if needed
  const seed = privateKey.length === 64 ? privateKey.slice(0, 32) : privateKey;
  const signature = ed25519.sign(message, seed);
  // SECURITY FIX (M10): Wipe the extracted seed copy if we sliced it
  if (privateKey.length === 64) {
    secureZero(seed);
  }
  return signature;
}

/**
 * Verify an Ed25519 signature
 * Used for: Verifying SPK signatures before use
 *
 * @param message - Original message (must not be null/undefined)
 * @param signature - 64-byte signature
 * @param publicKey - Ed25519 public key (32 bytes)
 * @returns true if signature is valid
 * @throws Error if inputs are invalid (to prevent silent failures on malformed data)
 */
export function ed25519Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  ensureInitialized();

  // SECURITY: Validate inputs - throw on invalid sizes to catch bugs
  // (not for invalid signatures - those return false)
  if (!message) {
    throw new Error('Message is required for signature verification');
  }
  if (!signature || signature.length !== CONSTANTS.ED25519_SIGNATURE_BYTES) {
    throw new Error(
      `Invalid signature: expected ${CONSTANTS.ED25519_SIGNATURE_BYTES} bytes, got ${signature?.length ?? 0}`
    );
  }
  if (!publicKey || publicKey.length !== CONSTANTS.ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `Invalid public key: expected ${CONSTANTS.ED25519_PUBLIC_KEY_BYTES} bytes, got ${publicKey?.length ?? 0}`
    );
  }

  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    // Verification failure (invalid signature) returns false, not an exception
    return false;
  }
}

// ============================================
// XChaCha20-Poly1305 Authenticated Encryption
// ============================================

export interface EncryptedData {
  nonce: Uint8Array; // 24 bytes for XChaCha20
  ciphertext: Uint8Array; // includes Poly1305 tag
}

/**
 * Encrypt using XChaCha20-Poly1305 (authenticated encryption)
 * Better than AES-GCM: 24-byte nonce (vs 12), nonce-misuse resistant
 *
 * @param plaintext - Data to encrypt (must not be null/undefined)
 * @param key - 32-byte encryption key
 * @param aad - Optional Associated Data (AAD) bound to the ciphertext via Poly1305 tag.
 *              AAD is authenticated but NOT encrypted. If provided during encryption,
 *              the same AAD MUST be provided during decryption or authentication will fail.
 *              Signal Protocol uses this to bind message headers (conversationId, counter,
 *              ratchet key) to the ciphertext, preventing header manipulation attacks.
 * @returns Nonce and ciphertext with authentication tag
 * @throws Error if key is invalid size
 */
export function encryptXChaCha20Poly1305(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad?: Uint8Array
): EncryptedData {
  ensureInitialized();

  // SECURITY: Validate inputs
  if (!plaintext) {
    throw new Error('Plaintext is required for encryption');
  }
  if (!key || key.length !== CONSTANTS.XCHACHA20_KEY_BYTES) {
    throw new Error(
      `Invalid encryption key: expected ${CONSTANTS.XCHACHA20_KEY_BYTES} bytes, got ${key?.length ?? 0}`
    );
  }

  // Generate random 24-byte nonce
  const nonce = nobleRandomBytes(CONSTANTS.XCHACHA20_NONCE_BYTES);

  // SECURITY: Validate nonce length before use
  if (nonce.length !== CONSTANTS.XCHACHA20_NONCE_BYTES) {
    throw new Error(
      `CRITICAL: RNG returned invalid nonce length: expected ${CONSTANTS.XCHACHA20_NONCE_BYTES} bytes, got ${nonce.length}. Encryption aborted.`
    );
  }

  // Encrypt with XChaCha20-Poly1305, optionally binding AAD to the authentication tag
  const cipher = xchacha20poly1305(key, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { nonce, ciphertext };
}

/**
 * Encrypt using XChaCha20-Poly1305 with a provided nonce
 *
 * SECURITY: Only use when you have a deterministic nonce scheme that
 * guarantees uniqueness (e.g., chunk index XOR'd with base nonce).
 * For most cases, use encryptXChaCha20Poly1305 which generates a random nonce.
 *
 * @param plaintext - Data to encrypt (must not be null/undefined)
 * @param key - 32-byte encryption key
 * @param nonce - 24-byte nonce (MUST be unique for each encryption with same key)
 * @returns Ciphertext with authentication tag
 * @throws Error if key or nonce is invalid size
 */
export function encryptXChaCha20Poly1305WithNonce(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  ensureInitialized();

  // SECURITY: Validate all inputs
  if (!plaintext) {
    throw new Error('Plaintext is required for encryption');
  }
  if (!key || key.length !== CONSTANTS.XCHACHA20_KEY_BYTES) {
    throw new Error(
      `Invalid encryption key: expected ${CONSTANTS.XCHACHA20_KEY_BYTES} bytes, got ${key?.length ?? 0}`
    );
  }
  if (!nonce || nonce.length !== CONSTANTS.XCHACHA20_NONCE_BYTES) {
    throw new Error(
      `Invalid nonce: expected ${CONSTANTS.XCHACHA20_NONCE_BYTES} bytes, got ${nonce?.length ?? 0}`
    );
  }

  // Encrypt with XChaCha20-Poly1305
  const cipher = xchacha20poly1305(key, nonce);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt using XChaCha20-Poly1305
 * Verifies authentication tag before returning plaintext
 *
 * Supports two call signatures:
 * 1. decryptXChaCha20Poly1305(encrypted: EncryptedData, key: Uint8Array, aad?: Uint8Array)
 * 2. decryptXChaCha20Poly1305(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array, aad?: Uint8Array)
 *
 * @param encryptedOrCiphertext - Either EncryptedData object or raw ciphertext bytes
 * @param keyOrNonce - Either 32-byte key (if first param is EncryptedData) or 24-byte nonce
 * @param keyOrAad - 32-byte encryption key (3-param) OR optional AAD (2-param)
 * @param aad - Optional Associated Data (only for 4-param signature).
 *              Must match the AAD used during encryption for authentication to succeed.
 * @returns Decrypted plaintext
 * @throws Error if authentication fails (tampering detected) or inputs are invalid
 */
export function decryptXChaCha20Poly1305(
  encryptedOrCiphertext: EncryptedData | Uint8Array,
  keyOrNonce: Uint8Array,
  keyOrAad?: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  ensureInitialized();

  let ciphertext: Uint8Array;
  let nonce: Uint8Array;
  let decryptionKey: Uint8Array;
  let associatedData: Uint8Array | undefined;

  // Determine which signature is being used
  if (
    encryptedOrCiphertext &&
    typeof encryptedOrCiphertext === 'object' &&
    'ciphertext' in encryptedOrCiphertext &&
    'nonce' in encryptedOrCiphertext
  ) {
    // 2-parameter signature with EncryptedData object: ({ ciphertext, nonce }, key, aad?)
    const encrypted = encryptedOrCiphertext as EncryptedData;
    ciphertext = encrypted.ciphertext;
    nonce = encrypted.nonce;
    decryptionKey = keyOrNonce;
    associatedData = keyOrAad; // 3rd param is optional AAD in this signature
  } else if (encryptedOrCiphertext instanceof Uint8Array && keyOrAad !== undefined) {
    // 3/4-parameter signature: (ciphertext, nonce, key, aad?). Detect it by
    // the FIRST arg being raw ciphertext bytes AND a key arg being present —
    // NOT by the key length. The old gate `keyOrAad.length === 32` made a
    // null key throw a raw TypeError ("Cannot read properties of null") and a
    // wrong-length key fall through to the misleading "Invalid arguments"
    // branch below. Routing here (with a key present) lets the explicit key
    // validation further down report a clean "Invalid decryption key:
    // expected 32 bytes, got N". A genuinely ambiguous 2-arg call (no key
    // arg) still falls through to "Invalid arguments".
    ciphertext = encryptedOrCiphertext;
    nonce = keyOrNonce;
    decryptionKey = keyOrAad as Uint8Array; // validated below (null/short/long → clean throw)
    associatedData = aad; // 4th param is optional AAD
  } else {
    throw new Error(
      'Invalid arguments: expected (EncryptedData, key[, aad]) or (ciphertext, nonce, key[, aad])'
    );
  }

  // SECURITY: Validate all cryptographic parameters
  if (!ciphertext || ciphertext.length < CONSTANTS.POLY1305_TAG_BYTES) {
    throw new Error(
      `Invalid ciphertext: minimum length is ${CONSTANTS.POLY1305_TAG_BYTES} bytes (tag), got ${ciphertext?.length ?? 0}`
    );
  }
  if (!nonce || nonce.length !== CONSTANTS.XCHACHA20_NONCE_BYTES) {
    throw new Error(
      `Invalid nonce: expected ${CONSTANTS.XCHACHA20_NONCE_BYTES} bytes, got ${nonce?.length ?? 0}`
    );
  }
  if (!decryptionKey || decryptionKey.length !== CONSTANTS.XCHACHA20_KEY_BYTES) {
    throw new Error(
      `Invalid decryption key: expected ${CONSTANTS.XCHACHA20_KEY_BYTES} bytes, got ${decryptionKey?.length ?? 0}`
    );
  }

  try {
    const cipher = xchacha20poly1305(decryptionKey, nonce, associatedData);
    const plaintext = cipher.decrypt(ciphertext);
    // SECURITY FIX (M10): Wipe the decryption key copy if we extracted it from EncryptedData
    // (the caller still owns their original key reference)
    return plaintext;
  } catch {
    throw new Error(
      'Decryption failed: authentication tag invalid (message tampered or wrong key)'
    );
  }
}

// ============================================
// Key Derivation (Signal Protocol compatible)
// ============================================

/**
 * Key derivation function using HKDF-SHA256 (RFC 5869)
 * Used throughout Signal Protocol for deriving keys from shared secrets
 *
 * SECURITY: Uses proper HKDF extract-then-expand pattern instead of
 * a custom BLAKE2b-based construction. HKDF-SHA256 is the standard KDF
 * specified by the Signal Protocol and RFC 5869.
 *
 * Supports two call signatures:
 * 1. deriveKey(inputKeyMaterial, salt, info, outputLength) - full signature
 * 2. deriveKey(inputKeyMaterial, info, outputLength) - convenience (salt=undefined)
 *
 * @param inputKeyMaterial - Input key material (e.g., ECDH shared secret, minimum 16 bytes)
 * @param saltOrInfo - Salt for HKDF extract OR info (if 3-param call)
 * @param infoOrLength - Info for HKDF expand OR output length (if 3-param call)
 * @param outputLength - Desired output length in bytes (only for 4-param call)
 * @returns Derived key material
 * @throws Error if IKM is too short or output length is invalid
 */
export function deriveKey(
  inputKeyMaterial: Uint8Array,
  saltOrInfo: Uint8Array | null,
  infoOrLength: Uint8Array | number,
  outputLength?: number
): Uint8Array {
  ensureInitialized();

  // SECURITY: Validate IKM has sufficient entropy
  const MIN_IKM_LENGTH = 16; // Minimum 128 bits of entropy
  if (!inputKeyMaterial || inputKeyMaterial.length < MIN_IKM_LENGTH) {
    throw new Error(
      `Invalid input key material: minimum ${MIN_IKM_LENGTH} bytes required, got ${inputKeyMaterial?.length ?? 0}`
    );
  }

  let salt: Uint8Array | undefined;
  let info: Uint8Array;
  let length: number;

  // Determine which signature is being used
  if (typeof infoOrLength === 'number') {
    // 3-param signature: (inputKeyMaterial, info, outputLength)
    salt = undefined;
    info = saltOrInfo as Uint8Array;
    length = infoOrLength;
  } else {
    // 4-param signature: (inputKeyMaterial, salt, info, outputLength)
    salt = saltOrInfo ?? undefined;
    info = infoOrLength;
    length = outputLength!;
  }

  // SECURITY: Validate info parameter
  if (!info) {
    throw new Error('Info parameter is required for key derivation');
  }

  // SECURITY: Validate output length (HKDF-SHA256 supports up to 255*HashLen = 8160 bytes)
  if (length < 1 || length > 255 * 32) {
    throw new Error(`Invalid output length: must be 1-8160 bytes, got ${length}`);
  }

  // HKDF-SHA256 (RFC 5869): extract-then-expand
  // Extract: PRK = HMAC-SHA256(salt, IKM)
  // Expand:  OKM = HKDF-Expand(PRK, info, length)
  return hkdf(sha256, inputKeyMaterial, salt, info, length);
}

/**
 * Derive multiple keys from a master key using HKDF-SHA256 with distinct info strings
 * Signal Protocol compatible key derivation
 *
 * SECURITY: Each derived key uses a unique info string of the form
 * "<context>_key_<index>" to ensure cryptographic domain separation.
 * This prevents collisions that could occur with counter-only differentiation.
 *
 * @param masterKey - Master key to derive from (minimum 16 bytes)
 * @param context - Context string for domain separation
 * @param numKeys - Number of keys to derive (1-256)
 * @param keyLength - Length of each derived key (1-255*32 bytes)
 * @returns Array of derived keys
 * @throws Error if inputs are invalid
 */
export function deriveMultipleKeys(
  masterKey: Uint8Array,
  context: string,
  numKeys: number,
  keyLength: number = 32
): Uint8Array[] {
  ensureInitialized();

  // SECURITY: Validate inputs
  const MIN_MASTER_KEY_LENGTH = 16;
  if (!masterKey || masterKey.length < MIN_MASTER_KEY_LENGTH) {
    throw new Error(
      `Invalid master key: minimum ${MIN_MASTER_KEY_LENGTH} bytes required, got ${masterKey?.length ?? 0}`
    );
  }
  if (!context || context.length === 0) {
    throw new Error('Context string is required for key derivation');
  }
  if (numKeys < 1 || numKeys > 256) {
    throw new Error(`Invalid numKeys: must be 1-256, got ${numKeys}`);
  }
  if (keyLength < 1 || keyLength > 255 * 32) {
    throw new Error(`Invalid keyLength: must be 1-8160, got ${keyLength}`);
  }

  const keys: Uint8Array[] = [];

  for (let i = 0; i < numKeys; i++) {
    // SECURITY: Each key gets a distinct info string for proper domain separation
    const info = new TextEncoder().encode(`${context}_key_${i}`);
    keys.push(hkdf(sha256, masterKey, undefined, info, keyLength));
  }

  return keys;
}

/**
 * Derive chain key and message key from a root key (Double Ratchet)
 *
 * @param rootKey - Current root key (must be 32 bytes)
 * @param dhOutput - ECDH output from ratchet step (must be 32 bytes)
 * @returns New root key and chain key
 * @throws Error if inputs are invalid sizes
 */
export function deriveRatchetKeys(
  rootKey: Uint8Array,
  dhOutput: Uint8Array
): { newRootKey: Uint8Array; chainKey: Uint8Array } {
  ensureInitialized();

  // SECURITY: Validate input sizes (both should be 32-byte X25519 outputs)
  if (!rootKey || rootKey.length !== 32) {
    throw new Error(
      `Invalid root key: expected 32 bytes, got ${rootKey?.length ?? 0}`
    );
  }
  if (!dhOutput || dhOutput.length !== 32) {
    throw new Error(
      `Invalid DH output: expected 32 bytes, got ${dhOutput?.length ?? 0}`
    );
  }

  // Combine DH output and root key
  const combined = new Uint8Array(dhOutput.length + rootKey.length);
  combined.set(dhOutput, 0);
  combined.set(rootKey, dhOutput.length);

  const keys = deriveMultipleKeys(
    combined,
    'WhisperRatchet',
    2,
    32
  );

  // SECURITY FIX (M10): Wipe intermediate combined buffer
  secureZero(combined);

  return {
    newRootKey: keys[0],
    chainKey: keys[1],
  };
}

/**
 * Derive message key from chain key (symmetric ratchet)
 *
 * @param chainKey - Current chain key (must be 32 bytes)
 * @returns Message key for encryption and next chain key
 * @throws Error if chain key is invalid size
 */
export function deriveMessageKeys(chainKey: Uint8Array): {
  messageKey: Uint8Array;
  nextChainKey: Uint8Array;
} {
  ensureInitialized();

  // SECURITY: Validate chain key size
  if (!chainKey || chainKey.length !== 32) {
    throw new Error(
      `Invalid chain key: expected 32 bytes, got ${chainKey?.length ?? 0}`
    );
  }

  // Message key: Hash(chain_key || 0x01)
  const messageKeyInput = new Uint8Array(chainKey.length + 1);
  messageKeyInput.set(chainKey, 0);
  messageKeyInput[chainKey.length] = 0x01;
  const messageKey = blake2b(messageKeyInput, { dkLen: 32 });

  // Next chain key: Hash(chain_key || 0x02)
  const chainKeyInput = new Uint8Array(chainKey.length + 1);
  chainKeyInput.set(chainKey, 0);
  chainKeyInput[chainKey.length] = 0x02;
  const nextChainKey = blake2b(chainKeyInput, { dkLen: 32 });

  // SECURITY FIX (M10): Wipe intermediate buffers
  secureZero(messageKeyInput);
  secureZero(chainKeyInput);

  return { messageKey, nextChainKey };
}

// ============================================
// Utility Functions
// ============================================

/**
 * Generate cryptographically secure random bytes
 */
export function randomBytes(length: number): Uint8Array {
  ensureInitialized();
  return nobleRandomBytes(length);
}

/**
 * Securely compare two byte arrays (constant-time)
 *
 * SECURITY: This comparison runs in constant time regardless of:
 * - Where the first difference occurs
 * - The length of the arrays (length mismatch is handled without early return)
 *
 * This prevents timing attacks that could leak information about secret values.
 *
 * @param a - First byte array
 * @param b - Second byte array
 * @returns true if arrays are equal, false otherwise
 */
export function secureCompare(a: Uint8Array, b: Uint8Array): boolean {
  ensureInitialized();

  // SECURITY: Handle null/undefined inputs
  if (!a || !b) {
    // Both null/undefined = equal, otherwise not equal
    // Use bitwise to avoid short-circuit timing
    return !a && !b;
  }

  // SECURITY FIX (M11): When lengths differ, compare `a` against itself
  // to consume the same time as a same-length comparison, then return false.
  // This prevents leaking the longer array's length through loop iteration count.
  if (a.length !== b.length) {
    // I14 fix: use a real XOR against a computed mask so JIT cannot optimize
    // away the loop (`a[i] ^ a[i]` is always 0 and gets eliminated).
    const maxLen = Math.max(a.length, b.length);
    let dummy = 0;
    for (let i = 0; i < maxLen; i++) {
      const av = i < a.length ? a[i] : 0;
      const bv = i < b.length ? b[i] : 0xff;
      dummy |= av ^ bv;
    }
    // Use dummy externally so the compiler cannot prove it is unused.
    if (dummy === -1) return true;
    return false;
  }

  // SECURITY: Constant-time byte comparison for equal-length arrays
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

/**
 * Securely zero out memory
 */
export function secureZero(data: Uint8Array): void {
  ensureInitialized();
  // Fill with zeros (best effort in JS - memory not guaranteed to be cleared)
  data.fill(0);
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  ensureInitialized();
  return nobleBytesToHex(bytes);
}

/**
 * Convert hex string to bytes
 *
 * @param hex - Hexadecimal string (must have even length, valid hex chars)
 * @returns Byte array
 * @throws Error if hex string is invalid
 */
export function hexToBytes(hex: string): Uint8Array {
  ensureInitialized();

  // SECURITY: Validate hex string format
  if (hex === undefined || hex === null || typeof hex !== 'string') {
    throw new Error('Hex string is required');
  }
  // Empty string is valid (represents empty byte array)
  if (hex.length === 0) {
    return new Uint8Array(0);
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Hex string contains invalid characters');
  }

  return nobleHexToBytes(hex);
}

/**
 * Convert bytes to base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  ensureInitialized();

  // Use btoa with proper encoding for React Native
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string to bytes
 *
 * @param base64 - Base64 encoded string
 * @returns Byte array
 * @throws Error if base64 string is invalid
 */
export function base64ToBytes(base64: string): Uint8Array {
  ensureInitialized();

  // SECURITY: Validate base64 string
  if (!base64 || typeof base64 !== 'string') {
    throw new Error('Base64 string is required');
  }

  try {
    // Use atob with proper decoding for React Native
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    throw new Error('Invalid base64 string');
  }
}

/**
 * Compute BLAKE2b-256 hash (cryptographically equivalent to SHA256)
 */
export function hash256(data: Uint8Array): Uint8Array {
  ensureInitialized();
  return blake2b(data, { dkLen: 32 });
}

/**
 * Password-based key derivation using PBKDF2-SHA256
 *
 * SECURITY FIX (M12): Replaced homegrown memory-hard KDF with standard
 * PBKDF2-SHA256 from @noble/hashes. The previous implementation was a
 * custom construction without peer review or formal security analysis.
 * PBKDF2-SHA256 with 100,000 iterations is a well-understood, standards-based
 * KDF (NIST SP 800-132, RFC 8018).
 *
 * NOTE: If Argon2id becomes available via @noble/hashes or another audited
 * library compatible with Hermes, it should replace PBKDF2 for superior
 * resistance to GPU/ASIC attacks.
 *
 * @param password - Password bytes
 * @param salt - Salt bytes (should be at least 16 bytes)
 * @param iterations - Number of PBKDF2 iterations (default: 100000, minimum: 100000)
 * @param _memoryKB - DEPRECATED: ignored, kept for API compatibility
 * @param outputLength - Desired key length in bytes
 * @returns Derived key
 */
export function deriveKeyMemoryHard(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number = 100_000,
  _memoryKB: number = 65536,
  outputLength: number = 32
): Uint8Array {
  ensureInitialized();

  // SECURITY: Enforce minimum iteration count
  const actualIterations = Math.max(iterations, 100_000);

  // SECURITY: Validate salt length
  if (!salt || salt.length < 16) {
    throw new Error(`Invalid salt: minimum 16 bytes required, got ${salt?.length ?? 0}`);
  }

  // PBKDF2-SHA256 (RFC 8018 / NIST SP 800-132)
  const derivedKey = pbkdf2(sha256, password, salt, {
    c: actualIterations,
    dkLen: outputLength,
  });

  return derivedKey;
}

/**
 * Compute fingerprint (truncated hash) of a public key
 * Used for safety number verification
 */
export function computeFingerprint(publicKey: Uint8Array): string {
  ensureInitialized();
  const hash = hash256(publicKey);
  return bytesToHex(hash.slice(0, 8)); // 16 hex chars
}

// Export constants for external use (compatible with libsodium)
export const CONSTANTS = {
  X25519_PUBLIC_KEY_BYTES: 32,
  X25519_PRIVATE_KEY_BYTES: 32,
  ED25519_PUBLIC_KEY_BYTES: 32,
  ED25519_PRIVATE_KEY_BYTES: 64,
  ED25519_SIGNATURE_BYTES: 64,
  XCHACHA20_NONCE_BYTES: 24,
  XCHACHA20_KEY_BYTES: 32,
  POLY1305_TAG_BYTES: 16,
} as const;
