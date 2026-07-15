/**
 * SodiumCrypto Unit Tests
 *
 * Comprehensive tests for all cryptographic primitives in SodiumCrypto.ts
 * Target: 100% code coverage
 */

import {
  initializeSodium,
  generateX25519KeyPair,
  generateEd25519KeyPair,
  x25519ECDH,
  x25519PrivateToEd25519,
  ed25519Sign,
  ed25519Verify,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  deriveKey,
  deriveMultipleKeys,
  deriveRatchetKeys,
  deriveMessageKeys,
  randomBytes,
  secureCompare,
  secureZero,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  hash256,
  deriveKeyMemoryHard,
  computeFingerprint,
  CONSTANTS,
  X25519KeyPair,
  Ed25519KeyPair,
  EncryptedData,
} from '@/src/services/SodiumCrypto';

import {
  X25519_TEST_VECTORS,
  ED25519_TEST_VECTORS,
  XCHACHA20_POLY1305_TEST_VECTORS,
  hexToBytes as vectorHexToBytes,
  bytesToHex as vectorBytesToHex,
} from '../../fixtures/testVectors';

import {
  TEST_X25519_KEYS,
  TEST_ED25519_KEYS,
  TEST_SYMMETRIC_KEYS,
  TEST_NONCES,
  getX25519KeyPair,
  getEd25519KeyPair,
  getSymmetricKey,
  getNonce,
} from '../../fixtures/keyPairs';

describe('SodiumCrypto', () => {
  // Initialize sodium before all tests
  beforeAll(async () => {
    await initializeSodium();
  });

  describe('initializeSodium', () => {
    it('should initialize without error', async () => {
      await expect(initializeSodium()).resolves.toBeUndefined();
    });

    it('should be idempotent (multiple calls should not fail)', async () => {
      await initializeSodium();
      await initializeSodium();
      await initializeSodium();
      // No error means success
      expect(true).toBe(true);
    });
  });

  describe('X25519 Key Generation', () => {
    it('should generate a valid X25519 key pair', () => {
      const keyPair = generateX25519KeyPair();

      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(CONSTANTS.X25519_PUBLIC_KEY_BYTES);
      expect(keyPair.privateKey.length).toBe(CONSTANTS.X25519_PRIVATE_KEY_BYTES);
    });

    it('should generate unique key pairs each time', () => {
      const keyPair1 = generateX25519KeyPair();
      const keyPair2 = generateX25519KeyPair();

      expect(bytesToHex(keyPair1.publicKey)).not.toBe(bytesToHex(keyPair2.publicKey));
      expect(bytesToHex(keyPair1.privateKey)).not.toBe(bytesToHex(keyPair2.privateKey));
    });

    it('should generate non-zero keys', () => {
      const keyPair = generateX25519KeyPair();

      expect(keyPair.publicKey.some((b) => b !== 0)).toBe(true);
      expect(keyPair.privateKey.some((b) => b !== 0)).toBe(true);
    });
  });

  describe('X25519 ECDH', () => {
    it('should compute shared secret correctly', () => {
      const aliceKeyPair = generateX25519KeyPair();
      const bobKeyPair = generateX25519KeyPair();

      const aliceShared = x25519ECDH(aliceKeyPair.privateKey, bobKeyPair.publicKey);
      const bobShared = x25519ECDH(bobKeyPair.privateKey, aliceKeyPair.publicKey);

      expect(bytesToHex(aliceShared)).toBe(bytesToHex(bobShared));
    });

    it('should return 32-byte shared secret', () => {
      const aliceKeyPair = generateX25519KeyPair();
      const bobKeyPair = generateX25519KeyPair();

      const sharedSecret = x25519ECDH(aliceKeyPair.privateKey, bobKeyPair.publicKey);

      expect(sharedSecret.length).toBe(32);
    });

    it('should match RFC 7748 test vectors', () => {
      const alicePrivate = vectorHexToBytes(X25519_TEST_VECTORS.alicePrivate);
      const bobPublic = vectorHexToBytes(X25519_TEST_VECTORS.bobPublic);
      const expectedShared = X25519_TEST_VECTORS.sharedSecret;

      const sharedSecret = x25519ECDH(alicePrivate, bobPublic);

      expect(bytesToHex(sharedSecret)).toBe(expectedShared);
    });

    it('should compute same shared secret regardless of which key is private', () => {
      const alicePrivate = vectorHexToBytes(X25519_TEST_VECTORS.alicePrivate);
      const alicePublic = vectorHexToBytes(X25519_TEST_VECTORS.alicePublic);
      const bobPrivate = vectorHexToBytes(X25519_TEST_VECTORS.bobPrivate);
      const bobPublic = vectorHexToBytes(X25519_TEST_VECTORS.bobPublic);

      const sharedFromAlice = x25519ECDH(alicePrivate, bobPublic);
      const sharedFromBob = x25519ECDH(bobPrivate, alicePublic);

      expect(bytesToHex(sharedFromAlice)).toBe(bytesToHex(sharedFromBob));
    });

    it('should produce different shared secrets with different keys', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();
      const charlie = generateX25519KeyPair();

      const aliceBobShared = x25519ECDH(alice.privateKey, bob.publicKey);
      const aliceCharlieShared = x25519ECDH(alice.privateKey, charlie.publicKey);

      expect(bytesToHex(aliceBobShared)).not.toBe(bytesToHex(aliceCharlieShared));
    });
  });

  describe('Ed25519 Key Generation', () => {
    it('should generate a valid Ed25519 key pair', () => {
      const keyPair = generateEd25519KeyPair();

      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(CONSTANTS.ED25519_PUBLIC_KEY_BYTES);
      expect(keyPair.privateKey.length).toBe(CONSTANTS.ED25519_PRIVATE_KEY_BYTES);
    });

    it('should generate unique key pairs each time', () => {
      const keyPair1 = generateEd25519KeyPair();
      const keyPair2 = generateEd25519KeyPair();

      expect(bytesToHex(keyPair1.publicKey)).not.toBe(bytesToHex(keyPair2.publicKey));
    });

    it('should include public key in private key (libsodium format)', () => {
      const keyPair = generateEd25519KeyPair();

      // Last 32 bytes of private key should be public key
      const extractedPublicKey = keyPair.privateKey.slice(32);
      expect(bytesToHex(extractedPublicKey)).toBe(bytesToHex(keyPair.publicKey));
    });
  });

  describe('x25519PrivateToEd25519', () => {
    it('should convert X25519 private key to Ed25519 signing key', () => {
      const x25519KeyPair = generateX25519KeyPair();
      const ed25519Private = x25519PrivateToEd25519(x25519KeyPair.privateKey);

      expect(ed25519Private).toBeInstanceOf(Uint8Array);
      expect(ed25519Private.length).toBe(64); // Ed25519 private key is 64 bytes
    });

    it('should produce deterministic results for same input', () => {
      const x25519KeyPair = generateX25519KeyPair();

      const ed25519Private1 = x25519PrivateToEd25519(x25519KeyPair.privateKey);
      const ed25519Private2 = x25519PrivateToEd25519(x25519KeyPair.privateKey);

      expect(bytesToHex(ed25519Private1)).toBe(bytesToHex(ed25519Private2));
    });

    it('should produce different Ed25519 keys for different X25519 keys', () => {
      const x25519Key1 = generateX25519KeyPair();
      const x25519Key2 = generateX25519KeyPair();

      const ed25519Private1 = x25519PrivateToEd25519(x25519Key1.privateKey);
      const ed25519Private2 = x25519PrivateToEd25519(x25519Key2.privateKey);

      expect(bytesToHex(ed25519Private1)).not.toBe(bytesToHex(ed25519Private2));
    });
  });

  describe('Ed25519 Sign and Verify', () => {
    it('should sign a message and verify the signature', () => {
      const keyPair = generateEd25519KeyPair();
      const message = new TextEncoder().encode('Hello, World!');

      const signature = ed25519Sign(message, keyPair.privateKey);
      const isValid = ed25519Verify(message, signature, keyPair.publicKey);

      expect(signature.length).toBe(CONSTANTS.ED25519_SIGNATURE_BYTES);
      expect(isValid).toBe(true);
    });

    it('should reject signature with wrong public key', () => {
      const keyPair1 = generateEd25519KeyPair();
      const keyPair2 = generateEd25519KeyPair();
      const message = new TextEncoder().encode('Test message');

      const signature = ed25519Sign(message, keyPair1.privateKey);
      const isValid = ed25519Verify(message, signature, keyPair2.publicKey);

      expect(isValid).toBe(false);
    });

    it('should reject tampered message', () => {
      const keyPair = generateEd25519KeyPair();
      const message = new TextEncoder().encode('Original message');
      const tamperedMessage = new TextEncoder().encode('Tampered message');

      const signature = ed25519Sign(message, keyPair.privateKey);
      const isValid = ed25519Verify(tamperedMessage, signature, keyPair.publicKey);

      expect(isValid).toBe(false);
    });

    it('should reject tampered signature', () => {
      const keyPair = generateEd25519KeyPair();
      const message = new TextEncoder().encode('Test message');

      const signature = ed25519Sign(message, keyPair.privateKey);
      signature[0] ^= 0xff; // Tamper with signature

      const isValid = ed25519Verify(message, signature, keyPair.publicKey);

      expect(isValid).toBe(false);
    });

    it('should match RFC 8032 test vector (empty message)', () => {
      const vector = ED25519_TEST_VECTORS.test1;
      const seed = vectorHexToBytes(vector.privateKey);
      const publicKey = vectorHexToBytes(vector.publicKey);
      const expectedSignature = vector.signature;

      // Create 64-byte private key from seed
      const { ed25519 } = require('@noble/curves/ed25519');
      const computedPublicKey = ed25519.getPublicKey(seed);
      const privateKey = new Uint8Array(64);
      privateKey.set(seed, 0);
      privateKey.set(computedPublicKey, 32);

      const message = new Uint8Array(0); // Empty message
      const signature = ed25519Sign(message, privateKey);

      expect(bytesToHex(signature)).toBe(expectedSignature);
    });

    it('should match RFC 8032 test vector (single byte)', () => {
      const vector = ED25519_TEST_VECTORS.test2;
      const seed = vectorHexToBytes(vector.privateKey);
      const message = vectorHexToBytes(vector.message);
      const expectedSignature = vector.signature;

      const { ed25519 } = require('@noble/curves/ed25519');
      const computedPublicKey = ed25519.getPublicKey(seed);
      const privateKey = new Uint8Array(64);
      privateKey.set(seed, 0);
      privateKey.set(computedPublicKey, 32);

      const signature = ed25519Sign(message, privateKey);

      expect(bytesToHex(signature)).toBe(expectedSignature);
    });

    it('should work with 32-byte seed as private key', () => {
      const seed = randomBytes(32);
      const { ed25519 } = require('@noble/curves/ed25519');
      const publicKey = ed25519.getPublicKey(seed);
      const message = new TextEncoder().encode('Test');

      // Should work with 32-byte seed
      const signature = ed25519Sign(message, seed);
      const isValid = ed25519Verify(message, signature, publicKey);

      expect(isValid).toBe(true);
    });
  });

  describe('XChaCha20-Poly1305 Encryption', () => {
    it('should encrypt and decrypt a message correctly', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('Secret message');

      const encrypted = encryptXChaCha20Poly1305(plaintext, key);
      const decrypted = decryptXChaCha20Poly1305(encrypted, key);

      expect(new TextDecoder().decode(decrypted)).toBe('Secret message');
    });

    it('should produce unique nonces each time', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('Same message');

      const encrypted1 = encryptXChaCha20Poly1305(plaintext, key);
      const encrypted2 = encryptXChaCha20Poly1305(plaintext, key);

      expect(bytesToHex(encrypted1.nonce)).not.toBe(bytesToHex(encrypted2.nonce));
      expect(bytesToHex(encrypted1.ciphertext)).not.toBe(bytesToHex(encrypted2.ciphertext));
    });

    it('should use 24-byte nonce (XChaCha20)', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('Test');

      const encrypted = encryptXChaCha20Poly1305(plaintext, key);

      expect(encrypted.nonce.length).toBe(CONSTANTS.XCHACHA20_NONCE_BYTES);
    });

    it('should fail decryption with wrong key', () => {
      const key1 = randomBytes(32);
      const key2 = randomBytes(32);
      const plaintext = new TextEncoder().encode('Secret');

      const encrypted = encryptXChaCha20Poly1305(plaintext, key1);

      expect(() => {
        decryptXChaCha20Poly1305(encrypted, key2);
      }).toThrow();
    });

    it('should fail decryption with tampered ciphertext', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('Secret');

      const encrypted = encryptXChaCha20Poly1305(plaintext, key);
      encrypted.ciphertext[0] ^= 0xff; // Tamper

      expect(() => {
        decryptXChaCha20Poly1305(encrypted, key);
      }).toThrow();
    });

    it('should fail decryption with tampered nonce', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('Secret');

      const encrypted = encryptXChaCha20Poly1305(plaintext, key);
      encrypted.nonce[0] ^= 0xff; // Tamper

      expect(() => {
        decryptXChaCha20Poly1305(encrypted, key);
      }).toThrow();
    });

    it('should handle empty plaintext', () => {
      const key = randomBytes(32);
      const plaintext = new Uint8Array(0);

      const encrypted = encryptXChaCha20Poly1305(plaintext, key);
      const decrypted = decryptXChaCha20Poly1305(encrypted, key);

      expect(decrypted.length).toBe(0);
    });

    it('should handle large plaintext', () => {
      const key = randomBytes(32);
      // Generate large plaintext in chunks to avoid 65536 byte limit
      const chunkSize = 60000;
      const chunks: Uint8Array[] = [];
      for (let i = 0; i < 2; i++) {
        chunks.push(randomBytes(chunkSize));
      }
      const plaintext = new Uint8Array(chunks.reduce((sum, c) => sum + c.length, 0));
      let offset = 0;
      for (const chunk of chunks) {
        plaintext.set(chunk, offset);
        offset += chunk.length;
      }

      const encrypted = encryptXChaCha20Poly1305(plaintext, key);
      const decrypted = decryptXChaCha20Poly1305(encrypted, key);

      expect(bytesToHex(decrypted)).toBe(bytesToHex(plaintext));
    });

    it('should support 3-parameter decryption signature', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('Test');

      const encrypted = encryptXChaCha20Poly1305(plaintext, key);
      const decrypted = decryptXChaCha20Poly1305(
        encrypted.ciphertext,
        encrypted.nonce,
        key
      );

      expect(new TextDecoder().decode(decrypted)).toBe('Test');
    });

    it('should throw error for invalid decryption arguments', () => {
      const key = randomBytes(32);

      expect(() => {
        // @ts-ignore - Testing invalid arguments
        decryptXChaCha20Poly1305(new Uint8Array(10), key);
      }).toThrow('Invalid arguments');
    });
  });

  describe('Key Derivation (deriveKey)', () => {
    it('should derive key of requested length', () => {
      const inputKey = randomBytes(32);
      const info = new TextEncoder().encode('test-context');

      const derivedKey = deriveKey(inputKey, info, 32);

      expect(derivedKey.length).toBe(32);
    });

    it('should produce deterministic output', () => {
      const inputKey = randomBytes(32);
      const info = new TextEncoder().encode('test-context');

      const derivedKey1 = deriveKey(inputKey, info, 32);
      const derivedKey2 = deriveKey(inputKey, info, 32);

      expect(bytesToHex(derivedKey1)).toBe(bytesToHex(derivedKey2));
    });

    it('should produce different output for different info', () => {
      const inputKey = randomBytes(32);
      const info1 = new TextEncoder().encode('context-1');
      const info2 = new TextEncoder().encode('context-2');

      const derivedKey1 = deriveKey(inputKey, info1, 32);
      const derivedKey2 = deriveKey(inputKey, info2, 32);

      expect(bytesToHex(derivedKey1)).not.toBe(bytesToHex(derivedKey2));
    });

    it('should produce different output for different input keys', () => {
      const inputKey1 = randomBytes(32);
      const inputKey2 = randomBytes(32);
      const info = new TextEncoder().encode('test');

      const derivedKey1 = deriveKey(inputKey1, info, 32);
      const derivedKey2 = deriveKey(inputKey2, info, 32);

      expect(bytesToHex(derivedKey1)).not.toBe(bytesToHex(derivedKey2));
    });

    it('should support 4-parameter signature with salt', () => {
      const inputKey = randomBytes(32);
      const salt = randomBytes(16);
      const info = new TextEncoder().encode('test');

      const derivedKey = deriveKey(inputKey, salt, info, 32);

      expect(derivedKey.length).toBe(32);
    });

    it('should produce different output with different salt', () => {
      const inputKey = randomBytes(32);
      const salt1 = randomBytes(16);
      const salt2 = randomBytes(16);
      const info = new TextEncoder().encode('test');

      const derivedKey1 = deriveKey(inputKey, salt1, info, 32);
      const derivedKey2 = deriveKey(inputKey, salt2, info, 32);

      expect(bytesToHex(derivedKey1)).not.toBe(bytesToHex(derivedKey2));
    });

    it('should handle null salt in 4-parameter signature', () => {
      const inputKey = randomBytes(32);
      const info = new TextEncoder().encode('test');

      // With null salt
      const derivedKey1 = deriveKey(inputKey, null, info, 32);
      // With 3-parameter signature (no salt)
      const derivedKey2 = deriveKey(inputKey, info, 32);

      // Results should be the same when salt is null
      expect(bytesToHex(derivedKey1)).toBe(bytesToHex(derivedKey2));
    });
  });

  describe('deriveMultipleKeys', () => {
    it('should derive multiple unique keys', () => {
      const masterKey = randomBytes(32);

      const keys = deriveMultipleKeys(masterKey, 'test', 3);

      expect(keys.length).toBe(3);
      expect(bytesToHex(keys[0])).not.toBe(bytesToHex(keys[1]));
      expect(bytesToHex(keys[1])).not.toBe(bytesToHex(keys[2]));
      expect(bytesToHex(keys[0])).not.toBe(bytesToHex(keys[2]));
    });

    it('should derive keys of correct length', () => {
      const masterKey = randomBytes(32);

      const keys = deriveMultipleKeys(masterKey, 'test', 2, 64);

      expect(keys[0].length).toBe(64);
      expect(keys[1].length).toBe(64);
    });

    it('should be deterministic', () => {
      const masterKey = randomBytes(32);

      const keys1 = deriveMultipleKeys(masterKey, 'test', 2);
      const keys2 = deriveMultipleKeys(masterKey, 'test', 2);

      expect(bytesToHex(keys1[0])).toBe(bytesToHex(keys2[0]));
      expect(bytesToHex(keys1[1])).toBe(bytesToHex(keys2[1]));
    });

    it('should produce different keys for different contexts', () => {
      const masterKey = randomBytes(32);

      const keys1 = deriveMultipleKeys(masterKey, 'context-a', 1);
      const keys2 = deriveMultipleKeys(masterKey, 'context-b', 1);

      expect(bytesToHex(keys1[0])).not.toBe(bytesToHex(keys2[0]));
    });
  });

  describe('deriveRatchetKeys', () => {
    it('should derive new root key and chain key', () => {
      const rootKey = randomBytes(32);
      const dhOutput = randomBytes(32);

      const { newRootKey, chainKey } = deriveRatchetKeys(rootKey, dhOutput);

      expect(newRootKey.length).toBe(32);
      expect(chainKey.length).toBe(32);
      expect(bytesToHex(newRootKey)).not.toBe(bytesToHex(chainKey));
    });

    it('should be deterministic', () => {
      const rootKey = randomBytes(32);
      const dhOutput = randomBytes(32);

      const result1 = deriveRatchetKeys(rootKey, dhOutput);
      const result2 = deriveRatchetKeys(rootKey, dhOutput);

      expect(bytesToHex(result1.newRootKey)).toBe(bytesToHex(result2.newRootKey));
      expect(bytesToHex(result1.chainKey)).toBe(bytesToHex(result2.chainKey));
    });

    it('should produce different output for different DH output', () => {
      const rootKey = randomBytes(32);
      const dhOutput1 = randomBytes(32);
      const dhOutput2 = randomBytes(32);

      const result1 = deriveRatchetKeys(rootKey, dhOutput1);
      const result2 = deriveRatchetKeys(rootKey, dhOutput2);

      expect(bytesToHex(result1.newRootKey)).not.toBe(bytesToHex(result2.newRootKey));
    });
  });

  describe('deriveMessageKeys', () => {
    it('should derive message key and next chain key', () => {
      const chainKey = randomBytes(32);

      const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);

      expect(messageKey.length).toBe(32);
      expect(nextChainKey.length).toBe(32);
      expect(bytesToHex(messageKey)).not.toBe(bytesToHex(nextChainKey));
    });

    it('should be deterministic', () => {
      const chainKey = randomBytes(32);

      const result1 = deriveMessageKeys(chainKey);
      const result2 = deriveMessageKeys(chainKey);

      expect(bytesToHex(result1.messageKey)).toBe(bytesToHex(result2.messageKey));
      expect(bytesToHex(result1.nextChainKey)).toBe(bytesToHex(result2.nextChainKey));
    });

    it('should produce different keys for different chain keys', () => {
      const chainKey1 = randomBytes(32);
      const chainKey2 = randomBytes(32);

      const result1 = deriveMessageKeys(chainKey1);
      const result2 = deriveMessageKeys(chainKey2);

      expect(bytesToHex(result1.messageKey)).not.toBe(bytesToHex(result2.messageKey));
    });

    it('should produce a chain of unique keys', () => {
      let chainKey = randomBytes(32);
      const messageKeys: string[] = [];

      for (let i = 0; i < 5; i++) {
        const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);
        messageKeys.push(bytesToHex(messageKey));
        chainKey = nextChainKey;
      }

      // All message keys should be unique
      const uniqueKeys = new Set(messageKeys);
      expect(uniqueKeys.size).toBe(5);
    });
  });

  describe('Utility Functions', () => {
    describe('randomBytes', () => {
      it('should generate bytes of requested length', () => {
        const bytes = randomBytes(32);
        expect(bytes.length).toBe(32);
      });

      it('should generate unique bytes each time', () => {
        const bytes1 = randomBytes(32);
        const bytes2 = randomBytes(32);
        expect(bytesToHex(bytes1)).not.toBe(bytesToHex(bytes2));
      });

      it('should generate non-zero bytes', () => {
        const bytes = randomBytes(100);
        expect(bytes.some((b) => b !== 0)).toBe(true);
      });
    });

    describe('secureCompare', () => {
      it('should return true for equal arrays', () => {
        const a = new Uint8Array([1, 2, 3, 4, 5]);
        const b = new Uint8Array([1, 2, 3, 4, 5]);
        expect(secureCompare(a, b)).toBe(true);
      });

      it('should return false for different arrays', () => {
        const a = new Uint8Array([1, 2, 3, 4, 5]);
        const b = new Uint8Array([1, 2, 3, 4, 6]);
        expect(secureCompare(a, b)).toBe(false);
      });

      it('should return false for arrays of different lengths', () => {
        const a = new Uint8Array([1, 2, 3]);
        const b = new Uint8Array([1, 2, 3, 4]);
        expect(secureCompare(a, b)).toBe(false);
      });

      it('should return true for empty arrays', () => {
        const a = new Uint8Array([]);
        const b = new Uint8Array([]);
        expect(secureCompare(a, b)).toBe(true);
      });
    });

    describe('secureZero', () => {
      it('should zero out the array', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        secureZero(data);
        expect(data.every((b) => b === 0)).toBe(true);
      });
    });

    describe('bytesToHex and hexToBytes', () => {
      it('should convert bytes to hex and back', () => {
        const original = new Uint8Array([0, 1, 15, 16, 255]);
        const hex = bytesToHex(original);
        const restored = hexToBytes(hex);

        expect(hex).toBe('00010f10ff');
        expect(Array.from(restored)).toEqual(Array.from(original));
      });

      it('should handle empty arrays', () => {
        const empty = new Uint8Array([]);
        expect(bytesToHex(empty)).toBe('');
        expect(hexToBytes('')).toEqual(new Uint8Array([]));
      });
    });

    describe('bytesToBase64 and base64ToBytes', () => {
      it('should convert bytes to base64 and back', () => {
        const original = new Uint8Array([0, 1, 2, 253, 254, 255]);
        const base64 = bytesToBase64(original);
        const restored = base64ToBytes(base64);

        expect(Array.from(restored)).toEqual(Array.from(original));
      });

      it('should handle text conversion', () => {
        const text = 'Hello, World!';
        const bytes = new TextEncoder().encode(text);
        const base64 = bytesToBase64(bytes);
        const restored = base64ToBytes(base64);

        expect(new TextDecoder().decode(restored)).toBe(text);
      });
    });

    describe('hash256', () => {
      it('should produce 32-byte hash', () => {
        const data = new TextEncoder().encode('test');
        const hash = hash256(data);
        expect(hash.length).toBe(32);
      });

      it('should produce deterministic hash', () => {
        const data = new TextEncoder().encode('test');
        const hash1 = hash256(data);
        const hash2 = hash256(data);
        expect(bytesToHex(hash1)).toBe(bytesToHex(hash2));
      });

      it('should produce different hash for different input', () => {
        const hash1 = hash256(new TextEncoder().encode('test1'));
        const hash2 = hash256(new TextEncoder().encode('test2'));
        expect(bytesToHex(hash1)).not.toBe(bytesToHex(hash2));
      });
    });

    describe('computeFingerprint', () => {
      it('should produce 16-character hex fingerprint', () => {
        const publicKey = randomBytes(32);
        const fingerprint = computeFingerprint(publicKey);

        expect(fingerprint.length).toBe(16);
        expect(/^[0-9a-f]+$/.test(fingerprint)).toBe(true);
      });

      it('should be deterministic', () => {
        const publicKey = randomBytes(32);
        const fp1 = computeFingerprint(publicKey);
        const fp2 = computeFingerprint(publicKey);
        expect(fp1).toBe(fp2);
      });

      it('should be different for different keys', () => {
        const key1 = randomBytes(32);
        const key2 = randomBytes(32);
        const fp1 = computeFingerprint(key1);
        const fp2 = computeFingerprint(key2);
        expect(fp1).not.toBe(fp2);
      });
    });
  });

  describe('deriveKeyMemoryHard', () => {
    it('should derive key of requested length', () => {
      const password = new TextEncoder().encode('password123');
      const salt = randomBytes(16);

      const key = deriveKeyMemoryHard(password, salt, 1, 1024, 32);

      expect(key.length).toBe(32);
    });

    it('should produce deterministic output', () => {
      const password = new TextEncoder().encode('password123');
      const salt = randomBytes(16);

      const key1 = deriveKeyMemoryHard(password, salt, 1, 1024, 32);
      const key2 = deriveKeyMemoryHard(password, salt, 1, 1024, 32);

      expect(bytesToHex(key1)).toBe(bytesToHex(key2));
    });

    it('should produce different output for different passwords', () => {
      const password1 = new TextEncoder().encode('password1');
      const password2 = new TextEncoder().encode('password2');
      const salt = randomBytes(16);

      const key1 = deriveKeyMemoryHard(password1, salt, 1, 1024, 32);
      const key2 = deriveKeyMemoryHard(password2, salt, 1, 1024, 32);

      expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
    });

    it('should produce different output for different salts', () => {
      const password = new TextEncoder().encode('password');
      const salt1 = randomBytes(16);
      const salt2 = randomBytes(16);

      const key1 = deriveKeyMemoryHard(password, salt1, 1, 1024, 32);
      const key2 = deriveKeyMemoryHard(password, salt2, 1, 1024, 32);

      expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
    });

    it('should clamp memory to maximum (64MB)', () => {
      const password = new TextEncoder().encode('test');
      const salt = randomBytes(16);

      // Request more than 64MB
      const key = deriveKeyMemoryHard(password, salt, 1, 100000, 32);

      // Should still work (clamped to 64MB)
      expect(key.length).toBe(32);
    });

    it('should clamp memory to minimum (1MB)', () => {
      const password = new TextEncoder().encode('test');
      const salt = randomBytes(16);

      // Request less than minimum
      const key = deriveKeyMemoryHard(password, salt, 1, 512, 32);

      // Should still work (clamped to 1MB)
      expect(key.length).toBe(32);
    });
  });

  describe('CONSTANTS', () => {
    it('should have correct X25519 constants', () => {
      expect(CONSTANTS.X25519_PUBLIC_KEY_BYTES).toBe(32);
      expect(CONSTANTS.X25519_PRIVATE_KEY_BYTES).toBe(32);
    });

    it('should have correct Ed25519 constants', () => {
      expect(CONSTANTS.ED25519_PUBLIC_KEY_BYTES).toBe(32);
      expect(CONSTANTS.ED25519_PRIVATE_KEY_BYTES).toBe(64);
      expect(CONSTANTS.ED25519_SIGNATURE_BYTES).toBe(64);
    });

    it('should have correct XChaCha20 constants', () => {
      expect(CONSTANTS.XCHACHA20_NONCE_BYTES).toBe(24);
      expect(CONSTANTS.XCHACHA20_KEY_BYTES).toBe(32);
      expect(CONSTANTS.POLY1305_TAG_BYTES).toBe(16);
    });
  });

  // ============================================
  // SECURITY: Input Validation Tests
  // Tests for security fixes that validate cryptographic inputs
  // ============================================
  describe('Security - Input Validation', () => {
    describe('x25519ECDH input validation', () => {
      it('should reject null private key', () => {
        const validPublicKey = randomBytes(32);
        expect(() => {
          // @ts-ignore - Testing invalid input
          x25519ECDH(null, validPublicKey);
        }).toThrow(/Invalid private key/);
      });

      it('should reject undefined private key', () => {
        const validPublicKey = randomBytes(32);
        expect(() => {
          // @ts-ignore - Testing invalid input
          x25519ECDH(undefined, validPublicKey);
        }).toThrow(/Invalid private key/);
      });

      it('should reject short private key (31 bytes)', () => {
        const shortKey = randomBytes(31);
        const validPublicKey = randomBytes(32);
        expect(() => {
          x25519ECDH(shortKey, validPublicKey);
        }).toThrow(/Invalid private key.*expected 32 bytes.*got 31/);
      });

      it('should reject long private key (33 bytes)', () => {
        const longKey = randomBytes(33);
        const validPublicKey = randomBytes(32);
        expect(() => {
          x25519ECDH(longKey, validPublicKey);
        }).toThrow(/Invalid private key.*expected 32 bytes.*got 33/);
      });

      it('should reject null public key', () => {
        const validPrivateKey = randomBytes(32);
        expect(() => {
          // @ts-ignore - Testing invalid input
          x25519ECDH(validPrivateKey, null);
        }).toThrow(/Invalid public key/);
      });

      it('should reject short public key (31 bytes)', () => {
        const validPrivateKey = randomBytes(32);
        const shortKey = randomBytes(31);
        expect(() => {
          x25519ECDH(validPrivateKey, shortKey);
        }).toThrow(/Invalid public key.*expected 32 bytes.*got 31/);
      });
    });

    describe('x25519PrivateToEd25519 input validation', () => {
      it('should reject null input', () => {
        expect(() => {
          // @ts-ignore - Testing invalid input
          x25519PrivateToEd25519(null);
        }).toThrow(/Invalid X25519 private key/);
      });

      it('should reject wrong size input', () => {
        expect(() => {
          x25519PrivateToEd25519(randomBytes(16));
        }).toThrow(/Invalid X25519 private key.*expected 32 bytes.*got 16/);
      });
    });

    describe('ed25519Sign input validation', () => {
      it('should reject null message', () => {
        const keyPair = generateEd25519KeyPair();
        expect(() => {
          // @ts-ignore - Testing invalid input
          ed25519Sign(null, keyPair.privateKey);
        }).toThrow(/Message is required/);
      });

      it('should reject null private key', () => {
        const message = new TextEncoder().encode('test');
        expect(() => {
          // @ts-ignore - Testing invalid input
          ed25519Sign(message, null);
        }).toThrow(/Private key is required/);
      });

      it('should reject invalid private key size', () => {
        const message = new TextEncoder().encode('test');
        expect(() => {
          ed25519Sign(message, randomBytes(16));
        }).toThrow(/Invalid Ed25519 private key.*expected 32 or 64 bytes.*got 16/);
      });

      it('should accept 32-byte private key (seed)', () => {
        const message = new TextEncoder().encode('test');
        const seed = randomBytes(32);
        expect(() => {
          ed25519Sign(message, seed);
        }).not.toThrow();
      });

      it('should accept 64-byte private key', () => {
        const message = new TextEncoder().encode('test');
        const keyPair = generateEd25519KeyPair();
        expect(() => {
          ed25519Sign(message, keyPair.privateKey);
        }).not.toThrow();
      });
    });

    describe('ed25519Verify input validation', () => {
      it('should reject null message', () => {
        const keyPair = generateEd25519KeyPair();
        const signature = randomBytes(64);
        expect(() => {
          // @ts-ignore - Testing invalid input
          ed25519Verify(null, signature, keyPair.publicKey);
        }).toThrow(/Message is required/);
      });

      it('should reject null signature', () => {
        const message = new TextEncoder().encode('test');
        const keyPair = generateEd25519KeyPair();
        expect(() => {
          // @ts-ignore - Testing invalid input
          ed25519Verify(message, null, keyPair.publicKey);
        }).toThrow(/Invalid signature/);
      });

      it('should reject short signature (63 bytes)', () => {
        const message = new TextEncoder().encode('test');
        const keyPair = generateEd25519KeyPair();
        const shortSig = randomBytes(63);
        expect(() => {
          ed25519Verify(message, shortSig, keyPair.publicKey);
        }).toThrow(/Invalid signature.*expected 64 bytes.*got 63/);
      });

      it('should reject null public key', () => {
        const message = new TextEncoder().encode('test');
        const signature = randomBytes(64);
        expect(() => {
          // @ts-ignore - Testing invalid input
          ed25519Verify(message, signature, null);
        }).toThrow(/Invalid public key/);
      });

      it('should reject short public key (31 bytes)', () => {
        const message = new TextEncoder().encode('test');
        const signature = randomBytes(64);
        const shortKey = randomBytes(31);
        expect(() => {
          ed25519Verify(message, signature, shortKey);
        }).toThrow(/Invalid public key.*expected 32 bytes.*got 31/);
      });
    });

    describe('encryptXChaCha20Poly1305 input validation', () => {
      it('should reject null plaintext', () => {
        const key = randomBytes(32);
        expect(() => {
          // @ts-ignore - Testing invalid input
          encryptXChaCha20Poly1305(null, key);
        }).toThrow(/Plaintext is required/);
      });

      it('should reject null key', () => {
        const plaintext = new TextEncoder().encode('test');
        expect(() => {
          // @ts-ignore - Testing invalid input
          encryptXChaCha20Poly1305(plaintext, null);
        }).toThrow(/Invalid encryption key/);
      });

      it('should reject short key (31 bytes)', () => {
        const plaintext = new TextEncoder().encode('test');
        const shortKey = randomBytes(31);
        expect(() => {
          encryptXChaCha20Poly1305(plaintext, shortKey);
        }).toThrow(/Invalid encryption key.*expected 32 bytes.*got 31/);
      });

      it('should reject long key (33 bytes)', () => {
        const plaintext = new TextEncoder().encode('test');
        const longKey = randomBytes(33);
        expect(() => {
          encryptXChaCha20Poly1305(plaintext, longKey);
        }).toThrow(/Invalid encryption key.*expected 32 bytes.*got 33/);
      });
    });

    describe('decryptXChaCha20Poly1305 input validation', () => {
      it('should reject null key', () => {
        const ciphertext = randomBytes(48);
        const nonce = randomBytes(24);
        expect(() => {
          // @ts-ignore - Testing invalid input
          decryptXChaCha20Poly1305(ciphertext, nonce, null);
        }).toThrow(/Invalid decryption key/);
      });

      it('should reject short key (31 bytes)', () => {
        const ciphertext = randomBytes(48);
        const nonce = randomBytes(24);
        const shortKey = randomBytes(31);
        expect(() => {
          decryptXChaCha20Poly1305(ciphertext, nonce, shortKey);
        }).toThrow(/Invalid decryption key.*expected 32 bytes.*got 31/);
      });

      it('should reject short nonce (23 bytes)', () => {
        const ciphertext = randomBytes(48);
        const shortNonce = randomBytes(23);
        const key = randomBytes(32);
        expect(() => {
          decryptXChaCha20Poly1305(ciphertext, shortNonce, key);
        }).toThrow(/Invalid nonce.*expected 24 bytes.*got 23/);
      });

      it('should reject ciphertext shorter than tag (15 bytes)', () => {
        const shortCiphertext = randomBytes(15);
        const nonce = randomBytes(24);
        const key = randomBytes(32);
        expect(() => {
          decryptXChaCha20Poly1305(shortCiphertext, nonce, key);
        }).toThrow(/Invalid ciphertext.*minimum length is 16 bytes/);
      });
    });

    describe('deriveKey input validation', () => {
      it('should reject null IKM', () => {
        const info = new TextEncoder().encode('test');
        expect(() => {
          // @ts-ignore - Testing invalid input
          deriveKey(null, info, 32);
        }).toThrow(/Invalid input key material/);
      });

      it('should reject short IKM (15 bytes)', () => {
        const shortIKM = randomBytes(15);
        const info = new TextEncoder().encode('test');
        expect(() => {
          deriveKey(shortIKM, info, 32);
        }).toThrow(/Invalid input key material.*minimum 16 bytes.*got 15/);
      });

      it('should reject null info', () => {
        const ikm = randomBytes(32);
        expect(() => {
          // @ts-ignore - Testing invalid input
          deriveKey(ikm, null, 32);
        }).toThrow(/Info parameter is required/);
      });

      it('should reject invalid output length (0)', () => {
        const ikm = randomBytes(32);
        const info = new TextEncoder().encode('test');
        expect(() => {
          deriveKey(ikm, info, 0);
        }).toThrow(/Invalid output length.*must be 1-8160/);
      });

      it('should reject invalid output length (8161, above HKDF-SHA256 max)', () => {
        // HKDF-SHA256 (RFC 5869) supports up to 255*HashLen = 8160 bytes;
        // 8160 is valid, 8161 is the first invalid length. (64 was the bound
        // of the old BLAKE2b construction this KDF was migrated away from.)
        const ikm = randomBytes(32);
        const info = new TextEncoder().encode('test');
        expect(() => {
          deriveKey(ikm, info, 8161);
        }).toThrow(/Invalid output length.*must be 1-8160/);
      });

      it('should accept a 65-byte output (valid for HKDF-SHA256)', () => {
        const ikm = randomBytes(32);
        const info = new TextEncoder().encode('test');
        const out = deriveKey(ikm, info, 65);
        expect(out).toBeInstanceOf(Uint8Array);
        expect(out.length).toBe(65);
      });
    });

    describe('deriveRatchetKeys input validation', () => {
      it('should reject null root key', () => {
        const dhOutput = randomBytes(32);
        expect(() => {
          // @ts-ignore - Testing invalid input
          deriveRatchetKeys(null, dhOutput);
        }).toThrow(/Invalid root key/);
      });

      it('should reject short root key (31 bytes)', () => {
        const shortKey = randomBytes(31);
        const dhOutput = randomBytes(32);
        expect(() => {
          deriveRatchetKeys(shortKey, dhOutput);
        }).toThrow(/Invalid root key.*expected 32 bytes.*got 31/);
      });

      it('should reject null DH output', () => {
        const rootKey = randomBytes(32);
        expect(() => {
          // @ts-ignore - Testing invalid input
          deriveRatchetKeys(rootKey, null);
        }).toThrow(/Invalid DH output/);
      });

      it('should reject short DH output (31 bytes)', () => {
        const rootKey = randomBytes(32);
        const shortDH = randomBytes(31);
        expect(() => {
          deriveRatchetKeys(rootKey, shortDH);
        }).toThrow(/Invalid DH output.*expected 32 bytes.*got 31/);
      });
    });

    describe('deriveMessageKeys input validation', () => {
      it('should reject null chain key', () => {
        expect(() => {
          // @ts-ignore - Testing invalid input
          deriveMessageKeys(null);
        }).toThrow(/Invalid chain key/);
      });

      it('should reject short chain key (31 bytes)', () => {
        const shortKey = randomBytes(31);
        expect(() => {
          deriveMessageKeys(shortKey);
        }).toThrow(/Invalid chain key.*expected 32 bytes.*got 31/);
      });
    });

    describe('hexToBytes input validation', () => {
      it('should reject null input', () => {
        expect(() => {
          // @ts-ignore - Testing invalid input
          hexToBytes(null);
        }).toThrow(/Hex string is required/);
      });

      it('should reject odd-length hex string', () => {
        expect(() => {
          hexToBytes('abc');
        }).toThrow(/Hex string must have even length/);
      });

      it('should reject invalid hex characters', () => {
        expect(() => {
          hexToBytes('ghij');
        }).toThrow(/Hex string contains invalid characters/);
      });

      it('should accept valid hex string', () => {
        expect(() => {
          hexToBytes('abcdef0123456789');
        }).not.toThrow();
      });
    });

    describe('base64ToBytes input validation', () => {
      it('should reject null input', () => {
        expect(() => {
          // @ts-ignore - Testing invalid input
          base64ToBytes(null);
        }).toThrow(/Base64 string is required/);
      });

      it('should reject invalid base64', () => {
        expect(() => {
          base64ToBytes('!!!invalid!!!');
        }).toThrow(/Invalid base64 string/);
      });

      it('should accept valid base64', () => {
        expect(() => {
          base64ToBytes('SGVsbG8gV29ybGQ=');
        }).not.toThrow();
      });
    });

    describe('secureCompare timing attack resistance', () => {
      it('should return false for different length arrays (constant time)', () => {
        const a = new Uint8Array([1, 2, 3, 4, 5]);
        const b = new Uint8Array([1, 2, 3]);
        expect(secureCompare(a, b)).toBe(false);
      });

      it('should return false for longer second array (constant time)', () => {
        const a = new Uint8Array([1, 2, 3]);
        const b = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        expect(secureCompare(a, b)).toBe(false);
      });

      it('should handle null/undefined inputs', () => {
        // @ts-ignore - Testing edge cases
        expect(secureCompare(null, null)).toBe(true);
        // @ts-ignore - Testing edge cases
        expect(secureCompare(undefined, undefined)).toBe(true);
        // @ts-ignore - Testing edge cases
        expect(secureCompare(null, new Uint8Array([1]))).toBe(false);
        // @ts-ignore - Testing edge cases
        expect(secureCompare(new Uint8Array([1]), null)).toBe(false);
      });
    });

    describe('deriveMultipleKeys input validation', () => {
      it('should reject null master key', () => {
        expect(() => {
          // @ts-ignore - Testing invalid input
          deriveMultipleKeys(null, 'test', 2);
        }).toThrow(/Invalid master key/);
      });

      it('should reject short master key', () => {
        expect(() => {
          deriveMultipleKeys(randomBytes(15), 'test', 2);
        }).toThrow(/Invalid master key.*minimum 16 bytes/);
      });

      it('should reject empty context', () => {
        expect(() => {
          deriveMultipleKeys(randomBytes(32), '', 2);
        }).toThrow(/Context string is required/);
      });

      it('should reject invalid numKeys (0)', () => {
        expect(() => {
          deriveMultipleKeys(randomBytes(32), 'test', 0);
        }).toThrow(/Invalid numKeys.*must be 1-256/);
      });

      it('should reject invalid numKeys (257)', () => {
        expect(() => {
          deriveMultipleKeys(randomBytes(32), 'test', 257);
        }).toThrow(/Invalid numKeys.*must be 1-256/);
      });

      it('should reject invalid keyLength (0)', () => {
        expect(() => {
          deriveMultipleKeys(randomBytes(32), 'test', 2, 0);
        }).toThrow(/Invalid keyLength.*must be 1-8160/);
      });

      it('should reject invalid keyLength (8161, above HKDF-SHA256 max)', () => {
        // HKDF-SHA256 supports up to 255*32 = 8160 bytes per key; 8161 is the
        // first invalid length. (64 was the old BLAKE2b bound, since migrated.)
        expect(() => {
          deriveMultipleKeys(randomBytes(32), 'test', 2, 8161);
        }).toThrow(/Invalid keyLength.*must be 1-8160/);
      });

      it('should accept a 65-byte keyLength (valid for HKDF-SHA256)', () => {
        const keys = deriveMultipleKeys(randomBytes(32), 'test', 2, 65);
        expect(keys).toHaveLength(2);
        expect(keys[0].length).toBe(65);
        expect(keys[1].length).toBe(65);
      });
    });
  });
});
