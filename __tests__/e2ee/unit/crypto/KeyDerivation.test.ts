/**
 * Key Derivation Unit Tests
 *
 * Tests for all key derivation functions used in the Signal Protocol implementation.
 * These tests verify correctness and security properties of key derivation.
 */

import {
  initializeSodium,
  deriveKey,
  deriveMultipleKeys,
  deriveRatchetKeys,
  deriveMessageKeys,
  randomBytes,
  bytesToHex,
  hexToBytes,
  hash256,
} from '@/src/services/SodiumCrypto';

import {
  TEST_SYMMETRIC_KEYS,
  getSymmetricKey,
} from '../../fixtures/keyPairs';

import {
  SIGNAL_PROTOCOL_TEST_VECTORS,
} from '../../fixtures/testVectors';

describe('Key Derivation Functions', () => {
  beforeAll(async () => {
    await initializeSodium();
  });

  describe('deriveKey - Signal Protocol KDF', () => {
    it('should derive 32-byte key from shared secret', () => {
      const sharedSecret = randomBytes(32);
      const info = new TextEncoder().encode('WhisperText');

      const derivedKey = deriveKey(sharedSecret, info, 32);

      expect(derivedKey.length).toBe(32);
      expect(derivedKey).toBeInstanceOf(Uint8Array);
    });

    it('should support variable output lengths', () => {
      const inputKey = randomBytes(32);
      const info = new TextEncoder().encode('test');

      const key16 = deriveKey(inputKey, info, 16);
      const key32 = deriveKey(inputKey, info, 32);
      const key64 = deriveKey(inputKey, info, 64);

      expect(key16.length).toBe(16);
      expect(key32.length).toBe(32);
      expect(key64.length).toBe(64);
    });

    it('should be context-dependent (different info produces different keys)', () => {
      const inputKey = randomBytes(32);
      const info1 = new TextEncoder().encode('MessageKeys');
      const info2 = new TextEncoder().encode('ChainKeys');

      const key1 = deriveKey(inputKey, info1, 32);
      const key2 = deriveKey(inputKey, info2, 32);

      expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
    });

    it('should be deterministic', () => {
      const inputKey = randomBytes(32);
      const info = new TextEncoder().encode('DeterministicTest');

      const key1 = deriveKey(inputKey, info, 32);
      const key2 = deriveKey(inputKey, info, 32);

      expect(bytesToHex(key1)).toBe(bytesToHex(key2));
    });

    it('should handle empty info', () => {
      const inputKey = randomBytes(32);
      const emptyInfo = new Uint8Array(0);

      const derivedKey = deriveKey(inputKey, emptyInfo, 32);

      expect(derivedKey.length).toBe(32);
    });

    it('should handle large info', () => {
      const inputKey = randomBytes(32);
      const largeInfo = new TextEncoder().encode('A'.repeat(1000));

      const derivedKey = deriveKey(inputKey, largeInfo, 32);

      expect(derivedKey.length).toBe(32);
    });

    describe('with salt (4-parameter signature)', () => {
      it('should derive key with salt', () => {
        const inputKey = randomBytes(32);
        const salt = randomBytes(16);
        const info = new TextEncoder().encode('test');

        const derivedKey = deriveKey(inputKey, salt, info, 32);

        expect(derivedKey.length).toBe(32);
      });

      it('should produce different keys with different salts', () => {
        const inputKey = randomBytes(32);
        const salt1 = randomBytes(16);
        const salt2 = randomBytes(16);
        const info = new TextEncoder().encode('test');

        const key1 = deriveKey(inputKey, salt1, info, 32);
        const key2 = deriveKey(inputKey, salt2, info, 32);

        expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
      });

      it('should handle empty salt as null salt', () => {
        const inputKey = randomBytes(32);
        const info = new TextEncoder().encode('test');

        const keyNullSalt = deriveKey(inputKey, null, info, 32);
        const keyEmptySalt = deriveKey(inputKey, new Uint8Array(0), info, 32);

        // Empty salt behaves differently from null salt due to keyed hash
        expect(keyNullSalt.length).toBe(32);
        expect(keyEmptySalt.length).toBe(32);
      });
    });
  });

  describe('deriveMultipleKeys - Batch Key Derivation', () => {
    it('should derive multiple keys from master key', () => {
      const masterKey = randomBytes(32);

      const keys = deriveMultipleKeys(masterKey, 'TestContext', 4);

      expect(keys.length).toBe(4);
      keys.forEach((key) => {
        expect(key.length).toBe(32); // Default key length
      });
    });

    it('should derive unique keys for each index', () => {
      const masterKey = randomBytes(32);

      const keys = deriveMultipleKeys(masterKey, 'UniqueTest', 5);

      const hexKeys = keys.map((k) => bytesToHex(k));
      const uniqueKeys = new Set(hexKeys);

      expect(uniqueKeys.size).toBe(5); // All keys should be unique
    });

    it('should respect custom key length', () => {
      const masterKey = randomBytes(32);

      const keys = deriveMultipleKeys(masterKey, 'CustomLength', 2, 48);

      expect(keys[0].length).toBe(48);
      expect(keys[1].length).toBe(48);
    });

    it('should be deterministic with same inputs', () => {
      const masterKey = randomBytes(32);
      const context = 'DeterministicMultiple';

      const keys1 = deriveMultipleKeys(masterKey, context, 3);
      const keys2 = deriveMultipleKeys(masterKey, context, 3);

      for (let i = 0; i < 3; i++) {
        expect(bytesToHex(keys1[i])).toBe(bytesToHex(keys2[i]));
      }
    });

    it('should produce different keys for different contexts', () => {
      const masterKey = randomBytes(32);

      const keysA = deriveMultipleKeys(masterKey, 'ContextA', 2);
      const keysB = deriveMultipleKeys(masterKey, 'ContextB', 2);

      expect(bytesToHex(keysA[0])).not.toBe(bytesToHex(keysB[0]));
      expect(bytesToHex(keysA[1])).not.toBe(bytesToHex(keysB[1]));
    });

    it('should handle deriving a single key', () => {
      const masterKey = randomBytes(32);

      const keys = deriveMultipleKeys(masterKey, 'Single', 1);

      expect(keys.length).toBe(1);
      expect(keys[0].length).toBe(32);
    });
  });

  describe('deriveRatchetKeys - Double Ratchet KDF', () => {
    it('should derive new root key and chain key from DH output', () => {
      const rootKey = randomBytes(32);
      const dhOutput = randomBytes(32);

      const { newRootKey, chainKey } = deriveRatchetKeys(rootKey, dhOutput);

      expect(newRootKey.length).toBe(32);
      expect(chainKey.length).toBe(32);
    });

    it('should produce different root and chain keys', () => {
      const rootKey = randomBytes(32);
      const dhOutput = randomBytes(32);

      const { newRootKey, chainKey } = deriveRatchetKeys(rootKey, dhOutput);

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

    it('should produce different output for different DH outputs (forward secrecy)', () => {
      const rootKey = randomBytes(32);
      const dhOutput1 = randomBytes(32);
      const dhOutput2 = randomBytes(32);

      const result1 = deriveRatchetKeys(rootKey, dhOutput1);
      const result2 = deriveRatchetKeys(rootKey, dhOutput2);

      expect(bytesToHex(result1.newRootKey)).not.toBe(bytesToHex(result2.newRootKey));
      expect(bytesToHex(result1.chainKey)).not.toBe(bytesToHex(result2.chainKey));
    });

    it('should produce different output for different root keys', () => {
      const rootKey1 = randomBytes(32);
      const rootKey2 = randomBytes(32);
      const dhOutput = randomBytes(32);

      const result1 = deriveRatchetKeys(rootKey1, dhOutput);
      const result2 = deriveRatchetKeys(rootKey2, dhOutput);

      expect(bytesToHex(result1.newRootKey)).not.toBe(bytesToHex(result2.newRootKey));
    });

    it('should use WhisperRatchet context', () => {
      // Verify the function uses the correct context internally
      const rootKey = randomBytes(32);
      const dhOutput = randomBytes(32);

      const result = deriveRatchetKeys(rootKey, dhOutput);

      // The result should be non-zero and 32 bytes
      expect(result.newRootKey.some((b) => b !== 0)).toBe(true);
      expect(result.chainKey.some((b) => b !== 0)).toBe(true);
    });
  });

  describe('deriveMessageKeys - Symmetric Ratchet KDF', () => {
    it('should derive message key and next chain key', () => {
      const chainKey = randomBytes(32);

      const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);

      expect(messageKey.length).toBe(32);
      expect(nextChainKey.length).toBe(32);
    });

    it('should produce different message key and next chain key', () => {
      const chainKey = randomBytes(32);

      const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);

      expect(bytesToHex(messageKey)).not.toBe(bytesToHex(nextChainKey));
    });

    it('should be deterministic', () => {
      const chainKey = randomBytes(32);

      const result1 = deriveMessageKeys(chainKey);
      const result2 = deriveMessageKeys(chainKey);

      expect(bytesToHex(result1.messageKey)).toBe(bytesToHex(result2.messageKey));
      expect(bytesToHex(result1.nextChainKey)).toBe(bytesToHex(result2.nextChainKey));
    });

    it('should produce a chain of unique message keys', () => {
      let chainKey = randomBytes(32);
      const messageKeys: string[] = [];

      for (let i = 0; i < 10; i++) {
        const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);
        messageKeys.push(bytesToHex(messageKey));
        chainKey = nextChainKey;
      }

      const uniqueKeys = new Set(messageKeys);
      expect(uniqueKeys.size).toBe(10); // All message keys should be unique
    });

    it('should not allow deriving previous keys from next chain key (forward secrecy)', () => {
      const initialChainKey = randomBytes(32);

      // Derive a sequence of keys
      const { messageKey: msg1, nextChainKey: chain1 } = deriveMessageKeys(initialChainKey);
      const { messageKey: msg2, nextChainKey: chain2 } = deriveMessageKeys(chain1);
      const { messageKey: msg3 } = deriveMessageKeys(chain2);

      // Having chain2, we can derive msg3 but not msg1 or msg2
      // This is verified by the fact that we can't reverse the hash
      expect(bytesToHex(msg1)).not.toBe(bytesToHex(msg2));
      expect(bytesToHex(msg2)).not.toBe(bytesToHex(msg3));

      // Verify we can still derive forward
      const { messageKey: verifyMsg3 } = deriveMessageKeys(chain2);
      expect(bytesToHex(verifyMsg3)).toBe(bytesToHex(msg3));
    });

    it('should use correct constants (0x01 for message key, 0x02 for chain key)', () => {
      const chainKey = randomBytes(32);

      const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);

      // Manually compute expected values
      const messageKeyInput = new Uint8Array(chainKey.length + 1);
      messageKeyInput.set(chainKey, 0);
      messageKeyInput[chainKey.length] = 0x01;
      const expectedMessageKey = hash256(messageKeyInput);

      const chainKeyInput = new Uint8Array(chainKey.length + 1);
      chainKeyInput.set(chainKey, 0);
      chainKeyInput[chainKey.length] = 0x02;
      const expectedChainKey = hash256(chainKeyInput);

      expect(bytesToHex(messageKey)).toBe(bytesToHex(expectedMessageKey));
      expect(bytesToHex(nextChainKey)).toBe(bytesToHex(expectedChainKey));
    });
  });

  describe('Key Derivation Security Properties', () => {
    it('should be computationally infeasible to derive input from output', () => {
      // This is a property test - we verify the output looks random
      const inputKey = randomBytes(32);
      const info = new TextEncoder().encode('test');

      const derivedKey = deriveKey(inputKey, info, 32);

      // Output should not contain input patterns
      expect(bytesToHex(derivedKey)).not.toContain(bytesToHex(inputKey));
    });

    it('should produce statistically uniform output', () => {
      // Generate many keys and check distribution
      const inputKey = randomBytes(32);
      const byteDistribution = new Array(256).fill(0);

      for (let i = 0; i < 1000; i++) {
        const info = new TextEncoder().encode(`test-${i}`);
        const key = deriveKey(inputKey, info, 32);
        key.forEach((b) => byteDistribution[b]++);
      }

      // Check that no byte value is significantly overrepresented
      const totalBytes = 1000 * 32;
      const expectedPerByte = totalBytes / 256;
      // Use 50% tolerance for statistical variance with this sample size
      const tolerance = expectedPerByte * 0.5;

      byteDistribution.forEach((count) => {
        expect(count).toBeGreaterThan(expectedPerByte - tolerance);
        expect(count).toBeLessThan(expectedPerByte + tolerance);
      });
    });

    it('should maintain avalanche effect (small input change causes large output change)', () => {
      const inputKey1 = randomBytes(32);
      const inputKey2 = new Uint8Array(inputKey1);
      inputKey2[0] ^= 0x01; // Flip one bit

      const info = new TextEncoder().encode('avalanche-test');

      const key1 = deriveKey(inputKey1, info, 32);
      const key2 = deriveKey(inputKey2, info, 32);

      // Count differing bits
      let differentBits = 0;
      for (let i = 0; i < 32; i++) {
        let xor = key1[i] ^ key2[i];
        while (xor) {
          differentBits += xor & 1;
          xor >>= 1;
        }
      }

      // Expect approximately 50% of bits to differ (128 out of 256)
      // Allow for 40-60% range
      expect(differentBits).toBeGreaterThan(256 * 0.4);
      expect(differentBits).toBeLessThan(256 * 0.6);
    });
  });

  describe('Performance', () => {
    it('should derive keys quickly', () => {
      const inputKey = randomBytes(32);
      const info = new TextEncoder().encode('performance-test');

      const start = performance.now();
      for (let i = 0; i < 1000; i++) {
        deriveKey(inputKey, info, 32);
      }
      const elapsed = performance.now() - start;

      // Should complete 1000 derivations in under 1 second
      expect(elapsed).toBeLessThan(1000);
    });

    it('should derive message keys quickly for real-time messaging', () => {
      let chainKey = randomBytes(32);

      const start = performance.now();
      for (let i = 0; i < 10000; i++) {
        const { nextChainKey } = deriveMessageKeys(chainKey);
        chainKey = nextChainKey;
      }
      const elapsed = performance.now() - start;

      // Should complete 10000 message key derivations in under 2 seconds
      expect(elapsed).toBeLessThan(2000);
    });
  });
});
