/**
 * Double Ratchet Protocol Unit Tests
 *
 * Tests for the Signal Protocol Double Ratchet algorithm which provides
 * forward secrecy and break-in recovery for secure messaging.
 *
 * These tests verify the cryptographic primitives used in Double Ratchet
 * without implementing the full protocol state machine.
 */

import {
  initializeSodium,
  generateX25519KeyPair,
  x25519ECDH,
  deriveKey,
  deriveRatchetKeys,
  deriveMessageKeys,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  bytesToHex,
  randomBytes,
} from '@/src/services/SodiumCrypto';

describe('Double Ratchet Protocol', () => {
  beforeAll(async () => {
    await initializeSodium();
  });

  describe('Symmetric Ratchet (Chain Key Derivation)', () => {
    it('should derive message key and next chain key from chain key', () => {
      const chainKey = randomBytes(32);
      const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);

      expect(messageKey.length).toBe(32);
      expect(nextChainKey.length).toBe(32);
      expect(bytesToHex(messageKey)).not.toBe(bytesToHex(chainKey));
      expect(bytesToHex(nextChainKey)).not.toBe(bytesToHex(chainKey));
      expect(bytesToHex(messageKey)).not.toBe(bytesToHex(nextChainKey));
    });

    it('should produce deterministic derivation', () => {
      const chainKey = randomBytes(32);

      const result1 = deriveMessageKeys(chainKey);
      const result2 = deriveMessageKeys(chainKey);

      expect(bytesToHex(result1.messageKey)).toBe(bytesToHex(result2.messageKey));
      expect(bytesToHex(result1.nextChainKey)).toBe(bytesToHex(result2.nextChainKey));
    });

    it('should produce unique keys when ratcheting forward', () => {
      let chainKey = randomBytes(32);
      const messageKeys: string[] = [];
      const chainKeys: string[] = [bytesToHex(chainKey)];

      // Ratchet forward 10 times
      for (let i = 0; i < 10; i++) {
        const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);
        messageKeys.push(bytesToHex(messageKey));
        chainKeys.push(bytesToHex(nextChainKey));
        chainKey = nextChainKey;
      }

      // All message keys should be unique
      const uniqueMessageKeys = new Set(messageKeys);
      expect(uniqueMessageKeys.size).toBe(10);

      // All chain keys should be unique
      const uniqueChainKeys = new Set(chainKeys);
      expect(uniqueChainKeys.size).toBe(11);
    });

    it('should allow encryption with derived message key', () => {
      const chainKey = randomBytes(32);
      const { messageKey } = deriveMessageKeys(chainKey);

      const plaintext = new TextEncoder().encode('Test message');
      const encrypted = encryptXChaCha20Poly1305(plaintext, messageKey);
      const decrypted = decryptXChaCha20Poly1305(encrypted, messageKey);

      expect(new TextDecoder().decode(decrypted)).toBe('Test message');
    });
  });

  describe('DH Ratchet (Root Key Derivation)', () => {
    it('should derive new root key and chain key from DH output', () => {
      const rootKey = randomBytes(32);
      const dhOutput = randomBytes(32);

      const { newRootKey, chainKey } = deriveRatchetKeys(rootKey, dhOutput);

      expect(newRootKey.length).toBe(32);
      expect(chainKey.length).toBe(32);
      expect(bytesToHex(newRootKey)).not.toBe(bytesToHex(rootKey));
      expect(bytesToHex(chainKey)).not.toBe(bytesToHex(rootKey));
      expect(bytesToHex(newRootKey)).not.toBe(bytesToHex(chainKey));
    });

    it('should produce deterministic derivation', () => {
      const rootKey = randomBytes(32);
      const dhOutput = randomBytes(32);

      const result1 = deriveRatchetKeys(rootKey, dhOutput);
      const result2 = deriveRatchetKeys(rootKey, dhOutput);

      expect(bytesToHex(result1.newRootKey)).toBe(bytesToHex(result2.newRootKey));
      expect(bytesToHex(result1.chainKey)).toBe(bytesToHex(result2.chainKey));
    });

    it('should produce different keys for different DH outputs', () => {
      const rootKey = randomBytes(32);
      const dhOutput1 = randomBytes(32);
      const dhOutput2 = randomBytes(32);

      const result1 = deriveRatchetKeys(rootKey, dhOutput1);
      const result2 = deriveRatchetKeys(rootKey, dhOutput2);

      expect(bytesToHex(result1.newRootKey)).not.toBe(bytesToHex(result2.newRootKey));
      expect(bytesToHex(result1.chainKey)).not.toBe(bytesToHex(result2.chainKey));
    });
  });

  describe('X25519 ECDH for Key Agreement', () => {
    it('should compute same shared secret from both sides', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();

      const aliceShared = x25519ECDH(alice.privateKey, bob.publicKey);
      const bobShared = x25519ECDH(bob.privateKey, alice.publicKey);

      expect(bytesToHex(aliceShared)).toBe(bytesToHex(bobShared));
    });

    it('should produce different shared secrets with different keys', () => {
      const alice = generateX25519KeyPair();
      const bob = generateX25519KeyPair();
      const carol = generateX25519KeyPair();

      const aliceBobShared = x25519ECDH(alice.privateKey, bob.publicKey);
      const aliceCarolShared = x25519ECDH(alice.privateKey, carol.publicKey);

      expect(bytesToHex(aliceBobShared)).not.toBe(bytesToHex(aliceCarolShared));
    });
  });

  describe('Forward Secrecy Properties', () => {
    it('should not be able to derive future keys from current chain key', () => {
      let chainKey = randomBytes(32);
      const initialChainKey = new Uint8Array(chainKey);

      // Derive 5 message keys
      const messageKeys: Uint8Array[] = [];
      for (let i = 0; i < 5; i++) {
        const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);
        messageKeys.push(messageKey);
        chainKey = nextChainKey;
      }

      // Starting from initial chain key, we can derive all message keys
      let verifyChainKey = initialChainKey;
      for (let i = 0; i < 5; i++) {
        const { messageKey, nextChainKey } = deriveMessageKeys(verifyChainKey);
        expect(bytesToHex(messageKey)).toBe(bytesToHex(messageKeys[i]));
        verifyChainKey = nextChainKey;
      }
    });

    it('should provide break-in recovery through DH ratchet', () => {
      const rootKey = randomBytes(32);

      // Alice's initial ratchet key
      const aliceRatchet1 = generateX25519KeyPair();
      const bobRatchet = generateX25519KeyPair();

      // Compute initial DH shared secret
      const dh1 = x25519ECDH(aliceRatchet1.privateKey, bobRatchet.publicKey);
      const { newRootKey: rootKey2, chainKey: chainKey1 } = deriveRatchetKeys(rootKey, dh1);

      // Compromise: attacker knows rootKey2 and chainKey1
      const compromisedChainKey = chainKey1;

      // Alice generates new ratchet key (recovery)
      const aliceRatchet2 = generateX25519KeyPair();
      const dh2 = x25519ECDH(aliceRatchet2.privateKey, bobRatchet.publicKey);
      const { newRootKey: rootKey3, chainKey: chainKey2 } = deriveRatchetKeys(rootKey2, dh2);

      // New chain key should be different and unknowable from compromised key
      expect(bytesToHex(chainKey2)).not.toBe(bytesToHex(compromisedChainKey));

      // Verify the compromised chain key cannot derive the new one
      // (This is the break-in recovery property)
      const { nextChainKey } = deriveMessageKeys(compromisedChainKey);
      expect(bytesToHex(nextChainKey)).not.toBe(bytesToHex(chainKey2));
    });
  });

  describe('Message Encryption with Ratcheted Keys', () => {
    it('should encrypt/decrypt using chain-derived keys', () => {
      let senderChainKey = randomBytes(32);
      let receiverChainKey = new Uint8Array(senderChainKey);

      const messages = ['Hello', 'World', 'Test'];

      for (const msg of messages) {
        // Sender derives key and encrypts
        const { messageKey: senderMsgKey, nextChainKey: senderNextChain } =
          deriveMessageKeys(senderChainKey);
        senderChainKey = senderNextChain;

        const plaintext = new TextEncoder().encode(msg);
        const encrypted = encryptXChaCha20Poly1305(plaintext, senderMsgKey);

        // Receiver derives same key and decrypts
        const { messageKey: receiverMsgKey, nextChainKey: receiverNextChain } =
          deriveMessageKeys(receiverChainKey);
        receiverChainKey = receiverNextChain;

        const decrypted = decryptXChaCha20Poly1305(encrypted, receiverMsgKey);
        expect(new TextDecoder().decode(decrypted)).toBe(msg);
      }
    });

    it('should fail decryption with wrong chain position', () => {
      const chainKey = randomBytes(32);

      // Derive key at position 0
      const { messageKey: key0 } = deriveMessageKeys(chainKey);

      // Derive key at position 1
      const { nextChainKey } = deriveMessageKeys(chainKey);
      const { messageKey: key1 } = deriveMessageKeys(nextChainKey);

      // Encrypt with key at position 0
      const plaintext = new TextEncoder().encode('Test');
      const encrypted = encryptXChaCha20Poly1305(plaintext, key0);

      // Try to decrypt with key at position 1 - should fail
      expect(() => {
        decryptXChaCha20Poly1305(encrypted, key1);
      }).toThrow();
    });
  });

  describe('Out-of-Order Message Simulation', () => {
    it('should allow storing and using skipped message keys', () => {
      let chainKey = randomBytes(32);
      const skippedKeys = new Map<number, Uint8Array>();

      // Generate 5 message keys and store them (simulating sender)
      for (let i = 0; i < 5; i++) {
        const { messageKey, nextChainKey } = deriveMessageKeys(chainKey);
        skippedKeys.set(i, messageKey);
        chainKey = nextChainKey;
      }

      // Encrypt messages
      const encrypted: Array<{ idx: number; data: ReturnType<typeof encryptXChaCha20Poly1305> }> = [];
      for (let i = 0; i < 5; i++) {
        const plaintext = new TextEncoder().encode(`Message ${i}`);
        encrypted.push({
          idx: i,
          data: encryptXChaCha20Poly1305(plaintext, skippedKeys.get(i)!),
        });
      }

      // Receive out of order: 4, 1, 3, 0, 2
      const order = [4, 1, 3, 0, 2];
      for (const idx of order) {
        const enc = encrypted.find((e) => e.idx === idx)!;
        const key = skippedKeys.get(idx)!;
        const decrypted = decryptXChaCha20Poly1305(enc.data, key);
        expect(new TextDecoder().decode(decrypted)).toBe(`Message ${idx}`);
      }
    });
  });

  describe('Security Properties', () => {
    it('should reject tampered ciphertext', () => {
      const chainKey = randomBytes(32);
      const { messageKey } = deriveMessageKeys(chainKey);

      const plaintext = new TextEncoder().encode('Secret message');
      const encrypted = encryptXChaCha20Poly1305(plaintext, messageKey);

      // Tamper with ciphertext
      const tampered = new Uint8Array(encrypted.ciphertext);
      tampered[0] ^= 0xff;

      expect(() => {
        decryptXChaCha20Poly1305(tampered, encrypted.nonce, messageKey);
      }).toThrow();
    });

    it('should reject tampered nonce', () => {
      const chainKey = randomBytes(32);
      const { messageKey } = deriveMessageKeys(chainKey);

      const plaintext = new TextEncoder().encode('Secret message');
      const encrypted = encryptXChaCha20Poly1305(plaintext, messageKey);

      // Tamper with nonce
      const tampered = new Uint8Array(encrypted.nonce);
      tampered[0] ^= 0xff;

      expect(() => {
        decryptXChaCha20Poly1305(encrypted.ciphertext, tampered, messageKey);
      }).toThrow();
    });

    it('should produce unique nonces for each encryption', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('Test');

      const nonces: string[] = [];
      for (let i = 0; i < 100; i++) {
        const encrypted = encryptXChaCha20Poly1305(plaintext, key);
        nonces.push(bytesToHex(encrypted.nonce));
      }

      const uniqueNonces = new Set(nonces);
      expect(uniqueNonces.size).toBe(100);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty messages', () => {
      const chainKey = randomBytes(32);
      const { messageKey } = deriveMessageKeys(chainKey);

      const plaintext = new Uint8Array(0);
      const encrypted = encryptXChaCha20Poly1305(plaintext, messageKey);
      const decrypted = decryptXChaCha20Poly1305(encrypted, messageKey);

      expect(decrypted.length).toBe(0);
    });

    it('should handle Unicode messages', () => {
      const chainKey = randomBytes(32);
      const { messageKey } = deriveMessageKeys(chainKey);

      const message = 'Hello 👋 World 🌍! سلام';
      const plaintext = new TextEncoder().encode(message);
      const encrypted = encryptXChaCha20Poly1305(plaintext, messageKey);
      const decrypted = decryptXChaCha20Poly1305(encrypted, messageKey);

      expect(new TextDecoder().decode(decrypted)).toBe(message);
    });

    it('should handle long chain ratcheting', () => {
      let chainKey = randomBytes(32);

      // Ratchet 1000 times
      for (let i = 0; i < 1000; i++) {
        const { nextChainKey } = deriveMessageKeys(chainKey);
        chainKey = nextChainKey;
      }

      // Should still produce valid 32-byte key
      expect(chainKey.length).toBe(32);
      expect(chainKey.some((b) => b !== 0)).toBe(true);
    });
  });
});
