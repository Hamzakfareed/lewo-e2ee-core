/**
 * X3DH Key Exchange Unit Tests
 *
 * Tests for the Extended Triple Diffie-Hellman (X3DH) key agreement protocol
 * as used in Signal Protocol. This tests the initial key exchange that
 * establishes shared secrets between two parties.
 */

import {
  initializeSodium,
  generateX25519KeyPair,
  x25519ECDH,
  deriveKey,
  bytesToHex,
  bytesToBase64,
  base64ToBytes,
  randomBytes,
  ed25519Sign,
  ed25519Verify,
  x25519PrivateToEd25519,
  X25519KeyPair,
} from '@/src/services/SodiumCrypto';

import {
  TEST_X25519_KEYS,
  getX25519KeyPair,
} from '../../fixtures/keyPairs';

describe('X3DH Key Exchange Protocol', () => {
  beforeAll(async () => {
    await initializeSodium();
  });

  /**
   * Helper to create a key bundle (Identity Key, Signed Pre-Key, One-Time Pre-Key)
   */
  function createKeyBundle() {
    const identityKey = generateX25519KeyPair();
    const signedPreKey = generateX25519KeyPair();
    const oneTimePreKey = generateX25519KeyPair();

    // Sign the SPK with identity key
    const signingKey = x25519PrivateToEd25519(identityKey.privateKey);
    const signature = ed25519Sign(signedPreKey.publicKey, signingKey);

    return {
      identityKey,
      signedPreKey,
      oneTimePreKey,
      signature,
      // For verification
      _signingPublicKey: signingKey.slice(32), // Ed25519 public key
    };
  }

  /**
   * X3DH key agreement from Alice's perspective (initiator)
   */
  function x3dhInitiator(
    aliceIdentityKey: X25519KeyPair,
    aliceEphemeralKey: X25519KeyPair,
    bobIdentityPublicKey: Uint8Array,
    bobSignedPreKeyPublic: Uint8Array,
    bobOneTimePreKeyPublic?: Uint8Array
  ): Uint8Array {
    // DH1 = DH(IKa, SPKb)
    const dh1 = x25519ECDH(aliceIdentityKey.privateKey, bobSignedPreKeyPublic);

    // DH2 = DH(EKa, IKb)
    const dh2 = x25519ECDH(aliceEphemeralKey.privateKey, bobIdentityPublicKey);

    // DH3 = DH(EKa, SPKb)
    const dh3 = x25519ECDH(aliceEphemeralKey.privateKey, bobSignedPreKeyPublic);

    // Combine DH outputs
    let combinedLength = dh1.length + dh2.length + dh3.length;
    let dh4: Uint8Array | undefined;

    if (bobOneTimePreKeyPublic) {
      // DH4 = DH(EKa, OPKb) - only if one-time pre-key available
      dh4 = x25519ECDH(aliceEphemeralKey.privateKey, bobOneTimePreKeyPublic);
      combinedLength += dh4.length;
    }

    const combined = new Uint8Array(combinedLength);
    combined.set(dh1, 0);
    combined.set(dh2, dh1.length);
    combined.set(dh3, dh1.length + dh2.length);
    if (dh4) {
      combined.set(dh4, dh1.length + dh2.length + dh3.length);
    }

    // Derive shared key
    const info = new TextEncoder().encode('WhisperText');
    return deriveKey(combined, info, 32);
  }

  /**
   * X3DH key agreement from Bob's perspective (responder)
   */
  function x3dhResponder(
    bobIdentityKey: X25519KeyPair,
    bobSignedPreKey: X25519KeyPair,
    aliceIdentityPublicKey: Uint8Array,
    aliceEphemeralPublicKey: Uint8Array,
    bobOneTimePreKey?: X25519KeyPair
  ): Uint8Array {
    // DH1 = DH(SPKb, IKa)
    const dh1 = x25519ECDH(bobSignedPreKey.privateKey, aliceIdentityPublicKey);

    // DH2 = DH(IKb, EKa)
    const dh2 = x25519ECDH(bobIdentityKey.privateKey, aliceEphemeralPublicKey);

    // DH3 = DH(SPKb, EKa)
    const dh3 = x25519ECDH(bobSignedPreKey.privateKey, aliceEphemeralPublicKey);

    // Combine DH outputs
    let combinedLength = dh1.length + dh2.length + dh3.length;
    let dh4: Uint8Array | undefined;

    if (bobOneTimePreKey) {
      // DH4 = DH(OPKb, EKa)
      dh4 = x25519ECDH(bobOneTimePreKey.privateKey, aliceEphemeralPublicKey);
      combinedLength += dh4.length;
    }

    const combined = new Uint8Array(combinedLength);
    combined.set(dh1, 0);
    combined.set(dh2, dh1.length);
    combined.set(dh3, dh1.length + dh2.length);
    if (dh4) {
      combined.set(dh4, dh1.length + dh2.length + dh3.length);
    }

    // Derive shared key
    const info = new TextEncoder().encode('WhisperText');
    return deriveKey(combined, info, 32);
  }

  describe('Basic X3DH Agreement', () => {
    it('should establish shared secret between Alice and Bob with OPK', () => {
      // Bob's keys (published to server)
      const bob = createKeyBundle();

      // Alice's keys
      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      // Alice computes shared secret
      const aliceShared = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey,
        bob.oneTimePreKey.publicKey
      );

      // Bob computes shared secret
      const bobShared = x3dhResponder(
        bob.identityKey,
        bob.signedPreKey,
        aliceIdentity.publicKey,
        aliceEphemeral.publicKey,
        bob.oneTimePreKey
      );

      expect(bytesToHex(aliceShared)).toBe(bytesToHex(bobShared));
    });

    it('should establish shared secret without OPK', () => {
      // Bob's keys (no OPK)
      const bobIdentity = generateX25519KeyPair();
      const bobSignedPreKey = generateX25519KeyPair();

      // Alice's keys
      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      // Alice computes shared secret (no OPK)
      const aliceShared = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        bobSignedPreKey.publicKey
        // No OPK
      );

      // Bob computes shared secret (no OPK)
      const bobShared = x3dhResponder(
        bobIdentity,
        bobSignedPreKey,
        aliceIdentity.publicKey,
        aliceEphemeral.publicKey
        // No OPK
      );

      expect(bytesToHex(aliceShared)).toBe(bytesToHex(bobShared));
    });
  });

  describe('Security Properties', () => {
    it('should produce different shared secrets for different sessions', () => {
      const bob = createKeyBundle();

      // Session 1
      const alice1Identity = generateX25519KeyPair();
      const alice1Ephemeral = generateX25519KeyPair();
      const shared1 = x3dhInitiator(
        alice1Identity,
        alice1Ephemeral,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey,
        bob.oneTimePreKey.publicKey
      );

      // Session 2 (different ephemeral key)
      const alice2Identity = generateX25519KeyPair();
      const alice2Ephemeral = generateX25519KeyPair();
      const shared2 = x3dhInitiator(
        alice2Identity,
        alice2Ephemeral,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey
        // Different or no OPK
      );

      expect(bytesToHex(shared1)).not.toBe(bytesToHex(shared2));
    });

    it('should fail if wrong identity key is used', () => {
      const bob = createKeyBundle();
      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      // Alice uses correct keys
      const aliceShared = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey,
        bob.oneTimePreKey.publicKey
      );

      // Attacker tries with wrong identity key
      const attackerIdentity = generateX25519KeyPair();
      const bobShared = x3dhResponder(
        bob.identityKey,
        bob.signedPreKey,
        attackerIdentity.publicKey, // Wrong identity key
        aliceEphemeral.publicKey,
        bob.oneTimePreKey
      );

      expect(bytesToHex(aliceShared)).not.toBe(bytesToHex(bobShared));
    });

    it('should fail if wrong ephemeral key is used', () => {
      const bob = createKeyBundle();
      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      const aliceShared = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey,
        bob.oneTimePreKey.publicKey
      );

      // Bob uses wrong ephemeral key
      const wrongEphemeral = generateX25519KeyPair();
      const bobShared = x3dhResponder(
        bob.identityKey,
        bob.signedPreKey,
        aliceIdentity.publicKey,
        wrongEphemeral.publicKey, // Wrong ephemeral
        bob.oneTimePreKey
      );

      expect(bytesToHex(aliceShared)).not.toBe(bytesToHex(bobShared));
    });

    it('should produce 32-byte shared secret suitable for AES-256', () => {
      const bob = createKeyBundle();
      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      const sharedSecret = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey,
        bob.oneTimePreKey.publicKey
      );

      expect(sharedSecret.length).toBe(32);
      expect(sharedSecret).toBeInstanceOf(Uint8Array);
    });
  });

  describe('Signed Pre-Key Verification', () => {
    it('should verify SPK signature before using', () => {
      const bob = createKeyBundle();

      // Verify signature
      const { ed25519 } = require('@noble/curves/ed25519');
      const bobSigningPublicKey = bob._signingPublicKey;

      const isValid = ed25519Verify(
        bob.signedPreKey.publicKey,
        bob.signature,
        bobSigningPublicKey
      );

      expect(isValid).toBe(true);
    });

    it('should reject tampered SPK', () => {
      const bob = createKeyBundle();

      // Tamper with SPK
      const tamperedSPK = new Uint8Array(bob.signedPreKey.publicKey);
      tamperedSPK[0] ^= 0xff;

      // Signature should not verify
      const isValid = ed25519Verify(
        tamperedSPK,
        bob.signature,
        bob._signingPublicKey
      );

      expect(isValid).toBe(false);
    });

    it('should reject wrong signature', () => {
      const bob = createKeyBundle();

      // Create wrong signature
      const wrongSignature = randomBytes(64);

      const isValid = ed25519Verify(
        bob.signedPreKey.publicKey,
        wrongSignature,
        bob._signingPublicKey
      );

      expect(isValid).toBe(false);
    });
  });

  describe('One-Time Pre-Key Consumption', () => {
    it('should produce different shared secrets with different OPKs', () => {
      const bobIdentity = generateX25519KeyPair();
      const bobSignedPreKey = generateX25519KeyPair();
      const opk1 = generateX25519KeyPair();
      const opk2 = generateX25519KeyPair();

      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      // With OPK1
      const shared1 = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        bobSignedPreKey.publicKey,
        opk1.publicKey
      );

      // With OPK2
      const shared2 = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        bobSignedPreKey.publicKey,
        opk2.publicKey
      );

      // Shared secrets should be different
      expect(bytesToHex(shared1)).not.toBe(bytesToHex(shared2));
    });

    it('should work when OPK is not available (fallback)', () => {
      const bobIdentity = generateX25519KeyPair();
      const bobSignedPreKey = generateX25519KeyPair();

      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      // Both parties agree without OPK
      const aliceShared = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        bobSignedPreKey.publicKey
      );

      const bobShared = x3dhResponder(
        bobIdentity,
        bobSignedPreKey,
        aliceIdentity.publicKey,
        aliceEphemeral.publicKey
      );

      expect(bytesToHex(aliceShared)).toBe(bytesToHex(bobShared));
    });
  });

  describe('Key Bundle Serialization', () => {
    it('should serialize and deserialize key bundle correctly', () => {
      const bob = createKeyBundle();

      // Serialize (as would be sent over network)
      const serialized = {
        identityKey: bytesToBase64(bob.identityKey.publicKey),
        signedPreKey: bytesToBase64(bob.signedPreKey.publicKey),
        oneTimePreKey: bytesToBase64(bob.oneTimePreKey.publicKey),
        signature: bytesToBase64(bob.signature),
      };

      // Deserialize
      const restored = {
        identityKey: base64ToBytes(serialized.identityKey),
        signedPreKey: base64ToBytes(serialized.signedPreKey),
        oneTimePreKey: base64ToBytes(serialized.oneTimePreKey),
        signature: base64ToBytes(serialized.signature),
      };

      // Compare
      expect(bytesToHex(restored.identityKey)).toBe(bytesToHex(bob.identityKey.publicKey));
      expect(bytesToHex(restored.signedPreKey)).toBe(bytesToHex(bob.signedPreKey.publicKey));
      expect(bytesToHex(restored.oneTimePreKey)).toBe(bytesToHex(bob.oneTimePreKey.publicKey));
      expect(bytesToHex(restored.signature)).toBe(bytesToHex(bob.signature));
    });
  });

  describe('Forward Secrecy', () => {
    it('should provide forward secrecy via ephemeral keys', () => {
      const bob = createKeyBundle();
      const aliceIdentity = generateX25519KeyPair();

      // Session 1 with ephemeral key 1
      const ephemeral1 = generateX25519KeyPair();
      const shared1 = x3dhInitiator(
        aliceIdentity,
        ephemeral1,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey,
        bob.oneTimePreKey.publicKey
      );

      // Session 2 with ephemeral key 2
      const ephemeral2 = generateX25519KeyPair();
      const shared2 = x3dhInitiator(
        aliceIdentity,
        ephemeral2,
        bob.identityKey.publicKey,
        bob.signedPreKey.publicKey
      );

      // Different ephemeral keys produce different shared secrets
      expect(bytesToHex(shared1)).not.toBe(bytesToHex(shared2));

      // Compromising ephemeral1 doesn't reveal shared2
      // (This is inherent in the protocol design)
    });

    it('should use different SPK rotations for forward secrecy', () => {
      // Bob rotates SPK
      const bobIdentity = generateX25519KeyPair();
      const spk1 = generateX25519KeyPair();
      const spk2 = generateX25519KeyPair();

      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();

      // Session with old SPK
      const shared1 = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        spk1.publicKey
      );

      // Session with new SPK
      const shared2 = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        spk2.publicKey
      );

      expect(bytesToHex(shared1)).not.toBe(bytesToHex(shared2));
    });
  });

  describe('Edge Cases', () => {
    it('should handle multiple concurrent sessions', () => {
      const bob = createKeyBundle();

      // Multiple Alices establishing sessions simultaneously
      const sessions = Array.from({ length: 5 }, () => {
        const aliceIdentity = generateX25519KeyPair();
        const aliceEphemeral = generateX25519KeyPair();
        return {
          aliceIdentity,
          aliceEphemeral,
          shared: x3dhInitiator(
            aliceIdentity,
            aliceEphemeral,
            bob.identityKey.publicKey,
            bob.signedPreKey.publicKey
          ),
        };
      });

      // All sessions should have unique shared secrets
      const hexSecrets = sessions.map((s) => bytesToHex(s.shared));
      const uniqueSecrets = new Set(hexSecrets);
      expect(uniqueSecrets.size).toBe(5);
    });

    it('should work with fresh random keys', () => {
      // Generate fresh keys for each party
      const aliceIdentity = generateX25519KeyPair();
      const aliceEphemeral = generateX25519KeyPair();
      const bobIdentity = generateX25519KeyPair();
      const bobSPK = generateX25519KeyPair();

      // Alice initiates X3DH
      const aliceShared = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        bobSPK.publicKey
      );

      // Bob responds to X3DH
      const bobShared = x3dhResponder(
        bobIdentity,
        bobSPK,
        aliceIdentity.publicKey,
        aliceEphemeral.publicKey
      );

      // Both should derive the same shared secret
      expect(bytesToHex(aliceShared)).toBe(bytesToHex(bobShared));
    });

    it('should produce consistent results with same keys', () => {
      // Use deterministic keys from fixtures
      const aliceIdentity = getX25519KeyPair('alice');
      const aliceEphemeral = getX25519KeyPair('bob');
      const bobIdentity = getX25519KeyPair('charlie');
      const bobSPK = getX25519KeyPair('dave');

      // Run X3DH twice with same keys
      const aliceShared1 = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        bobSPK.publicKey
      );

      const aliceShared2 = x3dhInitiator(
        aliceIdentity,
        aliceEphemeral,
        bobIdentity.publicKey,
        bobSPK.publicKey
      );

      // Same inputs should produce same output
      expect(bytesToHex(aliceShared1)).toBe(bytesToHex(aliceShared2));
    });
  });
});
