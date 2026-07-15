import { SealedSenderEnvelope } from '@/src/services/e2ee/SealedSenderEnvelope';
import {
  initializeSodium,
  generateX25519KeyPair,
  generateEd25519KeyPair,
  bytesToHex,
} from '@/src/services/SodiumCrypto';

beforeAll(async () => {
  await initializeSodium();
});

function makeIdentity() {
  const x25519 = generateX25519KeyPair();
  const ed25519 = generateEd25519KeyPair();
  return {
    publicKey: bytesToHex(x25519.publicKey),
    privateKey: bytesToHex(x25519.privateKey),
    signingPublicKey: bytesToHex(ed25519.publicKey),
    signingPrivateKey: bytesToHex(ed25519.privateKey),
  };
}

const innerPayload = {
  conversationId: 'conv-x',
  encryptedContent: 'cipher',
  messageCounter: 7,
  ratchetPublicKey: '0a'.repeat(32),
  ratchetStep: 3,
};

describe('SealedSenderEnvelope', () => {
  test('seal → unseal round-trips inner payload + cert', () => {
    const sender = makeIdentity();
    const recipient = makeIdentity();
    const sealed = SealedSenderEnvelope.seal(innerPayload, recipient.publicKey, {
      userId: 'alice',
      deviceId: 'desktop',
      identityKeyHex: sender.publicKey,
      signingPublicKeyHex: sender.signingPublicKey,
      signingPrivateKeyHex: sender.signingPrivateKey,
    });
    expect(sealed.sealedPayload).toMatch(/^[0-9a-f]+$/);
    expect(sealed.deliveryToken).toMatch(/^[0-9a-f]{64}$/);

    const out = SealedSenderEnvelope.unseal(sealed.sealedPayload, recipient.privateKey);
    expect(out.senderUserId).toBe('alice');
    expect(out.senderDeviceId).toBe('desktop');
    expect(out.senderIdentityKey).toBe(sender.publicKey);
    expect(out.senderSigningKey).toBe(sender.signingPublicKey);
    expect(out.encryptedMessage).toEqual(innerPayload);
  });

  test('SPK-by-id: usedSignedPreKeyId survives the sealed envelope round-trip', () => {
    const sender = makeIdentity();
    const recipient = makeIdentity();
    // X3DH-init metadata as it rides inside a sealed 1:1 first message.
    const inner = {
      conversationId: 'conv-x',
      encryptedContent: 'cipher',
      messageCounter: 0,
      ephemeralKey: 'ab'.repeat(32),
      usedSignedPreKeyId: 909090,
      usedOneTimePreKeyId: 11,
      dhCount: 4,
    };
    const sealed = SealedSenderEnvelope.seal(inner, recipient.publicKey, {
      userId: 'alice',
      deviceId: 'desktop',
      identityKeyHex: sender.publicKey,
    });
    const out = SealedSenderEnvelope.unseal(sealed.sealedPayload, recipient.privateKey);
    // Without this surviving, the responder for a sealed first message would
    // always fall back to its current SPK and a rotated-SPK message would fail.
    expect(out.encryptedMessage.usedSignedPreKeyId).toBe(909090);
    expect(out.encryptedMessage.usedOneTimePreKeyId).toBe(11);
    expect(out.encryptedMessage.dhCount).toBe(4);
  });

  test('unseal with wrong recipient key fails AEAD verification', () => {
    const sender = makeIdentity();
    const recipient = makeIdentity();
    const wrong = makeIdentity();
    const sealed = SealedSenderEnvelope.seal(innerPayload, recipient.publicKey, {
      userId: 'alice',
      deviceId: 'd',
      identityKeyHex: sender.publicKey,
    });
    expect(() =>
      SealedSenderEnvelope.unseal(sealed.sealedPayload, wrong.privateKey),
    ).toThrow(/Decryption failed/);
  });

  test('unseal with empty recipient key throws structured error', () => {
    expect(() => SealedSenderEnvelope.unseal('00'.repeat(80), '')).toThrow(
      /No identity key pair available/,
    );
  });

  test('unseal rejects truncated payload before attempting AEAD', () => {
    const recipient = makeIdentity();
    expect(() => SealedSenderEnvelope.unseal('aabb', recipient.privateKey)).toThrow(
      /Payload too short/,
    );
  });

  test('tampered ciphertext fails AEAD', () => {
    const sender = makeIdentity();
    const recipient = makeIdentity();
    const sealed = SealedSenderEnvelope.seal(innerPayload, recipient.publicKey, {
      userId: 'alice',
      deviceId: 'd',
      identityKeyHex: sender.publicKey,
    });
    const flipped =
      sealed.sealedPayload.slice(0, -2) +
      (sealed.sealedPayload.slice(-2) === 'ff' ? '00' : 'ff');
    expect(() => SealedSenderEnvelope.unseal(flipped, recipient.privateKey)).toThrow(
      /Decryption failed/,
    );
  });

  test('sealing without signing keys produces an envelope without sig', () => {
    const sender = makeIdentity();
    const recipient = makeIdentity();
    const sealed = SealedSenderEnvelope.seal(innerPayload, recipient.publicKey, {
      userId: 'alice',
      deviceId: 'd',
      identityKeyHex: sender.publicKey,
    });
    const out = SealedSenderEnvelope.unseal(sealed.sealedPayload, recipient.privateKey);
    expect(out.senderUserId).toBe('alice');
    // No signing key in cert when not provided.
    expect(out.senderSigningKey).toBeUndefined();
  });

  test('two seals of identical input produce different sealedPayloads (ephemeral freshness)', () => {
    const sender = makeIdentity();
    const recipient = makeIdentity();
    const a = SealedSenderEnvelope.seal(innerPayload, recipient.publicKey, {
      userId: 'a',
      deviceId: 'd',
      identityKeyHex: sender.publicKey,
    });
    const b = SealedSenderEnvelope.seal(innerPayload, recipient.publicKey, {
      userId: 'a',
      deviceId: 'd',
      identityKeyHex: sender.publicKey,
    });
    expect(a.sealedPayload).not.toBe(b.sealedPayload);
    expect(a.deliveryToken).not.toBe(b.deliveryToken);
  });
});
