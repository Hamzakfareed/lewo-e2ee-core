import { initializeSodium, randomBytes, bytesToHex, generateEd25519KeyPair } from '@/src/services/SodiumCrypto';
import { GroupMessageCipher } from '@/src/services/e2ee/GroupMessageCipher';
import type { SenderKeyRecord } from '@/src/services/E2EEncryptionService.types';

beforeAll(async () => {
  await initializeSodium();
});

const buildRecord = (overrides: Partial<SenderKeyRecord> = {}): SenderKeyRecord => ({
  senderKeyId: 1,
  senderKey: bytesToHex(randomBytes(32)),
  senderKeyChainKey: bytesToHex(randomBytes(32)),
  senderKeyNextId: 0,
  createdAt: Date.now(),
  ...overrides,
});

describe('GroupMessageCipher.encrypt', () => {
  test('produces XChaCha20-Poly1305 v1 envelope + advances chain key', () => {
    const record = buildRecord();
    const result = GroupMessageCipher.encrypt({
      conversationId: 'group-1',
      plaintext: 'hello group',
      senderKeyRecord: record,
      messageUuid: 'msg-uuid-1',
    });
    expect(result.encryptedMessage.encryptedContent).toContain('"v":');
    expect(result.encryptedMessage.messageCounter).toBe(0);
    expect(result.encryptedMessage.senderKeyId).toBe(1);
    expect(result.nextChainKey).not.toBe(record.senderKeyChainKey);
  });

  test('signs payload when signing key is provided', () => {
    const signingKp = generateEd25519KeyPair();
    const record = buildRecord();
    const result = GroupMessageCipher.encrypt({
      conversationId: 'group-1',
      plaintext: 'hi',
      senderKeyRecord: record,
      signingPrivateKeyHex: bytesToHex(signingKp.privateKey),
      messageUuid: 'm-1',
    });
    expect(result.encryptedMessage.signature).toBeDefined();
    expect(result.encryptedMessage.signature).toMatch(/^[0-9a-f]+$/);
  });
});

describe('GroupMessageCipher.decrypt', () => {
  test('roundtrips encrypt → decrypt with matching senderKeyId', async () => {
    const record = buildRecord();
    const enc = GroupMessageCipher.encrypt({
      conversationId: 'group-2',
      plaintext: 'roundtrip',
      senderKeyRecord: record,
      messageUuid: 'm-2',
    });
    const dec = await GroupMessageCipher.decrypt({
      conversationId: 'group-2',
      senderKeyRecord: record,
      expectedSenderKeyId: 1,
      encryptedContent: enc.encryptedMessage.encryptedContent,
      ivData: enc.encryptedMessage.ivData,
      messageCounter: 0,
      requireSignature: false,
    });
    expect(dec.plaintext).toBe('roundtrip');
    expect(dec.newCounter).toBe(1);
  });

  test('throws KEY_MISMATCH when senderKeyId differs', async () => {
    const record = buildRecord({ senderKeyId: 1 });
    const enc = GroupMessageCipher.encrypt({
      conversationId: 'g',
      plaintext: 'x',
      senderKeyRecord: record,
      messageUuid: 'm',
    });
    await expect(
      GroupMessageCipher.decrypt({
        conversationId: 'g',
        senderKeyRecord: record,
        expectedSenderKeyId: 2,
        encryptedContent: enc.encryptedMessage.encryptedContent,
        ivData: enc.encryptedMessage.ivData,
        messageCounter: 0,
        requireSignature: false,
      }),
    ).rejects.toMatchObject({ code: 'KEY_MISMATCH' });
  });

  test('throws SIGNATURE_REQUIRED when required and absent', async () => {
    const record = buildRecord();
    const enc = GroupMessageCipher.encrypt({
      conversationId: 'g',
      plaintext: 'x',
      senderKeyRecord: record,
      messageUuid: 'm',
    });
    await expect(
      GroupMessageCipher.decrypt({
        conversationId: 'g',
        senderKeyRecord: record,
        expectedSenderKeyId: 1,
        encryptedContent: enc.encryptedMessage.encryptedContent,
        ivData: enc.encryptedMessage.ivData,
        messageCounter: 0,
        requireSignature: true,
      }),
    ).rejects.toMatchObject({ code: 'SIGNATURE_REQUIRED' });
  });

  test('verifies signature when provided', async () => {
    const signingKp = generateEd25519KeyPair();
    const record = buildRecord();
    const enc = GroupMessageCipher.encrypt({
      conversationId: 'g',
      plaintext: 'signed',
      senderKeyRecord: record,
      signingPrivateKeyHex: bytesToHex(signingKp.privateKey),
      messageUuid: 'm',
    });
    const dec = await GroupMessageCipher.decrypt({
      conversationId: 'g',
      senderKeyRecord: record,
      expectedSenderKeyId: 1,
      encryptedContent: enc.encryptedMessage.encryptedContent,
      ivData: enc.encryptedMessage.ivData,
      messageCounter: 0,
      signature: enc.encryptedMessage.signature,
      senderSigningKey: bytesToHex(signingKp.publicKey),
      requireSignature: true,
    });
    expect(dec.plaintext).toBe('signed');
  });

  test('throws SIGNATURE_INVALID when signature does not verify', async () => {
    const realKp = generateEd25519KeyPair();
    const otherKp = generateEd25519KeyPair();
    const record = buildRecord();
    const enc = GroupMessageCipher.encrypt({
      conversationId: 'g',
      plaintext: 'signed',
      senderKeyRecord: record,
      signingPrivateKeyHex: bytesToHex(realKp.privateKey),
      messageUuid: 'm',
    });
    await expect(
      GroupMessageCipher.decrypt({
        conversationId: 'g',
        senderKeyRecord: record,
        expectedSenderKeyId: 1,
        encryptedContent: enc.encryptedMessage.encryptedContent,
        ivData: enc.encryptedMessage.ivData,
        messageCounter: 0,
        signature: enc.encryptedMessage.signature,
        senderSigningKey: bytesToHex(otherKp.publicKey),
        requireSignature: true,
      }),
    ).rejects.toMatchObject({ code: 'SIGNATURE_INVALID' });
  });

  test('throws OUT_OF_ORDER when messageCounter < currentCounter', async () => {
    const record = buildRecord({ senderKeyNextId: 5 });
    await expect(
      GroupMessageCipher.decrypt({
        conversationId: 'g',
        senderKeyRecord: record,
        expectedSenderKeyId: 1,
        encryptedContent: '{"v":2,"n":"00","c":"00"}',
        ivData: '00',
        messageCounter: 3,
        requireSignature: false,
      }),
    ).rejects.toMatchObject({ code: 'OUT_OF_ORDER' });
  });
});
