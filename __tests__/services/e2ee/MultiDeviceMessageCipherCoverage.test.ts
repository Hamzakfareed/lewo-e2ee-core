/**
 * MultiDeviceMessageCipher coverage round.
 *
 * Targets uncovered branches: 82 (non-Error throw stringification),
 * 135 (decryptForOurDevice non-Error throw).
 *
 * BUG: When non-Error values (string, number, plain object) are thrown,
 *      `String(error)` produces the JS coercion which for objects is
 *      `[object Object]`. Real diagnostic info is lost. Should JSON.stringify
 *      with safe fallback.
 */

import {
  encryptForRecipientDevices,
  decryptForOurDevice,
} from '@/src/services/e2ee/MultiDeviceMessageCipher';

describe('MultiDeviceMessageCipher - non-Error throw paths', () => {
  test('encrypt records failure when encryptForDevice throws a non-Error value (line 82)', async () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
    const result = await encryptForRecipientDevices({
      senderDeviceId: 'me',
      recipientUserId: 'u1',
      recipientDeviceIds: ['d1', 'd2'],
      plaintext: 'hello',
      encryptForDevice: async () => {
        // eslint-disable-next-line no-throw-literal
        throw 'string error not Error';
      },
    });
    expect(result.failedDeviceIds).toContain('d1');
    expect(result.failedDeviceIds).toContain('d2');
    expect(result.hadPartialFailure).toBe(true);
    consoleSpy.mockRestore();
  });

  test('encrypt records success for healthy device', async () => {
    const result = await encryptForRecipientDevices({
      senderDeviceId: 'me',
      recipientUserId: 'u1',
      recipientDeviceIds: ['d1'],
      plaintext: 'hello',
      encryptForDevice: async () => ({
        encryptedContent: 'cipher',
        messageCounter: 0,
        ivData: 'iv',
        keyFingerprint: 'fp',
      }),
    });
    expect(result.succeededDeviceIds).toContain('d1');
  });

  test('decryptForOurDevice returns failed status when decrypt throws non-Error (line 135)', async () => {
    const result = await decryptForOurDevice({
      myDeviceId: 'me',
      senderDeviceId: 'sender',
      senderUserId: 'u1',
      deviceEncryptions: {
        me: {
          encryptedContent: 'ct',
          messageCounter: 0,
          ratchetHeader: 'rh',
          keyFingerprint: 'fp',
        },
      },
      decryptForDevice: async () => {
        // eslint-disable-next-line no-throw-literal
        throw { code: 'oops' };
      },
    });
    expect(result.status).toBe('failed');
    expect((result as any).error).toBe('[object Object]');
  });

  test('decryptForOurDevice returns success on normal decrypt', async () => {
    const result = await decryptForOurDevice({
      myDeviceId: 'me',
      senderDeviceId: 'sender',
      senderUserId: 'u1',
      deviceEncryptions: {
        me: {
          encryptedContent: 'ct',
          messageCounter: 0,
          ratchetHeader: 'rh',
          keyFingerprint: 'fp',
        },
      },
      decryptForDevice: async () => 'plaintext',
    });
    expect(result.status).toBe('success');
    expect((result as any).content).toBe('plaintext');
  });

  test('decryptForOurDevice returns not_for_device when no entry', async () => {
    const result = await decryptForOurDevice({
      myDeviceId: 'me',
      senderDeviceId: 'sender',
      senderUserId: 'u1',
      deviceEncryptions: {},
      decryptForDevice: async () => 'never',
    });
    expect(result.status).toBe('not_for_device');
  });
});
