jest.mock('@/src/services/e2ee/MultiDeviceFanOut', () => ({
  multiDeviceConversationId: jest.fn((a: string, b: string) => `${a}::${b}`),
  DeviceFanOutCollector: jest.fn().mockImplementation((deviceIds: string[]) => {
    const entries: Record<string, any> = {};
    const failed: string[] = [];
    const succeeded: string[] = [];
    return {
      recordSuccess: (id: string, payload: any) => { entries[id] = payload; succeeded.push(id); },
      recordFailure: (id: string) => { failed.push(id); },
      getEntries: () => entries,
      hadPartialFailure: () => failed.length > 0,
      summary: () => ({ totalRequested: deviceIds.length, failedDeviceIds: failed, succeededDeviceIds: succeeded }),
    };
  }),
}));

import {
  encryptForRecipientDevices,
  decryptForOurDevice,
} from '@/src/services/e2ee/MultiDeviceMessageCipher';

describe('encryptForRecipientDevices', () => {
  test('encrypts plaintext separately for each device', async () => {
    const encryptForDevice = jest.fn(async () => ({
      encryptedContent: 'cipher',
      messageCounter: 1,
      ivData: 'iv',
      keyFingerprint: 'fp',
    }));

    const result = await encryptForRecipientDevices({
      senderDeviceId: 'me',
      recipientUserId: 'them',
      recipientDeviceIds: ['d1', 'd2'],
      plaintext: 'hi',
      encryptForDevice,
    });

    expect(encryptForDevice).toHaveBeenCalledTimes(2);
    expect(Object.keys(result.deviceEncryptions)).toEqual(['d1', 'd2']);
    expect(result.failedDeviceIds).toEqual([]);
    expect(result.hadPartialFailure).toBe(false);
  });

  test('records failures for devices whose encrypt throws', async () => {
    const errSpy = jest.spyOn(console, 'warn').mockImplementation();
    try {
      const encryptForDevice = jest.fn(async (_c, _p, _s, _r) => {
        throw new Error('boom');
      });

      const result = await encryptForRecipientDevices({
        senderDeviceId: 'me',
        recipientUserId: 'them',
        recipientDeviceIds: ['d1'],
        plaintext: 'hi',
        encryptForDevice,
      });

      expect(result.failedDeviceIds).toEqual(['d1']);
      expect(result.hadPartialFailure).toBe(true);
    } finally {
      errSpy.mockRestore();
    }
  });
});

describe('decryptForOurDevice', () => {
  test('returns not_for_device when no entry exists', async () => {
    const result = await decryptForOurDevice({
      myDeviceId: 'me',
      senderDeviceId: 'them',
      senderUserId: 'them-user',
      deviceEncryptions: {},
      decryptForDevice: jest.fn(),
    });
    expect(result.status).toBe('not_for_device');
  });

  test('returns success with content on successful decrypt', async () => {
    const result = await decryptForOurDevice({
      myDeviceId: 'me',
      senderDeviceId: 'them',
      senderUserId: 'them-user',
      deviceEncryptions: {
        me: { encryptedContent: 'c', messageCounter: 1, ratchetHeader: 'h' },
      },
      decryptForDevice: jest.fn(async () => 'hello'),
    });
    expect(result).toEqual({ status: 'success', content: 'hello' });
  });

  test('returns failed with error message when decrypt throws', async () => {
    const result = await decryptForOurDevice({
      myDeviceId: 'me',
      senderDeviceId: 'them',
      senderUserId: 'them-user',
      deviceEncryptions: {
        me: { encryptedContent: 'c', messageCounter: 1, ratchetHeader: 'h' },
      },
      decryptForDevice: jest.fn(async () => { throw new Error('mac mismatch'); }),
    });
    expect(result).toEqual({ status: 'failed', error: 'mac mismatch' });
  });
});
