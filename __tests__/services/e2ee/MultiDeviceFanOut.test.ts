/**
 * MultiDeviceFanOut tests — pure data structure, no crypto.
 */

import {
  multiDeviceConversationId,
  DeviceFanOutCollector,
} from '@/src/services/e2ee/MultiDeviceFanOut';

describe('multiDeviceConversationId', () => {
  test('formats as multidev:<sender>:<recipient>', () => {
    expect(multiDeviceConversationId('dev-A', 'dev-B'))
      .toBe('multidev:dev-A:dev-B');
  });

  test('order matters — sender first, recipient second', () => {
    expect(multiDeviceConversationId('alice', 'bob'))
      .not.toBe(multiDeviceConversationId('bob', 'alice'));
  });

  test('handles hex device IDs', () => {
    expect(multiDeviceConversationId('a1b2', 'c3d4'))
      .toBe('multidev:a1b2:c3d4');
  });
});

describe('DeviceFanOutCollector', () => {
  const fakeEntry = {
    encryptedContent: 'enc',
    messageCounter: 1,
    ratchetHeader: 'iv',
    keyFingerprint: 'fp',
  };

  test('records successes and exposes the entry map', () => {
    const c = new DeviceFanOutCollector(['d1', 'd2']);
    c.recordSuccess('d1', fakeEntry);
    c.recordSuccess('d2', fakeEntry);
    expect(Object.keys(c.getEntries())).toEqual(['d1', 'd2']);
  });

  test('partial failure flag flips when recordFailure is called', () => {
    const c = new DeviceFanOutCollector(['d1', 'd2']);
    expect(c.hadPartialFailure()).toBe(false);
    c.recordFailure('d2');
    expect(c.hadPartialFailure()).toBe(true);
  });

  test('summary reports succeeded, failed, and total requested', () => {
    const c = new DeviceFanOutCollector(['d1', 'd2', 'd3']);
    c.recordSuccess('d1', fakeEntry);
    c.recordFailure('d2');
    c.recordSuccess('d3', fakeEntry);

    const s = c.summary();
    expect(s.succeededDeviceIds.sort()).toEqual(['d1', 'd3']);
    expect(s.failedDeviceIds).toEqual(['d2']);
    expect(s.totalRequested).toBe(3);
  });
});
