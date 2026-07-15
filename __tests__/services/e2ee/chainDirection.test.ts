import {
  resolveChainDirectionIsFirst,
  resolveOwnDeviceIdSync,
} from '../../../src/services/e2ee/chainDirection';

// Helper mirroring how the runtime maps the flag to chain keys:
// isFirstParticipant === true  → SEND=A, RECEIVE=B
// isFirstParticipant === false → SEND=B, RECEIVE=A
const send = (isFirst: boolean) => (isFirst ? 'A' : 'B');
const receive = (isFirst: boolean) => (isFirst ? 'B' : 'A');

describe('resolveChainDirectionIsFirst', () => {
  describe('genuine peer (different userIds) — legacy userId tiebreak, unchanged', () => {
    it('the two ends compute OPPOSITE flags (working duplex)', () => {
      // Initiator = userA toward userB; responder = userB receiving from userA.
      const initiator = resolveChainDirectionIsFirst({
        myUserId: 'userA',
        peerUserId: 'userB',
        myDeviceId: null,
        otherDeviceId: undefined,
        roleIsInitiator: true,
      });
      const responder = resolveChainDirectionIsFirst({
        myUserId: 'userB',
        peerUserId: 'userA',
        myDeviceId: null,
        otherDeviceId: undefined,
        roleIsInitiator: false,
      });
      expect(initiator).not.toBe(responder);
      // duplex: initiator.send === responder.receive and vice versa
      expect(send(initiator)).toBe(receive(responder));
      expect(receive(initiator)).toBe(send(responder));
    });

    it('result is independent of device ids (peer path ignores them)', () => {
      const a = resolveChainDirectionIsFirst({
        myUserId: 'userA',
        peerUserId: 'userB',
        myDeviceId: 'dev-zzz',
        otherDeviceId: 'dev-aaa',
        roleIsInitiator: true,
      });
      const b = resolveChainDirectionIsFirst({
        myUserId: 'userA',
        peerUserId: 'userB',
        myDeviceId: null,
        otherDeviceId: undefined,
        roleIsInitiator: true,
      });
      expect(a).toBe(b);
      // lexicographic: 'userA' < 'userB' ⇒ userA is first
      expect(a).toBe(true);
    });
  });

  describe('self-sync (same userId) — deviceId tiebreak', () => {
    it('the two devices compute OPPOSITE flags (the bug this fixes)', () => {
      const web = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: 'web-4abd',
        otherDeviceId: 'phone-aae3',
        roleIsInitiator: true, // web sent first
      });
      const phone = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: 'phone-aae3',
        otherDeviceId: 'web-4abd',
        roleIsInitiator: false, // phone is responder
      });
      expect(web).not.toBe(phone);
      expect(send(web)).toBe(receive(phone));
      expect(receive(web)).toBe(send(phone));
    });

    it('is symmetric regardless of which device initiated', () => {
      // phone initiates, web responds — still opposite.
      const phone = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: 'phone-aae3',
        otherDeviceId: 'web-4abd',
        roleIsInitiator: true,
      });
      const web = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: 'web-4abd',
        otherDeviceId: 'phone-aae3',
        roleIsInitiator: false,
      });
      expect(phone).not.toBe(web);
    });

    it('tiebreak is by deviceId, not role (the lexicographically-smaller device is first on BOTH perspectives)', () => {
      // 'phone-aae3' < 'web-4abd' lexicographically.
      const webView = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: 'web-4abd',
        otherDeviceId: 'phone-aae3',
        roleIsInitiator: true,
      });
      const phoneView = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: 'phone-aae3',
        otherDeviceId: 'web-4abd',
        roleIsInitiator: false,
      });
      expect(webView).toBe(false); // web is NOT the smaller id
      expect(phoneView).toBe(true); // phone IS the smaller id
    });

    it('falls back to role when own device id is unresolved (still opposite if both fall back)', () => {
      const spy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const initiator = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: null, // unresolved
        otherDeviceId: 'phone-aae3',
        roleIsInitiator: true,
      });
      const responder = resolveChainDirectionIsFirst({
        myUserId: 'user1',
        peerUserId: 'user1',
        myDeviceId: null, // unresolved
        otherDeviceId: 'web-4abd',
        roleIsInitiator: false,
      });
      expect(initiator).toBe(true);
      expect(responder).toBe(false);
      expect(initiator).not.toBe(responder);
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('falls back to role when the other device id is missing/primary', () => {
      const spy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      expect(
        resolveChainDirectionIsFirst({
          myUserId: 'user1',
          peerUserId: 'user1',
          myDeviceId: 'web-4abd',
          otherDeviceId: 'primary',
          roleIsInitiator: true,
        }),
      ).toBe(true);
      spy.mockRestore();
    });
  });
});

describe('resolveOwnDeviceIdSync', () => {
  afterEach(() => jest.resetModules());

  it('returns the memoised id when it is a real non-primary id', () => {
    jest.doMock(
      '../../../src/services/e2ee/MultiDeviceManager',
      () => ({ multiDeviceManager: { getOwnDeviceIdSync: () => 'web-4abd' } }),
      { virtual: true },
    );
    const { resolveOwnDeviceIdSync: fn } = require('../../../src/services/e2ee/chainDirection');
    expect(fn()).toBe('web-4abd');
  });

  it('returns null for primary / empty / unresolved', () => {
    jest.doMock(
      '../../../src/services/e2ee/MultiDeviceManager',
      () => ({ multiDeviceManager: { getOwnDeviceIdSync: () => 'primary' } }),
      { virtual: true },
    );
    const { resolveOwnDeviceIdSync: fn } = require('../../../src/services/e2ee/chainDirection');
    expect(fn()).toBeNull();
  });
});

describe('resolveOwnDeviceId (async — the RC1 race fix)', () => {
  afterEach(() => jest.resetModules());

  it('AWAITS and resolves the real device id EVEN WHEN the sync memo is still null', async () => {
    // This is the bug: the sync accessor returns null during the cold-start
    // window, so the self-sync direction tiebreak silently fell back to role.
    // The async path forces the AsyncStorage read to complete first.
    jest.doMock(
      '../../../src/services/e2ee/MultiDeviceManager',
      () => ({
        multiDeviceManager: {
          getOwnDeviceIdSync: () => null, // memo not yet populated
          getOwnDeviceId: async () => 'web-4abd', // async resolve succeeds
        },
      }),
      { virtual: true },
    );
    const { resolveOwnDeviceId: fn, resolveOwnDeviceIdSync: syncFn } =
      require('../../../src/services/e2ee/chainDirection');
    expect(syncFn()).toBeNull(); // sync would have degraded to role
    await expect(fn()).resolves.toBe('web-4abd'); // async gets the real id
  });

  it('returns null when the async resolve yields primary (defensive default)', async () => {
    jest.doMock(
      '../../../src/services/e2ee/MultiDeviceManager',
      () => ({ multiDeviceManager: { getOwnDeviceId: async () => 'primary' } }),
      { virtual: true },
    );
    const { resolveOwnDeviceId: fn } = require('../../../src/services/e2ee/chainDirection');
    await expect(fn()).resolves.toBeNull();
  });

  it('returns null (never throws) when resolution rejects', async () => {
    jest.doMock(
      '../../../src/services/e2ee/MultiDeviceManager',
      () => ({
        multiDeviceManager: {
          getOwnDeviceId: async () => {
            throw new Error('storage down');
          },
        },
      }),
      { virtual: true },
    );
    const { resolveOwnDeviceId: fn } = require('../../../src/services/e2ee/chainDirection');
    await expect(fn()).resolves.toBeNull();
  });

  it('with the async id resolved, the two self-sync perspectives compute OPPOSITE, correct chains', async () => {
    // End-to-end of the fix: even though the SYNC memo is null on both ends,
    // awaiting the device id makes the deterministic deviceId tiebreak run, so
    // web and phone land on opposite chains (working duplex) — not the
    // degenerate role fallback that produced "authentication tag invalid".
    jest.doMock(
      '../../../src/services/e2ee/MultiDeviceManager',
      () => ({
        multiDeviceManager: { getOwnDeviceIdSync: () => null, getOwnDeviceId: async () => 'web-4abd' },
      }),
      { virtual: true },
    );
    const { resolveOwnDeviceId, resolveChainDirectionIsFirst: tie } =
      require('../../../src/services/e2ee/chainDirection');
    const webDevice = await resolveOwnDeviceId();
    const web = tie({
      myUserId: 'user1',
      peerUserId: 'user1',
      myDeviceId: webDevice,
      otherDeviceId: 'phone-aae3',
      roleIsInitiator: true,
    });
    const phone = tie({
      myUserId: 'user1',
      peerUserId: 'user1',
      myDeviceId: 'phone-aae3', // phone resolved its own id symmetrically
      otherDeviceId: 'web-4abd',
      roleIsInitiator: false,
    });
    expect(web).not.toBe(phone);
    expect(send(web)).toBe(receive(phone));
    expect(receive(web)).toBe(send(phone));
  });
});
