/**
 * Pure `resolveChainDirectionIsFirst` tests — no module mocking, so they are
 * hermetic and safe in the shared e2ee gate. Split out of chainDirection.test.ts
 * (2026-07-10): the device-id resolver tests there use `jest.doMock` with virtual
 * modules, which flake under the parallel gate's shared module registry. Those
 * stay in the default jest config; THIS file — which is what kills the
 * chain-direction tie-break mutations — runs in the gate.
 */
import { resolveChainDirectionIsFirst } from '../../../src/services/e2ee/chainDirection';

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
