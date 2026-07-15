/**
 * MUTATION-KILL suite — DecryptReceiveChainCallbacks.ts:63
 *
 *   if ((state.x3dhEphemeralKey || state.x3dhUsedOPKId) &&
 *       state.receiveCounter > 1) { ... clear X3DH liveness fields ... }
 *
 * Target operator: ` > ` -> ` >= ` on `receiveCounter > 1`.
 *
 * `receiveCounter` is read AFTER the in-order increment. The FIRST received
 * message advances receiveCounter 0 -> 1. The X3DH liveness fields
 * (x3dhEphemeralKey / x3dhUsedOPKId) must SURVIVE that first message
 * (`1 > 1` is false) — the responder needs them to complete X3DH if the very
 * first inbound frame has to be retried/resent. Only from the SECOND message
 * on (`2 > 1`) are they cleared.
 *
 * Under the `>=` mutant, `1 >= 1` is true, so the fields are wiped after the
 * first message — dropping X3DH liveness one message too early.
 *
 * The existing DecryptReceiveChainCallbacks.test.ts is NOT in the gate's
 * testMatch, so this boundary survived the sweep. This suite lives in the
 * OFFLINE gate lane.
 */
import { makeAdvanceReceiveAndPersist } from '@/src/services/e2ee/DecryptReceiveChainCallbacks';

describe('DecryptReceiveChainCallbacks:63 liveness clear — `>` mutant (> -> >=)', () => {
  test('first in-order message (receiveCounter 0 -> 1) KEEPS X3DH liveness fields', async () => {
    const state: any = {
      chainKeyReceive: 'ck0',
      receiveCounter: 0, // pre-increment; becomes 1 after advance
      lastUpdated: 0,
      x3dhEphemeralKey: 'eph',
      x3dhUsedOPKId: 7,
    };
    const advance = makeAdvanceReceiveAndPersist({
      state,
      isFutureMessage: false,
      chainKeyToUse: 'unused',
      messageCounter: 0,
      conversationId: 'conv-1',
      setState: jest.fn(),
      saveStates: jest.fn().mockResolvedValue(undefined),
      deriveNextChainKey: (k) => `next(${k})`,
    });

    await advance();

    expect(state.receiveCounter).toBe(1);
    // Correct (`> 1` => 1>1 false): fields PRESERVED.
    // Mutant (`>= 1` => 1>=1 true): fields wiped -> these assertions red.
    expect(state.x3dhEphemeralKey).toBe('eph');
    expect(state.x3dhUsedOPKId).toBe(7);
  });

  test('second in-order message (receiveCounter 1 -> 2) CLEARS X3DH liveness fields', async () => {
    // Guards the other side of the boundary: 2 > 1 is true under both `>` and
    // `>=`, so clearing here is correct and must keep working.
    const state: any = {
      chainKeyReceive: 'ck1',
      receiveCounter: 1, // becomes 2 after advance
      lastUpdated: 0,
      x3dhEphemeralKey: 'eph',
      x3dhUsedOPKId: 7,
    };
    const advance = makeAdvanceReceiveAndPersist({
      state,
      isFutureMessage: false,
      chainKeyToUse: 'unused',
      messageCounter: 1,
      conversationId: 'conv-1',
      setState: jest.fn(),
      saveStates: jest.fn().mockResolvedValue(undefined),
      deriveNextChainKey: (k) => `next(${k})`,
    });

    await advance();

    expect(state.receiveCounter).toBe(2);
    expect(state.x3dhEphemeralKey).toBeUndefined();
    expect(state.x3dhUsedOPKId).toBeUndefined();
  });
});
