/**
 * Unit tests for DoubleRatchetEngine — Path B Phase B.7.
 *
 * Pure-function tests; no SecureStore mocks needed.
 *
 *   - needsDHRatchet: false when received key is missing, false on
 *     first encounter (no stored peer key), true on key change,
 *     false when stored == received
 *   - performStep: throws when ourRatchetKeyPair is null;
 *     monotonically bumps ratchetStep; resets both counters to 0;
 *     records previousSession only when chainKeyReceive was set;
 *     does NOT mutate the input state; updates lastUpdated; rotates
 *     ourRatchetKeyPair (new keypair material)
 */

import { DoubleRatchetEngine } from '@/src/services/e2ee/DoubleRatchetEngine';
import {
  initializeSodium,
  generateX25519KeyPair,
  bytesToHex,
  randomBytes,
} from '@/src/services/SodiumCrypto';
import type { ConversationState } from '@/src/services/E2EEncryptionService.types';

beforeAll(async () => {
  await initializeSodium();
});

function makeKeyPair() {
  const kp = generateX25519KeyPair();
  return {
    publicKey: bytesToHex(kp.publicKey),
    privateKey: bytesToHex(kp.privateKey),
  };
}

function makeState(overrides: Partial<ConversationState> = {}): ConversationState {
  return {
    conversationId: 'conv-1',
    participantA: 'alice',
    participantB: 'bob',
    rootKey: bytesToHex(randomBytes(32)),
    chainKeySend: bytesToHex(randomBytes(32)),
    chainKeyReceive: bytesToHex(randomBytes(32)),
    sendCounter: 5,
    receiveCounter: 3,
    lastUpdated: 1_000,
    ratchetStep: 1,
    ourRatchetKeyPair: makeKeyPair(),
    theirRatchetKey: bytesToHex(randomBytes(32)),
    ...overrides,
  } as ConversationState;
}

describe('DoubleRatchetEngine — needsDHRatchet', () => {
  test('false when receivedRatchetKey is missing', () => {
    expect(DoubleRatchetEngine.needsDHRatchet(makeState(), undefined)).toBe(false);
    expect(DoubleRatchetEngine.needsDHRatchet(makeState(), '')).toBe(false);
  });

  test('false on first encounter (no stored peer key) — caller stores without ratcheting', () => {
    const s = makeState({ theirRatchetKey: undefined } as any);
    expect(DoubleRatchetEngine.needsDHRatchet(s, bytesToHex(randomBytes(32)))).toBe(false);
  });

  test('true when stored peer key differs from received', () => {
    const s = makeState({ theirRatchetKey: bytesToHex(randomBytes(32)) });
    const newPeer = bytesToHex(randomBytes(32));
    expect(DoubleRatchetEngine.needsDHRatchet(s, newPeer)).toBe(true);
  });

  test('false when stored equals received (same-key follow-up message)', () => {
    const peerKey = bytesToHex(randomBytes(32));
    const s = makeState({ theirRatchetKey: peerKey });
    expect(DoubleRatchetEngine.needsDHRatchet(s, peerKey)).toBe(false);
  });
});

describe('DoubleRatchetEngine — performStep', () => {
  test('throws when ourRatchetKeyPair is missing', () => {
    const s = makeState({ ourRatchetKeyPair: null } as any);
    expect(() =>
      DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32))),
    ).toThrow(/No local ratchet key pair/);
  });

  test('bumps ratchetStep by 1', () => {
    const s = makeState({ ratchetStep: 7 });
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.ratchetStep).toBe(8);
  });

  test('handles undefined ratchetStep (treats as 0 → 1)', () => {
    const s = makeState({ ratchetStep: undefined } as any);
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.ratchetStep).toBe(1);
  });

  test('resets BOTH counters to 0 on every step', () => {
    const s = makeState({ sendCounter: 99, receiveCounter: 42 });
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.sendCounter).toBe(0);
    expect(out.receiveCounter).toBe(0);
  });

  test('records previousSession when chainKeyReceive was set', () => {
    const s = makeState({
      chainKeyReceive: bytesToHex(randomBytes(32)),
      receiveCounter: 11,
    });
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.previousSession).toBeDefined();
    expect(out.previousSession!.chainKeyReceive).toBe(s.chainKeyReceive);
    expect(out.previousSession!.receiveCounter).toBe(11);
    expect(out.previousSession!.rootKey).toBe(s.rootKey);
  });

  test('does NOT record previousSession when chainKeyReceive was empty', () => {
    const s = makeState({ chainKeyReceive: '' as any });
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.previousSession).toBeUndefined();
  });

  test('does not mutate the input state (returns a new object)', () => {
    const s = makeState();
    const snapshot = JSON.parse(JSON.stringify({
      rootKey: s.rootKey,
      chainKeySend: s.chainKeySend,
      chainKeyReceive: s.chainKeyReceive,
      sendCounter: s.sendCounter,
      receiveCounter: s.receiveCounter,
      ratchetStep: s.ratchetStep,
      ourRatchetKeyPair: s.ourRatchetKeyPair,
      theirRatchetKey: s.theirRatchetKey,
    }));
    DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    // Input untouched.
    expect(s.rootKey).toBe(snapshot.rootKey);
    expect(s.chainKeySend).toBe(snapshot.chainKeySend);
    expect(s.chainKeyReceive).toBe(snapshot.chainKeyReceive);
    expect(s.sendCounter).toBe(snapshot.sendCounter);
    expect(s.receiveCounter).toBe(snapshot.receiveCounter);
    expect(s.ratchetStep).toBe(snapshot.ratchetStep);
    expect(s.ourRatchetKeyPair).toEqual(snapshot.ourRatchetKeyPair);
    expect(s.theirRatchetKey).toBe(snapshot.theirRatchetKey);
  });

  test('rotates ourRatchetKeyPair (different material on output)', () => {
    const s = makeState();
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.ourRatchetKeyPair?.publicKey).not.toBe(s.ourRatchetKeyPair?.publicKey);
    expect(out.ourRatchetKeyPair?.privateKey).not.toBe(s.ourRatchetKeyPair?.privateKey);
    expect(out.ourRatchetKeyPair?.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(out.ourRatchetKeyPair?.privateKey).toMatch(/^[0-9a-f]{64}$/);
  });

  test('updates theirRatchetKey to the received value', () => {
    const s = makeState();
    const incoming = bytesToHex(randomBytes(32));
    const out = DoubleRatchetEngine.performStep(s, incoming);
    expect(out.theirRatchetKey).toBe(incoming);
  });

  test('updates rootKey to a non-equal value (DH-derived)', () => {
    const s = makeState();
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.rootKey).not.toBe(s.rootKey);
    expect(out.rootKey).toMatch(/^[0-9a-f]{64}$/);
  });

  test('updates lastUpdated to a recent timestamp', () => {
    const s = makeState({ lastUpdated: 1_000 });
    const before = Date.now();
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    const after = Date.now();
    expect(out.lastUpdated).toBeGreaterThanOrEqual(before);
    expect(out.lastUpdated).toBeLessThanOrEqual(after);
  });

  test('two distinct receivedRatchetKey inputs produce different newSend/newReceive chain keys', () => {
    const s = makeState();
    const a = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    // Re-snapshot s because performStep updates ourRatchetKeyPair on
    // its output but not the input — using the SAME `s` again is fine.
    const b = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(a.chainKeySend).not.toBe(b.chainKeySend);
    expect(a.chainKeyReceive).not.toBe(b.chainKeyReceive);
  });
});

describe('DoubleRatchetEngine — RATCHET-02: superseded key is not a new ratchet', () => {
  test('needsDHRatchet returns FALSE for the immediately-superseded key (out-of-order previous chain)', () => {
    const k1 = bytesToHex(randomBytes(32));
    const k2 = bytesToHex(randomBytes(32));
    const k3 = bytesToHex(randomBytes(32));
    const s = makeState({ theirRatchetKey: k2, previousTheirRatchetKey: k1 } as any);
    // Pre-RATCHET-02 this returned true → a spurious ratchet on K1 thrashed the ratchet.
    expect(DoubleRatchetEngine.needsDHRatchet(s, k1)).toBe(false); // superseded → NO ratchet
    expect(DoubleRatchetEngine.needsDHRatchet(s, k2)).toBe(false); // current chain
    expect(DoubleRatchetEngine.needsDHRatchet(s, k3)).toBe(true);  // genuinely new → ratchet
  });

  test('legacy state (no previousTheirRatchetKey) still ratchets on a genuinely different key', () => {
    const s = makeState({ theirRatchetKey: bytesToHex(randomBytes(32)) });
    delete (s as any).previousTheirRatchetKey;
    expect(DoubleRatchetEngine.needsDHRatchet(s, bytesToHex(randomBytes(32)))).toBe(true);
  });

  test('performStep records the superseded key, and a later delayed message on it is suppressed', () => {
    const s = makeState({ theirRatchetKey: bytesToHex(randomBytes(32)) });
    const oldKey = s.theirRatchetKey;
    const out = DoubleRatchetEngine.performStep(s, bytesToHex(randomBytes(32)));
    expect(out.previousTheirRatchetKey).toBe(oldKey);
    expect(DoubleRatchetEngine.needsDHRatchet(out, oldKey!)).toBe(false); // no re-ratchet on the old key
  });
});
