/**
 * C2 — roster trust gate (sender-key adoption decision). Fail-open rollout: warn
 * mode keeps groups working while flagging; enforce mode rejects a sender not in
 * a validly admin-signed roster (the ghost-member case).
 */
(global as any).__DEV__ = false;

import {
  initializeSodium,
  generateEd25519KeyPair,
  bytesToHex,
} from '@/src/services/SodiumCrypto';
import { signGroupRoster } from '@/src/services/e2ee/GroupRosterSignature';
import { evaluateSenderKeyAuthorization, AdminSignedRoster } from '@/src/services/e2ee/GroupRosterGate';

const GROUP = 'group-1';
const ADMIN = 'admin-user';
const MEMBERS = ['admin-user', 'bob', 'carol'];
const VERSION = 4;

let signedRoster: AdminSignedRoster;

beforeAll(async () => {
  await initializeSodium();
  const kp = generateEd25519KeyPair();
  const signature = signGroupRoster(bytesToHex(kp.privateKey), GROUP, VERSION, MEMBERS, ADMIN);
  signedRoster = {
    groupId: GROUP,
    keyVersion: VERSION,
    memberIds: MEMBERS,
    adminUserId: ADMIN,
    adminSigningPublicKey: bytesToHex(kp.publicKey),
    signature,
  };
});

describe('C2 evaluateSenderKeyAuthorization', () => {
  it('accepts a sender who is in a validly signed roster', () => {
    const d = evaluateSenderKeyAuthorization('bob', signedRoster, 'enforce');
    expect(d.accept).toBe(true);
    expect(d.verified).toBe(true);
    expect(d.reason).toBe('authorized');
  });

  it('enforce mode REJECTS a sender not in the signed roster (ghost member)', () => {
    const d = evaluateSenderKeyAuthorization('attacker', signedRoster, 'enforce');
    expect(d.accept).toBe(false);
    expect(d.reason).toBe('sender-not-in-roster');
  });

  it('enforce mode REJECTS an invalid roster signature', () => {
    const tampered = { ...signedRoster, memberIds: [...MEMBERS, 'attacker'] };
    const d = evaluateSenderKeyAuthorization('attacker', tampered, 'enforce');
    expect(d.accept).toBe(false);
    expect(d.reason).toBe('invalid-roster-signature');
  });

  it('enforce mode REJECTS when there is no signed roster', () => {
    const unsigned: AdminSignedRoster = { groupId: GROUP, keyVersion: VERSION, memberIds: MEMBERS, adminUserId: ADMIN };
    const d = evaluateSenderKeyAuthorization('bob', unsigned, 'enforce');
    expect(d.accept).toBe(false);
    expect(d.reason).toBe('no-signed-roster');
  });

  it('warn mode ACCEPTS but flags an unsigned/ghost case (rollout)', () => {
    const unsigned: AdminSignedRoster = { groupId: GROUP, keyVersion: VERSION, memberIds: MEMBERS, adminUserId: ADMIN };
    const noSig = evaluateSenderKeyAuthorization('bob', unsigned, 'warn');
    expect(noSig.accept).toBe(true);
    expect(noSig.warn).toBe(true);

    const ghost = evaluateSenderKeyAuthorization('attacker', signedRoster, 'warn');
    expect(ghost.accept).toBe(true);
    // The ROSTER verified (valid admin signature) — the sender just isn't in it,
    // which is exactly the positive ghost evidence graceful/enforce reject on.
    expect(ghost.verified).toBe(true);
    expect(ghost.warn).toBe(true);
    expect(ghost.reason).toBe('sender-not-in-roster');
  });
});
