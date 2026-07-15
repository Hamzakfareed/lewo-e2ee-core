/**
 * C2 — admin-signed roster crypto core. A member distributes/accepts a group
 * sender key only if the roster it applies to is signed by the admin's identity
 * key. These tests pin the round-trip and every rejection: an injected member,
 * a replayed (stale keyVersion), a wrong group, and a non-admin signer.
 */
(global as any).__DEV__ = false;

import {
  initializeSodium,
  generateEd25519KeyPair,
  bytesToHex,
} from '@/src/services/SodiumCrypto';
import {
  signGroupRoster,
  verifyGroupRoster,
  canonicalMemberList,
} from '@/src/services/e2ee/GroupRosterSignature';

const GROUP = 'group-1';
const ADMIN = 'admin-user';
const MEMBERS = ['admin-user', 'bob', 'carol'];
const VERSION = 3;

let adminPrivHex: string;
let adminPubHex: string;

beforeAll(async () => {
  await initializeSodium();
  const kp = generateEd25519KeyPair();
  adminPrivHex = bytesToHex(kp.privateKey);
  adminPubHex = bytesToHex(kp.publicKey);
});

describe('C2 canonicalMemberList', () => {
  it('is order-independent and de-duplicated', () => {
    expect(canonicalMemberList(['bob', 'admin-user', 'carol', 'bob'])).toBe(
      canonicalMemberList(['carol', 'bob', 'admin-user']),
    );
  });
});

describe('C2 group roster signature', () => {
  it('verifies a roster the admin signed', () => {
    const sig = signGroupRoster(adminPrivHex, GROUP, VERSION, MEMBERS, ADMIN);
    expect(verifyGroupRoster(adminPubHex, sig, GROUP, VERSION, MEMBERS, ADMIN)).toBe(true);
  });

  it('verifies regardless of member ordering (canonicalized)', () => {
    const sig = signGroupRoster(adminPrivHex, GROUP, VERSION, ['carol', 'bob', 'admin-user'], ADMIN);
    expect(verifyGroupRoster(adminPubHex, sig, GROUP, VERSION, ['admin-user', 'bob', 'carol'], ADMIN)).toBe(true);
  });

  it('rejects an INJECTED member (server added someone to the roster)', () => {
    const sig = signGroupRoster(adminPrivHex, GROUP, VERSION, MEMBERS, ADMIN);
    expect(verifyGroupRoster(adminPubHex, sig, GROUP, VERSION, [...MEMBERS, 'attacker'], ADMIN)).toBe(false);
  });

  it('rejects a REPLAYED roster at a different keyVersion', () => {
    const sig = signGroupRoster(adminPrivHex, GROUP, VERSION, MEMBERS, ADMIN);
    expect(verifyGroupRoster(adminPubHex, sig, GROUP, VERSION + 1, MEMBERS, ADMIN)).toBe(false);
  });

  it('rejects a signature bound to a different group', () => {
    const sig = signGroupRoster(adminPrivHex, GROUP, VERSION, MEMBERS, ADMIN);
    expect(verifyGroupRoster(adminPubHex, sig, 'other-group', VERSION, MEMBERS, ADMIN)).toBe(false);
  });

  it('rejects a signature from a non-admin key', () => {
    const attacker = generateEd25519KeyPair();
    const sig = signGroupRoster(bytesToHex(attacker.privateKey), GROUP, VERSION, MEMBERS, ADMIN);
    expect(verifyGroupRoster(adminPubHex, sig, GROUP, VERSION, MEMBERS, ADMIN)).toBe(false);
  });

  it('returns false (never throws) on garbage input', () => {
    expect(verifyGroupRoster('', '', GROUP, VERSION, MEMBERS, ADMIN)).toBe(false);
    expect(verifyGroupRoster(adminPubHex, 'zzz', GROUP, VERSION, MEMBERS, ADMIN)).toBe(false);
  });
});
