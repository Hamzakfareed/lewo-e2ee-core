/**
 * C1 — device cross-signature sign/verify (the ghost-device crypto core).
 * A copy is encrypted to a non-primary device only if the primary's Ed25519
 * cross-signature over that device's identity verifies. These tests pin the
 * round-trip and every rejection path, cross-checked so a forged device fails.
 */
(global as any).__DEV__ = false;

import {
  initializeSodium,
  generateEd25519KeyPair,
  bytesToHex,
} from '@/src/services/SodiumCrypto';
import {
  signDeviceCrossSignature,
  verifyDeviceCrossSignature,
} from '@/src/services/e2ee/DeviceCrossSignature';

let primaryPrivHex: string;
let primaryPubHex: string;

const USER = 'user-A';
const DEVICE = 'device-secondary-1';
const IDENTITY = '11'.repeat(32);
const SIGNING = '22'.repeat(32);

beforeAll(async () => {
  await initializeSodium();
  const kp = generateEd25519KeyPair();
  primaryPrivHex = bytesToHex(kp.privateKey);
  primaryPubHex = bytesToHex(kp.publicKey);
});

describe('C1 device cross-signature', () => {
  it('a signature from the primary verifies for the exact device', () => {
    const sig = signDeviceCrossSignature(primaryPrivHex, USER, DEVICE, IDENTITY, SIGNING);
    expect(verifyDeviceCrossSignature(primaryPubHex, sig, USER, DEVICE, IDENTITY, SIGNING)).toBe(true);
  });

  it('rejects a signature replayed onto a DIFFERENT deviceId (ghost device)', () => {
    const sig = signDeviceCrossSignature(primaryPrivHex, USER, DEVICE, IDENTITY, SIGNING);
    expect(verifyDeviceCrossSignature(primaryPubHex, sig, USER, 'ghost-device', IDENTITY, SIGNING)).toBe(false);
  });

  it('rejects when the identity key is swapped (server substituted keys)', () => {
    const sig = signDeviceCrossSignature(primaryPrivHex, USER, DEVICE, IDENTITY, SIGNING);
    expect(verifyDeviceCrossSignature(primaryPubHex, sig, USER, DEVICE, '33'.repeat(32), SIGNING)).toBe(false);
  });

  it('rejects a signature under a different userId', () => {
    const sig = signDeviceCrossSignature(primaryPrivHex, USER, DEVICE, IDENTITY, SIGNING);
    expect(verifyDeviceCrossSignature(primaryPubHex, sig, 'user-B', DEVICE, IDENTITY, SIGNING)).toBe(false);
  });

  it('rejects a signature verified against a DIFFERENT (attacker) primary key', () => {
    const attacker = generateEd25519KeyPair();
    const sig = signDeviceCrossSignature(primaryPrivHex, USER, DEVICE, IDENTITY, SIGNING);
    expect(
      verifyDeviceCrossSignature(bytesToHex(attacker.publicKey), sig, USER, DEVICE, IDENTITY, SIGNING),
    ).toBe(false);
  });

  it('rejects a tampered signature', () => {
    const sig = signDeviceCrossSignature(primaryPrivHex, USER, DEVICE, IDENTITY, SIGNING);
    const tampered = (sig[0] === 'a' ? 'b' : 'a') + sig.slice(1);
    expect(verifyDeviceCrossSignature(primaryPubHex, tampered, USER, DEVICE, IDENTITY, SIGNING)).toBe(false);
  });

  it('returns false (never throws) on empty/garbage input', () => {
    expect(verifyDeviceCrossSignature('', '', USER, DEVICE, IDENTITY, SIGNING)).toBe(false);
    expect(verifyDeviceCrossSignature(primaryPubHex, 'zzzz', USER, DEVICE, IDENTITY, SIGNING)).toBe(false);
  });
});
