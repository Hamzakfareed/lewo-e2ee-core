/**
 * C1 — device trust gate (fan-out decision). Pins the fail-open rollout: warn
 * mode keeps existing devices working while flagging them; enforce mode blocks
 * anything not proven by the primary's cross-signature. The primary anchor is
 * always allowed; a real cross-signed device is allowed in both modes.
 */
(global as any).__DEV__ = false;

import {
  initializeSodium,
  generateEd25519KeyPair,
  bytesToHex,
} from '@/src/services/SodiumCrypto';
import { signDeviceCrossSignature } from '@/src/services/e2ee/DeviceCrossSignature';
import { evaluateDeviceTrust, partitionDevicesByTrust, DeviceForTrust } from '@/src/services/e2ee/DeviceTrustGate';

const USER = 'peer-user';
const IDENTITY = '11'.repeat(32);
const SIGNING = '22'.repeat(32);

let primary: DeviceForTrust;
let signedSecondary: DeviceForTrust;
let unsignedSecondary: DeviceForTrust;
let forgedSecondary: DeviceForTrust;

beforeAll(async () => {
  await initializeSodium();
  const primaryKp = generateEd25519KeyPair();
  primary = { deviceId: 'dev-primary', isPrimary: true, signingPublicKey: bytesToHex(primaryKp.publicKey) };

  const sig = signDeviceCrossSignature(bytesToHex(primaryKp.privateKey), USER, 'dev-2', IDENTITY, SIGNING);
  signedSecondary = { deviceId: 'dev-2', identityKey: IDENTITY, signingPublicKey: SIGNING, crossSignature: sig };

  unsignedSecondary = { deviceId: 'dev-3', identityKey: IDENTITY, signingPublicKey: SIGNING };

  // A ghost device: attacker keys, signature that does not verify under the real primary.
  const attackerKp = generateEd25519KeyPair();
  const forgedSig = signDeviceCrossSignature(bytesToHex(attackerKp.privateKey), USER, 'dev-ghost', IDENTITY, SIGNING);
  forgedSecondary = { deviceId: 'dev-ghost', identityKey: IDENTITY, signingPublicKey: SIGNING, crossSignature: forgedSig };
});

describe('C1 DeviceTrustGate — primary anchor', () => {
  it('always allows the primary device (both modes)', () => {
    expect(evaluateDeviceTrust(USER, primary, primary, 'warn').allow).toBe(true);
    expect(evaluateDeviceTrust(USER, primary, primary, 'enforce').allow).toBe(true);
  });
});

describe('C1 DeviceTrustGate — a validly cross-signed device', () => {
  it('is allowed and marked verified in BOTH modes', () => {
    for (const mode of ['warn', 'enforce'] as const) {
      const d = evaluateDeviceTrust(USER, signedSecondary, primary, mode);
      expect(d.allow).toBe(true);
      expect(d.verified).toBe(true);
      expect(d.warn).toBe(false);
    }
  });
});

describe('C1 DeviceTrustGate — unsigned/legacy device (fail-open rollout)', () => {
  it('warn mode ALLOWS but flags it', () => {
    const d = evaluateDeviceTrust(USER, unsignedSecondary, primary, 'warn');
    expect(d.allow).toBe(true);
    expect(d.verified).toBe(false);
    expect(d.warn).toBe(true);
    expect(d.reason).toBe('no-cross-signature');
  });
  it('enforce mode BLOCKS it', () => {
    const d = evaluateDeviceTrust(USER, unsignedSecondary, primary, 'enforce');
    expect(d.allow).toBe(false);
  });
});

describe('C1 DeviceTrustGate — ghost device with a forged signature', () => {
  it('is never "verified"; enforce mode BLOCKS it', () => {
    const warn = evaluateDeviceTrust(USER, forgedSecondary, primary, 'warn');
    expect(warn.verified).toBe(false);
    expect(warn.warn).toBe(true);
    expect(warn.reason).toBe('invalid-cross-signature');

    const enforce = evaluateDeviceTrust(USER, forgedSecondary, primary, 'enforce');
    expect(enforce.allow).toBe(false);
    expect(enforce.verified).toBe(false);
  });
});

describe('C1 DeviceTrustGate — no primary key available', () => {
  it('warn allows, enforce blocks', () => {
    expect(evaluateDeviceTrust(USER, signedSecondary, undefined, 'warn').allow).toBe(true);
    expect(evaluateDeviceTrust(USER, signedSecondary, undefined, 'enforce').allow).toBe(false);
  });
});

describe('C1 partitionDevicesByTrust — what the fan-out actually sends to', () => {
  it('enforce mode keeps primary + verified, blocks unsigned + ghost', () => {
    const roster = [primary, signedSecondary, unsignedSecondary, forgedSecondary];
    const p = partitionDevicesByTrust(USER, roster, 'enforce');
    const allowedIds = p.allowed.map((d) => d.deviceId).sort();
    expect(allowedIds).toEqual(['dev-2', 'dev-primary']);
    const blockedIds = p.blocked.map((b) => b.device.deviceId).sort();
    expect(blockedIds).toEqual(['dev-3', 'dev-ghost']);
  });

  it('warn mode sends to everyone but flags the unsigned/ghost devices', () => {
    const roster = [primary, signedSecondary, unsignedSecondary, forgedSecondary];
    const p = partitionDevicesByTrust(USER, roster, 'warn');
    expect(p.allowed).toHaveLength(4);
    expect(p.blocked).toHaveLength(0);
    expect(p.warned.map((w) => w.device.deviceId).sort()).toEqual(['dev-3', 'dev-ghost']);
  });
});

describe('C1 partitionDevicesByTrust — GRACEFUL adaptive default (SAFE)', () => {
  it('ADOPTED peer (has a signed secondary): blocks the unsigned + ghost like enforce', () => {
    // signedSecondary proves this peer adopted cross-signing → unsigned/ghost are anomalous.
    const roster = [primary, signedSecondary, unsignedSecondary, forgedSecondary];
    const p = partitionDevicesByTrust(USER, roster, 'graceful');
    expect(p.allowed.map((d) => d.deviceId).sort()).toEqual(['dev-2', 'dev-primary']);
    expect(p.blocked.map((b) => b.device.deviceId).sort()).toEqual(['dev-3', 'dev-ghost']);
  });

  it('NON-ADOPTED peer (no signed secondary): tolerates everyone (never breaks a legacy user)', () => {
    // No cross-signed secondary anywhere → the peer has not adopted → tolerate all.
    const roster = [primary, unsignedSecondary];
    const p = partitionDevicesByTrust(USER, roster, 'graceful');
    expect(p.blocked).toHaveLength(0);
    expect(p.allowed.map((d) => d.deviceId).sort()).toEqual(['dev-3', 'dev-primary']);
  });

  it('a lone injected ghost on a NON-adopted peer is tolerated (documented first-contact limit)', () => {
    // Attacker injects a ghost before the user ever cross-signs a real device:
    // indistinguishable from a legacy device, so graceful can\'t block it yet.
    const roster = [primary, forgedSecondary];
    const p = partitionDevicesByTrust(USER, roster, 'graceful');
    expect(p.blocked).toHaveLength(0);
  });
});

describe('C1 partitionDevicesByTrust — anchor is the UNIQUE primary (isPrimary-spoof defense)', () => {
  it('a GHOST marked isPrimary is NOT auto-trusted when a second primary exists', () => {
    // Server injects a ghost flagged isPrimary alongside the real primary → the
    // anchor is ambiguous → NO free pass to ANY device (incl. the real primary),
    // so the ghost is blocked under enforce.
    const ghostPrimary: DeviceForTrust = { deviceId: 'dev-ghost-primary', isPrimary: true };
    const p = partitionDevicesByTrust(USER, [primary, ghostPrimary, signedSecondary], 'enforce');
    const blockedIds = p.blocked.map((b) => b.device.deviceId);
    expect(blockedIds).toContain('dev-ghost-primary');
    // Ambiguous anchor → even the REAL primary loses its free pass (this is what
    // pins the "exactly one primary" rule; without it a `>= 1` bug would slip by).
    expect(blockedIds).toContain('dev-primary');
    expect(p.allowed.map((d) => d.deviceId)).not.toContain('dev-ghost-primary');
  });

  it('a ghost placed FIRST in the roster does NOT become the anchor (ordering-independent)', () => {
    // The dangerous case: server lists the ghost primary BEFORE the real one.
    // With a correct "exactly one primary" anchor, the ambiguity blocks it; a
    // "first primary wins" bug would hand the ghost a free pass.
    const ghostPrimary: DeviceForTrust = { deviceId: 'dev-ghost-primary', isPrimary: true };
    const p = partitionDevicesByTrust(USER, [ghostPrimary, primary, signedSecondary], 'enforce');
    expect(p.allowed.map((d) => d.deviceId)).not.toContain('dev-ghost-primary');
    expect(p.blocked.map((b) => b.device.deviceId)).toContain('dev-ghost-primary');
  });

  it('with exactly ONE primary, the anchor still gets its pass (no regression)', () => {
    const p = partitionDevicesByTrust(USER, [primary, signedSecondary], 'enforce');
    expect(p.allowed.map((d) => d.deviceId).sort()).toEqual(['dev-2', 'dev-primary']);
    expect(p.blocked).toHaveLength(0);
  });
});

describe('C1 partitionDevicesByTrust — persisted adoption ratchet (omission-downgrade defense)', () => {
  it('graceful + priorAdoption=true STILL enforces when the server OMITS the signed secondary', () => {
    // Malicious server returns only [primary, ghost] (dropped the real signed
    // secondary) to look un-adopted. The persisted ratchet forces enforce → ghost blocked.
    const roster = [primary, forgedSecondary];
    const withoutRatchet = partitionDevicesByTrust(USER, roster, 'graceful', false);
    expect(withoutRatchet.blocked).toHaveLength(0); // would slip through without the ratchet
    const withRatchet = partitionDevicesByTrust(USER, roster, 'graceful', true);
    expect(withRatchet.blocked.map((b) => b.device.deviceId)).toContain('dev-ghost');
  });

  it('reports adopted=true when a validly cross-signed secondary is present (so the caller can persist it)', () => {
    const p = partitionDevicesByTrust(USER, [primary, signedSecondary], 'graceful');
    expect(p.adopted).toBe(true);
  });

  it('reports adopted=false when no secondary is cross-signed', () => {
    const p = partitionDevicesByTrust(USER, [primary, unsignedSecondary], 'graceful');
    expect(p.adopted).toBe(false);
  });
});
