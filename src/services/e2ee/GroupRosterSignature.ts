/**
 * C2 — admin-signed group/channel roster (membership authorization).
 *
 * Today a client fans its sender key to whatever member list the SERVER returns,
 * with no cryptographic check — so a malicious/compelled server can add a member
 * and silently receive the key. This module lets an admin Ed25519-sign the
 * authoritative roster (bound to the group and the monotonic key version), and
 * lets members verify that signature before distributing/accepting sender keys.
 *
 * TRUST ANCHOR: the admin's IDENTITY signing key (`signingPublicKey`), which is
 * already published in the key bundle and TOFU-pinned — no new key-distribution
 * channel is needed. REPLAY: the signature covers a monotonic `keyVersion`, so a
 * stale roster (e.g. re-authorizing a removed member) is rejected by comparing
 * versions at the call site.
 *
 * The signature is over a domain-separated BLAKE2b digest of a CANONICAL roster
 * (sorted, de-duplicated member ids) so signer and verifier never diverge on
 * ordering.
 */
import { ed25519Sign, ed25519Verify, hash256, bytesToHex, hexToBytes } from '../SodiumCrypto';

const DOMAIN = 'lewo-group-roster-v1';
const SEP = 0x1f;

/** Canonical, order-independent encoding of the roster the admin authorizes. */
export function canonicalMemberList(memberIds: string[]): string {
  return Array.from(new Set(memberIds.filter((m) => !!m))).sort().join(',');
}

export function buildRosterSignPayload(
  groupId: string,
  keyVersion: number,
  memberIds: string[],
  adminUserId: string,
): Uint8Array {
  const enc = new TextEncoder();
  const fields = [
    DOMAIN,
    groupId,
    String(keyVersion),
    canonicalMemberList(memberIds),
    adminUserId,
  ].map((f) => enc.encode(f));
  const total = fields.reduce((n, f) => n + f.length, 0) + (fields.length - 1);
  const buf = new Uint8Array(total);
  let off = 0;
  fields.forEach((f, i) => {
    if (i > 0) buf[off++] = SEP;
    buf.set(f, off);
    off += f.length;
  });
  return hash256(buf);
}

/** Admin signs the roster with its Ed25519 identity signing private key. */
export function signGroupRoster(
  adminSigningPrivateKeyHex: string,
  groupId: string,
  keyVersion: number,
  memberIds: string[],
  adminUserId: string,
): string {
  const payload = buildRosterSignPayload(groupId, keyVersion, memberIds, adminUserId);
  return bytesToHex(ed25519Sign(payload, hexToBytes(adminSigningPrivateKeyHex)));
}

/**
 * Verify a roster signature against the admin's identity signing key. Returns
 * false (never throws) on any malformed input.
 */
export function verifyGroupRoster(
  adminSigningPublicKeyHex: string,
  signatureHex: string,
  groupId: string,
  keyVersion: number,
  memberIds: string[],
  adminUserId: string,
): boolean {
  try {
    if (!adminSigningPublicKeyHex || !signatureHex) return false;
    const payload = buildRosterSignPayload(groupId, keyVersion, memberIds, adminUserId);
    return ed25519Verify(payload, hexToBytes(signatureHex), hexToBytes(adminSigningPublicKeyHex));
  } catch {
    return false;
  }
}
