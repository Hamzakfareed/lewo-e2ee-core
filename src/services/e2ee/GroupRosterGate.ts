/**
 * C2 — group/channel roster trust gate.
 *
 * When a member receives a sender-key distribution, it must decide whether the
 * sender is an AUTHORIZED member — not someone the server injected. The admin
 * signs the roster (GroupRosterSignature); this gate verifies that signature and
 * checks the sender is in the signed roster before the sender key is adopted.
 *
 * ROLLOUT — three modes, tuned so the ghost defense is ON by default WITHOUT
 * breaking groups that have no signed roster yet (the "reject only after
 * coverage" rule). The distinction is POSITIVE EVIDENCE vs mere absence:
 *   • 'warn'     — tolerate everything, flag only. Pure measurement / escape hatch.
 *   • 'graceful' — DEFAULT. Reject only POSITIVE ghost/tamper evidence: a validly
 *                  admin-signed roster that EXCLUDES the sender, an invalid roster
 *                  signature, or a roster signed by a different admin than the one
 *                  first pinned. A group with NO roster yet is still tolerated, so
 *                  legacy/passive-admin groups keep working — but the instant a
 *                  real admin roster exists, an injected member is rejected.
 *   • 'enforce'  — strictest: ALSO rejects a missing roster (every sender key must
 *                  come with an admin-authorized roster). Opt-in, post full rollout.
 */
import { verifyGroupRoster } from './GroupRosterSignature';

export type RosterTrustMode = 'warn' | 'graceful' | 'enforce';

export interface AdminSignedRoster {
  groupId: string;
  keyVersion: number;
  memberIds: string[];
  adminUserId: string;
  /** The admin's identity Ed25519 signing key (trust anchor). */
  adminSigningPublicKey?: string;
  /** The admin's signature over the roster (GroupRosterSignature). */
  signature?: string;
}

export interface RosterTrustDecision {
  accept: boolean;
  verified: boolean;
  warn: boolean;
  reason:
    | 'authorized'
    | 'no-signed-roster'
    | 'invalid-roster-signature'
    | 'sender-not-in-roster';
}

/**
 * Decide whether a sender-key distribution from `fromMemberId` may be adopted.
 */
export function evaluateSenderKeyAuthorization(
  fromMemberId: string,
  roster: AdminSignedRoster,
  mode: RosterTrustMode,
): RosterTrustDecision {
  // ABSENCE (no verifiable roster) is tolerated in every mode except strict
  // enforce — a group whose admin hasn't signed yet must keep working.
  const tolerateAbsence = mode !== 'enforce';
  // POSITIVE EVIDENCE (a valid roster that excludes the sender, or a tampered
  // signature) is tolerated ONLY in pure-warn measurement mode; graceful and
  // enforce both reject it.
  const tolerateEvidence = mode === 'warn';

  if (!roster.signature || !roster.adminSigningPublicKey) {
    return { accept: tolerateAbsence, verified: false, warn: true, reason: 'no-signed-roster' };
  }

  const sigOk = verifyGroupRoster(
    roster.adminSigningPublicKey,
    roster.signature,
    roster.groupId,
    roster.keyVersion,
    roster.memberIds,
    roster.adminUserId,
  );
  if (!sigOk) {
    return { accept: tolerateEvidence, verified: false, warn: true, reason: 'invalid-roster-signature' };
  }

  if (!new Set(roster.memberIds).has(fromMemberId)) {
    // Signature is VALID but the sender is not in the admin-authorized roster —
    // a server-injected member. This is the core ghost-member case, and the
    // roster itself verified, so `verified` is true.
    return { accept: tolerateEvidence, verified: true, warn: true, reason: 'sender-not-in-roster' };
  }

  return { accept: true, verified: true, warn: false, reason: 'authorized' };
}
