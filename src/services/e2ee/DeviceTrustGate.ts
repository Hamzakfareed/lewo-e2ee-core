/**
 * C1 — device trust gate for the send fan-out.
 *
 * Decides whether a message copy may be encrypted to a given recipient device,
 * based on the primary device's cross-signature over it (see DeviceCrossSignature).
 *
 * ROLLOUT — three modes, tuned so the ghost-device defense is ON by default
 * WITHOUT breaking multi-device users who haven't cross-signed yet. The problem:
 * a server-injected ghost has NO cross-signature — indistinguishable from a
 * legit-but-unsigned legacy device — so a blanket "block unsigned" would break
 * existing users. The escape is ADAPTIVE: a peer who has cross-signed ANY of
 * their secondaries has demonstrably adopted cross-signing, so an UNSIGNED device
 * among their signed ones is anomalous (a ghost) and is blocked; a peer with NO
 * signed secondary hasn't adopted, so nothing is blocked.
 *   • 'warn'     — tolerate everything, flag only. Escape hatch / measurement.
 *   • 'graceful' — DEFAULT. Per-peer adaptive: enforce for peers that have ≥1
 *                  validly cross-signed secondary; tolerate (warn) for peers with
 *                  none. Safe on by default — never blocks a non-adopter.
 *   • 'enforce'  — strict: block every non-primary device lacking a valid
 *                  cross-signature, regardless of adoption. Opt-in, post-rollout.
 *
 * The primary device is the trust anchor (pinned via TOFU), so it is always
 * allowed and is never itself cross-signed.
 */
import { verifyDeviceCrossSignature } from './DeviceCrossSignature';

export type DeviceTrustMode = 'warn' | 'graceful' | 'enforce';

export interface DeviceForTrust {
  deviceId: string;
  isPrimary?: boolean;
  identityKey?: string;
  signingPublicKey?: string;
  crossSignature?: string;
}

export interface DeviceTrustDecision {
  /** May the fan-out encrypt a copy to this device? */
  allow: boolean;
  /** Did a cross-signature actually verify (vs allowed only by fail-open)? */
  verified: boolean;
  /** Should the caller surface a warning / telemetry for this device? */
  warn: boolean;
  reason:
    | 'primary-anchor'
    | 'verified'
    | 'no-cross-signature'
    | 'invalid-cross-signature'
    | 'no-primary-key';
}

export function evaluateDeviceTrust(
  peerUserId: string,
  device: DeviceForTrust,
  primary: DeviceForTrust | undefined,
  mode: DeviceTrustMode,
): DeviceTrustDecision {
  // The primary device is the TOFU anchor; it is not cross-signed. Only the
  // device that IS the resolved anchor (`primary`) gets the free pass — NOT any
  // device the server happens to flag `isPrimary`. Otherwise a server could mark
  // an injected ghost `isPrimary:true` (or add a second primary) and skip the
  // gate entirely. When the anchor is ambiguous (`primary` undefined — 0 or >1
  // primaries in the roster), NO device gets the pass; every non-anchor device
  // must prove a cross-signature.
  if (primary && device.deviceId && device.deviceId === primary.deviceId) {
    return { allow: true, verified: true, warn: false, reason: 'primary-anchor' };
  }

  // 'graceful' needs full-roster context (does this peer have ANY signed
  // secondary?), which this per-device function doesn't have — the caller
  // (partitionDevicesByTrust) resolves graceful → warn/enforce first. Reached
  // directly with 'graceful', treat it as lenient (warn).
  const allowOnMiss = mode !== 'enforce';

  if (!primary?.signingPublicKey) {
    // No primary signing key to verify against (roster incomplete / pre-rollout).
    return { allow: allowOnMiss, verified: false, warn: true, reason: 'no-primary-key' };
  }
  if (!device.crossSignature || !device.identityKey || !device.signingPublicKey) {
    // Legacy / not-yet-signed device.
    return { allow: allowOnMiss, verified: false, warn: true, reason: 'no-cross-signature' };
  }

  const ok = verifyDeviceCrossSignature(
    primary.signingPublicKey,
    device.crossSignature,
    peerUserId,
    device.deviceId,
    device.identityKey,
    device.signingPublicKey,
  );
  if (ok) {
    return { allow: true, verified: true, warn: false, reason: 'verified' };
  }
  // A present-but-invalid signature is a strong ghost/tamper signal. During the
  // warn window we still allow-with-warning (a client bug must not break
  // delivery); in enforce mode it is blocked.
  return { allow: allowOnMiss, verified: false, warn: true, reason: 'invalid-cross-signature' };
}

export interface TrustPartition<T extends DeviceForTrust> {
  /** Devices the fan-out may encrypt to. */
  allowed: T[];
  /** Devices blocked (enforce mode only): likely ghost/injected devices. */
  blocked: Array<{ device: T; reason: DeviceTrustDecision['reason'] }>;
  /** Devices allowed but flagged (warn mode / rollout): surface telemetry. */
  warned: Array<{ device: T; reason: DeviceTrustDecision['reason'] }>;
  /** Was a validly cross-signed secondary observed THIS call? (persist it.) */
  adopted: boolean;
}

/**
 * Split a peer's device roster into allowed/blocked/warned by cross-signature
 * trust. The primary is taken from the roster (isPrimary) as the verification
 * anchor. The fan-out sends only to `allowed`.
 *
 * `priorAdoption` is the PERSISTED fact that this peer was PREVIOUSLY seen with a
 * valid cross-signed secondary. It ratchets graceful enforcement: once a peer has
 * adopted cross-signing, a malicious server can no longer downgrade them to warn
 * by OMITTING the signed secondaries from the roster it returns.
 */
export function partitionDevicesByTrust<T extends DeviceForTrust>(
  peerUserId: string,
  devices: T[],
  mode: DeviceTrustMode,
  priorAdoption = false,
): TrustPartition<T> {
  // The anchor is the UNIQUE primary. If the server returns 0 or >1 primaries
  // (e.g. it injected a second `isPrimary:true` ghost to bypass the gate), the
  // anchor is ambiguous → undefined → NO device gets a free primary pass and
  // every non-verified device is blocked under enforcement.
  const primaries = devices.filter((d) => d.isPrimary);
  const primary = primaries.length === 1 ? primaries[0] : undefined;

  // Adopted = this peer has (now OR before) a validly cross-signed secondary.
  const adoptedNow = devices.some(
    (d) => !d.isPrimary && evaluateDeviceTrust(peerUserId, d, primary, 'enforce').verified,
  );
  const adopted = adoptedNow || priorAdoption;

  // Resolve the ADAPTIVE graceful default: enforce for an adopted peer (unsigned
  // devices among their signed ones are anomalous → ghost), tolerate (warn) for a
  // peer who has never adopted (so we never break a non-adopter). The persisted
  // ratchet means an omitting server can't drop an adopted peer back to warn.
  const effective: 'warn' | 'enforce' = mode === 'graceful' ? (adopted ? 'enforce' : 'warn') : mode;

  const out: TrustPartition<T> = { allowed: [], blocked: [], warned: [], adopted: adoptedNow };
  for (const device of devices) {
    const decision = evaluateDeviceTrust(peerUserId, device, primary, effective);
    if (decision.allow) {
      out.allowed.push(device);
      if (decision.warn) out.warned.push({ device, reason: decision.reason });
    } else {
      out.blocked.push({ device, reason: decision.reason });
    }
  }
  return out;
}
