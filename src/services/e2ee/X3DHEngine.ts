/**
 * Pure-function module for the X3DH key-agreement protocol — both
 * sides of the handshake (initiator and responder).
 *
 * EXTRACTED FROM `E2EEncryptionService.ts` (Path B Phase B.8). The
 * orchestrator's `performX3DHInitiator` / `performX3DHResponder`
 * methods are now thin wrappers that delegate here so the protocol
 * can be tested in isolation against synthetic key bundles.
 *
 * X3DH ("Extended Triple Diffie-Hellman") establishes a shared secret
 * between two parties without prior interaction beyond the responder
 * publishing a key bundle. The initiator picks an ephemeral X25519
 * keypair, performs 3 or 4 DH operations, and concatenates the
 * outputs through a KDF with domain-separation context "X3DH:v1".
 *
 *   DH1 = DH(IK_init, SPK_resp)   — long-term × signed pre-key
 *   DH2 = DH(EK_init, IK_resp)    — ephemeral × long-term
 *   DH3 = DH(EK_init, SPK_resp)   — ephemeral × signed pre-key
 *   DH4 = DH(EK_init, OPK_resp)   — ephemeral × one-time pre-key (optional)
 *
 * The responder computes the same operations with private keys
 * swapped (DH commutativity) and recovers the same shared secret.
 *
 * The 4th DH (with a one-time pre-key) provides forward secrecy for
 * the very first message: even if SPK_resp leaks later, the OPK is
 * single-use and consumed on receipt. When the responder's OPK pool
 * is exhausted the protocol degrades to 3-DH per the Signal spec.
 *
 * The responder must know whether the initiator used 3-DH or 4-DH to
 * derive the matching shared secret. The orchestrator wire format
 * carries `dhCount` and `usedOPKId` in the message header to convey
 * this. If `dhCount === 3` (initiator had no OPK), the responder
 * MUST NOT do DH4 even if its OPK store has the key.
 *
 * Side effects: like DoubleRatchetEngine, the engine zeroes its own
 * intermediate Uint8Array buffers via `secureZero` to limit residual
 * key material in memory. Hex-string outputs returned to callers are
 * immutable strings — caller is responsible for any further zeroing.
 */

import {
  generateX25519KeyPair,
  x25519ECDH,
  bytesToHex,
  hexToBytes,
  secureZero,
  deriveKey,
} from '../SodiumCrypto';
import { E2EError } from './e2eeErrors';

export interface X3DHRemoteKeyBundle {
  identityKey: string;
  signedPreKey: string;
  /**
   * The server-published keyId of `signedPreKey`. The initiator stamps this
   * onto the message (`usedSignedPreKeyId`) so the responder can look up the
   * EXACT signed-pre-key private it sealed to — even after the responder has
   * since rotated its SPK. Mirrors `oneTimePreKeyId`. Optional for back-compat
   * with bundles served before the id was surfaced (responder then falls back
   * to its current SPK).
   */
  signedPreKeyId?: number;
  oneTimePreKey?: string;
  oneTimePreKeyId?: number;
}

export interface X3DHInitiatorResult {
  sharedSecret: string;
  ephemeralKeyPublic: string;
  /** keyId of the responder's signed pre-key we sealed to (for the wire). */
  usedSPKId?: number;
  usedOPKId?: number;
  dhCount: number;
}

/**
 * Async callback that resolves a one-time pre-key private key by id,
 * or null if the responder has no matching OPK locally. Injected by
 * the orchestrator so the engine doesn't depend on the OPK manager.
 */
export type FindOpkPrivateFn = (keyId: number) => Promise<string | null>;

/**
 * Async callback that resolves a SIGNED pre-key private key by id, or null
 * if the responder has no keypair recorded under that id (e.g. the keyId was
 * never stamped, or the keypair aged out beyond the retention window).
 *
 * Unlike {@link FindOpkPrivateFn}, a null result is NOT fatal: the responder
 * falls back to its CURRENT signed-pre-key private (today's behaviour), which
 * is correct whenever the message was in fact sealed to the current keypair
 * (the overwhelmingly common case, including forced-fresh self-sync). The
 * by-id lookup's value is the ROTATION case: a message sealed to the now-
 * `previous` SPK resolves to the previous private here instead of silently
 * deriving the wrong shared secret against the current one.
 */
export type FindSpkPrivateFn = (keyId: number) => Promise<string | null>;

export class X3DHEngine {
  static readonly KDF_CONTEXT = new TextEncoder().encode('X3DH:v1');

  /**
   * Initiator: generate ephemeral key, perform 3 or 4 DHs against the
   * responder's bundle, derive the X3DH shared secret.
   *
   * Throws `E2EError` if the local identity-key or remote keys are
   * missing. Caller passes its own identity private key (the engine
   * doesn't read fields from the orchestrator).
   */
  static performInitiator(args: {
    localIdentityPrivateKeyHex: string;
    remoteKeyBundle: X3DHRemoteKeyBundle;
  }): X3DHInitiatorResult {
    const { localIdentityPrivateKeyHex, remoteKeyBundle } = args;
    if (!localIdentityPrivateKeyHex) {
      throw new E2EError('X3DH initiator: local identity key unavailable', 'INVALID_STATE');
    }
    if (!remoteKeyBundle?.identityKey) {
      throw new E2EError('X3DH initiator: remote identity key unavailable', 'INVALID_STATE');
    }
    if (!remoteKeyBundle?.signedPreKey) {
      throw new E2EError('X3DH initiator: remote signed pre-key unavailable', 'INVALID_STATE');
    }

    const ephemeralKeyPair = generateX25519KeyPair();
    const ekPrivate = ephemeralKeyPair.privateKey;
    const ekPublic = ephemeralKeyPair.publicKey;
    const ephemeralKeyPublic = bytesToHex(ekPublic);

    const ikPrivate = hexToBytes(localIdentityPrivateKeyHex);
    const spkPublic = hexToBytes(remoteKeyBundle.signedPreKey);
    const ikRemotePublic = hexToBytes(remoteKeyBundle.identityKey);

    const dhOutputs: Uint8Array[] = [];

    try {
      // DH1 = DH(IK_init, SPK_resp)
      dhOutputs.push(x25519ECDH(ikPrivate, spkPublic));

      // DH2 = DH(EK_init, IK_resp)
      dhOutputs.push(x25519ECDH(ekPrivate, ikRemotePublic));

      // DH3 = DH(EK_init, SPK_resp)
      dhOutputs.push(x25519ECDH(ekPrivate, spkPublic));

      // DH4 = DH(EK_init, OPK_resp) — optional. When the responder
      // has no OPKs left, X3DH degrades to 3-DH per the Signal spec.
      //
      // error5 ROOT CAUSE: the OPK public key and its keyId are two INDEPENDENT
      // fields on the bundle, and they can disagree — e.g.
      // `E2EEncryptionService.group.ts` :444-445 maps them from different
      // sources (`b.oneTimePreKey?.publicKey || b.oneTimePreKey` can resolve a
      // RAW STRING public key while `?.keyId` stays undefined). Gating DH4 on
      // the public key ALONE then produced `dhCount: 4` with
      // `usedOPKId: undefined` → on the wire `dhCount:4, opkId:null`.
      //
      // That frame is UNANSWERABLE: performResponder can neither skip DH4 (it
      // would derive a different shared secret) nor perform it (no keyId to look
      // the OPK private up by), so it throws KEY_MISMATCH — and every reissue
      // rebuilds the SAME impossible frame. That is the permanent group-decrypt
      // wedge seen in the field (all members stuck on "waiting for decryption").
      //
      // A 4-DH whose keyId we cannot ship is worthless: require BOTH halves, or
      // degrade honestly to 3-DH, which the responder always converges on.
      let usedOPKId: number | undefined;
      const opkId = remoteKeyBundle.oneTimePreKeyId;
      if (remoteKeyBundle.oneTimePreKey && opkId !== undefined && opkId !== null) {
        const opkPublic = hexToBytes(remoteKeyBundle.oneTimePreKey);
        dhOutputs.push(x25519ECDH(ekPrivate, opkPublic));
        usedOPKId = opkId;
        secureZero(opkPublic);
      } else if (remoteKeyBundle.oneTimePreKey && __DEV__) {
        console.warn(
          '⚠️ [X3DH] bundle carried an OPK public key with NO keyId — degrading to 3-DH. '
          + 'Claiming 4-DH here would emit an unanswerable dhCount=4/opkId=null frame.',
        );
      }

      const sharedSecret = X3DHEngine.deriveSharedSecret(dhOutputs);
      return {
        sharedSecret,
        ephemeralKeyPublic,
        // Always carried (every X3DH uses the SPK). Undefined only when the
        // bundle was served without an id (legacy) — the responder then falls
        // back to its current SPK.
        usedSPKId: remoteKeyBundle.signedPreKeyId,
        usedOPKId,
        dhCount: dhOutputs.length,
      };
    } finally {
      // SECURITY: Zero every intermediate Uint8Array on both paths.
      secureZero(ikPrivate);
      secureZero(ekPrivate);
      secureZero(spkPublic);
      secureZero(ikRemotePublic);
      for (const dh of dhOutputs) secureZero(dh);
    }
  }

  /**
   * Responder: recover the initiator's shared secret using the
   * commutative DH equivalents.
   *
   * `initiatorDhCount` (3 or 4) tells us whether to do DH4 on our
   * side. Backwards-compat: if `initiatorDhCount` is undefined and
   * `usedOPKId` is undefined, assume 3-DH (no OPK).
   *
   * If the initiator claims 4-DH but `usedOPKId` is missing or our
   * local OPK store doesn't have the key, we throw `KEY_MISMATCH`
   * rather than silently falling back to 3-DH (which would derive a
   * different shared secret and break the session permanently).
   *
   * Note: OPK consumption is DEFERRED. The caller (orchestrator)
   * consumes the OPK only after a successful first decrypt. If the
   * X3DH attempt fails (stale TOFU pin, etc.), the caller skips
   * consumption so a retry can use the same OPK.
   */
  static async performResponder(args: {
    localIdentityPrivateKeyHex: string;
    localSignedPreKeyPrivateKeyHex: string;
    senderIdentityKeyHex: string;
    ephemeralKeyHex: string;
    usedSPKId?: number;
    usedOPKId?: number;
    initiatorDhCount?: number;
    findOpkPrivate: FindOpkPrivateFn;
    /**
     * Resolve OUR signed-pre-key private by the id the initiator sealed to.
     * Optional + null-tolerant: when absent / unresolved we use
     * `localSignedPreKeyPrivateKeyHex` (the current SPK) — exactly today's
     * behaviour. See {@link FindSpkPrivateFn}.
     */
    findSpkPrivate?: FindSpkPrivateFn;
  }): Promise<string> {
    const {
      localIdentityPrivateKeyHex,
      localSignedPreKeyPrivateKeyHex,
      senderIdentityKeyHex,
      ephemeralKeyHex,
      usedSPKId,
      usedOPKId,
      initiatorDhCount,
      findOpkPrivate,
      findSpkPrivate,
    } = args;

    if (!localSignedPreKeyPrivateKeyHex) {
      throw new E2EError('X3DH responder: local signed pre-key unavailable', 'INVALID_STATE');
    }
    if (!localIdentityPrivateKeyHex) {
      throw new E2EError('X3DH responder: local identity key unavailable', 'INVALID_STATE');
    }

    // SPK-by-id: when the initiator told us WHICH of our signed pre-keys it
    // sealed to, resolve that exact private. A hit on the now-`previous` SPK is
    // the whole point — it lets a message sealed just before our SPK rotation
    // still decrypt. A miss (id absent, or keypair aged out) is non-fatal: we
    // keep the current SPK private, which is correct for every message sealed
    // to the live keypair. NEVER throw here — that would strand the message
    // with no recovery (self-sync has no resend path).
    let resolvedSpkPrivateHex = localSignedPreKeyPrivateKeyHex;
    if (usedSPKId !== undefined && findSpkPrivate) {
      try {
        const byId = await findSpkPrivate(usedSPKId);
        if (byId) resolvedSpkPrivateHex = byId;
      } catch {
        /* lookup failure → keep current SPK (best-effort) */
      }
    }

    const spkPrivate = hexToBytes(resolvedSpkPrivateHex);
    const ikPrivate = hexToBytes(localIdentityPrivateKeyHex);
    const ikInitiatorPublic = hexToBytes(senderIdentityKeyHex);
    const ekInitiatorPublic = hexToBytes(ephemeralKeyHex);

    const dhOutputs: Uint8Array[] = [];

    try {
      // DH1 = DH(SPK_resp, IK_init)  — commutativity of initiator's DH1.
      dhOutputs.push(x25519ECDH(spkPrivate, ikInitiatorPublic));
      // DH2 = DH(IK_resp, EK_init)   — commutativity of initiator's DH2.
      dhOutputs.push(x25519ECDH(ikPrivate, ekInitiatorPublic));
      // DH3 = DH(SPK_resp, EK_init)  — commutativity of initiator's DH3.
      dhOutputs.push(x25519ECDH(spkPrivate, ekInitiatorPublic));

      // DH4 = DH(OPK_resp, EK_init) — only if initiator did 4-DH.
      //
      // Phase 1 fix (bug #89): dhCount is AUTHORITATIVE. Previously we fell
      // back to `usedOPKId !== undefined` when dhCount was missing, but
      // that's unreliable — `usedOPKId` could leak from a prior send under
      // certain state-corruption paths, producing a phantom 4-DH attempt
      // and a guaranteed shared-secret mismatch. With dhCount authoritative,
      // a missing/invalid dhCount is a wire-format error — bail with
      // KEY_MISMATCH so the recovery service can refetch the bundle and
      // re-run X3DH cleanly. A correctly-formed wire envelope always carries
      // dhCount (server schema enforces this in V2067).
      if (initiatorDhCount === undefined) {
        throw new E2EError(
          'X3DH responder: dhCount missing from wire envelope — cannot determine 3-DH vs 4-DH',
          'KEY_MISMATCH',
        );
      }
      if (initiatorDhCount !== 3 && initiatorDhCount !== 4) {
        throw new E2EError(
          `X3DH responder: invalid dhCount=${initiatorDhCount} (must be 3 or 4)`,
          'KEY_MISMATCH',
        );
      }
      const initiatorUsedOPK = initiatorDhCount === 4;

      if (initiatorUsedOPK && usedOPKId === undefined) {
        // R4 fix: don't guess which OPK was used — picking the wrong
        // one yields a different shared secret and a permanent
        // KEY_MISMATCH. Surface and let the caller's recovery flow
        // (DECRYPTION_FAILED → fresh key exchange) take over.
        throw new E2EError(
          'X3DH responder: initiator claims 4-DH but usedOPKId missing from header',
          'KEY_MISMATCH',
        );
      }

      if (initiatorUsedOPK && usedOPKId !== undefined) {
        const opkPrivateHex = await findOpkPrivate(usedOPKId);
        if (!opkPrivateHex) {
          // CRITICAL: initiator did 4-DH but we can't find the
          // matching OPK locally → skipping DH4 would derive a
          // different shared secret. Surface KEY_MISMATCH so the
          // caller can recover with a fresh handshake.
          //
          // Round-22 P0-A: attach a structured discriminator so the
          // channel-distribution recovery path stops string-matching.
          // STRICTLY ADDITIVE: the message text and `.code`
          // ('KEY_MISMATCH') are byte-identical to pre-round-22 —
          // DUPLICATE_SKD_BENIGN_CODES (group SKD swallow) and every
          // 1:1 KEY_MISMATCH recovery flow keep seeing exactly what
          // they saw. Only NEW callers read `x3dhFailure`/`usedOPKId`
          // (see `isOpkNotFoundError` below).
          const opkError = new E2EError(
            `X3DH responder: OPK keyId=${usedOPKId} not found locally — cannot match initiator's 4-DH shared secret`,
            'KEY_MISMATCH',
          );
          opkError.x3dhFailure = 'OPK_NOT_FOUND';
          opkError.usedOPKId = usedOPKId;
          throw opkError;
        }
        const opkPrivate = hexToBytes(opkPrivateHex);
        dhOutputs.push(x25519ECDH(opkPrivate, ekInitiatorPublic));
        secureZero(opkPrivate);
      }

      return X3DHEngine.deriveSharedSecret(dhOutputs);
    } finally {
      // SECURITY: Zero on both paths.
      secureZero(spkPrivate);
      secureZero(ikPrivate);
      secureZero(ikInitiatorPublic);
      secureZero(ekInitiatorPublic);
      for (const dh of dhOutputs) secureZero(dh);
    }
  }

  /**
   * Concatenate DH outputs and run the X3DH KDF with the canonical
   * "X3DH:v1" domain-separation context. Returns the 32-byte shared
   * secret as a 64-hex-char string.
   */
  private static deriveSharedSecret(dhOutputs: Uint8Array[]): string {
    const totalLength = dhOutputs.reduce((sum, arr) => sum + arr.length, 0);
    const concatenated = new Uint8Array(totalLength);
    let offset = 0;
    for (const dh of dhOutputs) {
      concatenated.set(dh, offset);
      offset += dh.length;
    }
    const sharedSecretBytes = deriveKey(concatenated, null, X3DHEngine.KDF_CONTEXT, 32);
    const sharedSecret = bytesToHex(sharedSecretBytes);
    secureZero(concatenated);
    secureZero(sharedSecretBytes);
    return sharedSecret;
  }
}

/**
 * Round-22 P0-A: true when an error is the X3DH responder's
 * "OPK not found locally" failure — the signature of an initiator whose
 * long-lived session still cites a one-time pre-key this device no longer
 * holds (burned long ago, or backend rows stale vs. the local store after
 * a reinstall/re-login regen).
 *
 * Prefers the structured `x3dhFailure` discriminator attached at the
 * throw site; falls back to the exact legacy message shape for errors
 * that crossed a boundary which stripped custom properties (e.g. a
 * re-serialized copy). NEVER keyed on `.code` — that stays
 * 'KEY_MISMATCH' for every legacy consumer.
 */
export function isOpkNotFoundError(
  err: unknown,
): err is E2EError & { usedOPKId?: number } {
  if (!err || typeof err !== 'object') return false;
  if ((err as { x3dhFailure?: string }).x3dhFailure === 'OPK_NOT_FOUND') {
    return true;
  }
  const msg = (err as { message?: unknown }).message;
  return (
    typeof msg === 'string' &&
    /X3DH responder: OPK keyId=\d+ not found locally/.test(msg)
  );
}
