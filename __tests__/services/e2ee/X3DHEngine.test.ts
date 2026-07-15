/**
 * Unit tests for X3DHEngine — Path B Phase B.8.
 *
 * Pure-function tests; no SecureStore mocks needed.
 *
 *   - performInitiator: throws on missing local IK, missing remote
 *     IK, missing remote SPK; produces 3-DH (no OPK) and 4-DH (with
 *     OPK) shared secrets; ephemeralKeyPublic is well-formed
 *   - performResponder: matches initiator's shared secret in both
 *     3-DH and 4-DH cases; throws KEY_MISMATCH when initiator claims
 *     4-DH but usedOPKId is missing; throws KEY_MISMATCH when local
 *     OPK lookup fails; correctly skips DH4 when initiatorDhCount=3
 *   - protocol invariant: initiator + responder derive the SAME hex
 *     shared secret given matching keys
 */

import { X3DHEngine } from '@/src/services/e2ee/X3DHEngine';
import {
  initializeSodium,
  generateX25519KeyPair,
  bytesToHex,
} from '@/src/services/SodiumCrypto';

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

interface Party {
  identity: { publicKey: string; privateKey: string };
  signedPreKey: { publicKey: string; privateKey: string };
}

function makeParty(): Party {
  return {
    identity: makeKeyPair(),
    signedPreKey: makeKeyPair(),
  };
}

describe('X3DHEngine — performInitiator', () => {
  test('throws when local identity key is missing', () => {
    const responder = makeParty();
    expect(() =>
      X3DHEngine.performInitiator({
        localIdentityPrivateKeyHex: '',
        remoteKeyBundle: {
          identityKey: responder.identity.publicKey,
          signedPreKey: responder.signedPreKey.publicKey,
        },
      }),
    ).toThrow(/local identity key unavailable/);
  });

  test('throws when remote identity key is missing', () => {
    const initiator = makeParty();
    const responder = makeParty();
    expect(() =>
      X3DHEngine.performInitiator({
        localIdentityPrivateKeyHex: initiator.identity.privateKey,
        remoteKeyBundle: {
          identityKey: '',
          signedPreKey: responder.signedPreKey.publicKey,
        },
      }),
    ).toThrow(/remote identity key unavailable/);
  });

  test('throws when remote signed pre-key is missing', () => {
    const initiator = makeParty();
    const responder = makeParty();
    expect(() =>
      X3DHEngine.performInitiator({
        localIdentityPrivateKeyHex: initiator.identity.privateKey,
        remoteKeyBundle: {
          identityKey: responder.identity.publicKey,
          signedPreKey: '',
        },
      }),
    ).toThrow(/remote signed pre-key unavailable/);
  });

  test('3-DH (no OPK) returns hex shared secret + ephemeral key, dhCount=3', () => {
    const initiator = makeParty();
    const responder = makeParty();
    const result = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
      },
    });
    expect(result.sharedSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(result.ephemeralKeyPublic).toMatch(/^[0-9a-f]{64}$/);
    expect(result.usedOPKId).toBeUndefined();
    expect(result.dhCount).toBe(3);
  });

  test('4-DH (with OPK) sets usedOPKId + dhCount=4', () => {
    const initiator = makeParty();
    const responder = makeParty();
    const opk = makeKeyPair();
    const result = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        oneTimePreKey: opk.publicKey,
        oneTimePreKeyId: 42,
      },
    });
    expect(result.usedOPKId).toBe(42);
    expect(result.dhCount).toBe(4);
  });
});

describe('X3DHEngine — performResponder', () => {
  test('matches initiator shared secret in 3-DH (no OPK)', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
      },
    });
    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      initiatorDhCount: 3,
      findOpkPrivate: async () => null,
    });
    expect(responderSecret).toBe(initResult.sharedSecret);
  });

  test('matches initiator shared secret in 4-DH (with OPK)', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const opk = makeKeyPair();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        oneTimePreKey: opk.publicKey,
        oneTimePreKeyId: 7,
      },
    });
    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      usedOPKId: 7,
      initiatorDhCount: 4,
      findOpkPrivate: async (keyId) => {
        expect(keyId).toBe(7);
        return opk.privateKey;
      },
    });
    expect(responderSecret).toBe(initResult.sharedSecret);
  });

  test('throws KEY_MISMATCH when initiator claims 4-DH but usedOPKId is missing', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    await expect(
      X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: responder.identity.privateKey,
        localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: makeKeyPair().publicKey,
        usedOPKId: undefined,
        initiatorDhCount: 4,
        findOpkPrivate: async () => null,
      }),
    ).rejects.toThrow(/usedOPKId missing/);
  });

  test('throws KEY_MISMATCH when local OPK lookup fails', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const opk = makeKeyPair();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        oneTimePreKey: opk.publicKey,
        oneTimePreKeyId: 99,
      },
    });
    await expect(
      X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: responder.identity.privateKey,
        localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: initResult.ephemeralKeyPublic,
        usedOPKId: 99,
        initiatorDhCount: 4,
        findOpkPrivate: async () => null, // local store has no key 99
      }),
    ).rejects.toThrow(/OPK keyId=99 not found/);
  });

  test('does NOT do DH4 when initiatorDhCount=3 even if usedOPKId is set', async () => {
    // If we (incorrectly) did DH4 here, the secrets would diverge.
    const initiator = makeParty();
    const responder = makeParty();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        // 3-DH: no OPK in bundle
      },
    });
    expect(initResult.dhCount).toBe(3);

    const findCalled = jest.fn();
    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      // Even though usedOPKId is "stale" from a header, dhCount=3
      // tells us to skip DH4 to match the initiator's 3-DH secret.
      initiatorDhCount: 3,
      findOpkPrivate: findCalled as any,
    });
    expect(responderSecret).toBe(initResult.sharedSecret);
    expect(findCalled).not.toHaveBeenCalled();
  });

  test('REGRESSION (Phase 1 task #89): throws KEY_MISMATCH when initiatorDhCount is missing', async () => {
    // Pre-fix the responder fell back to `usedOPKId !== undefined` when
    // dhCount was absent, but usedOPKId could leak from prior state and
    // mislead the responder into a phantom 4-DH attempt → permanent
    // shared-secret mismatch. With dhCount authoritative, a missing
    // dhCount is a wire-format error that surfaces immediately so the
    // recovery service can refetch the bundle and re-handshake.
    const initiator = makeParty();
    const responder = makeParty();
    await expect(
      X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: responder.identity.privateKey,
        localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: makeKeyPair().publicKey,
        // initiatorDhCount intentionally undefined
        usedOPKId: 7, // would have triggered phantom 4-DH under old code
        findOpkPrivate: async () => null,
      }),
    ).rejects.toMatchObject({ code: 'KEY_MISMATCH' });
  });

  test('REGRESSION (Phase 1 task #89): rejects out-of-range dhCount values', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    await expect(
      X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: responder.identity.privateKey,
        localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: makeKeyPair().publicKey,
        initiatorDhCount: 5 as any, // only 3 and 4 are valid
        findOpkPrivate: async () => null,
      }),
    ).rejects.toMatchObject({ code: 'KEY_MISMATCH' });
  });

  test('throws when local SPK private key is missing', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    await expect(
      X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: responder.identity.privateKey,
        localSignedPreKeyPrivateKeyHex: '',
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: makeKeyPair().publicKey,
        initiatorDhCount: 3,
        findOpkPrivate: async () => null,
      }),
    ).rejects.toThrow(/signed pre-key unavailable/);
  });

  test('throws when local identity private key is missing', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    await expect(
      X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: '',
        localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: makeKeyPair().publicKey,
        initiatorDhCount: 3,
        findOpkPrivate: async () => null,
      }),
    ).rejects.toThrow(/local identity key unavailable/);
  });
});

describe('X3DHEngine — protocol invariant', () => {
  test('two independent runs produce different shared secrets (ephemeral key freshness)', () => {
    const initiator = makeParty();
    const responder = makeParty();
    const a = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
      },
    });
    const b = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
      },
    });
    expect(a.sharedSecret).not.toBe(b.sharedSecret);
    expect(a.ephemeralKeyPublic).not.toBe(b.ephemeralKeyPublic);
  });

  test('shared secret is deterministic for fixed inputs (no hidden randomness in KDF)', async () => {
    // We can't fix the ephemeral key, but with the SAME initiator
    // result, the responder must derive the same secret repeatedly.
    const initiator = makeParty();
    const responder = makeParty();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
      },
    });
    const a = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      initiatorDhCount: 3,
      findOpkPrivate: async () => null,
    });
    const b = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      initiatorDhCount: 3,
      findOpkPrivate: async () => null,
    });
    expect(a).toBe(b);
  });
});

describe('X3DHEngine — SPK-by-id (signed pre-key lookup)', () => {
  test('initiator carries signedPreKeyId as usedSPKId on the result', () => {
    const initiator = makeParty();
    const responder = makeParty();
    const result = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        signedPreKeyId: 4242,
      },
    });
    expect(result.usedSPKId).toBe(4242);
  });

  test('usedSPKId is undefined when bundle omits signedPreKeyId (legacy)', () => {
    const initiator = makeParty();
    const responder = makeParty();
    const result = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
      },
    });
    expect(result.usedSPKId).toBeUndefined();
  });

  test('responder resolves the SPK private by id (rotation case: uses PREVIOUS keypair)', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    // The keypair the initiator sealed to (id=111). The responder has SINCE
    // rotated, so its `current` SPK is a different keypair, but it still retains
    // the old one keyed by id 111.
    const sealedToSpk = responder.signedPreKey;
    const rotatedCurrentSpk = makeKeyPair();

    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: sealedToSpk.publicKey,
        signedPreKeyId: 111,
      },
    });

    const findSpkPrivate = jest.fn(async (keyId: number) =>
      keyId === 111 ? sealedToSpk.privateKey : null,
    );

    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      // current = the ROTATED keypair (would derive the WRONG secret)…
      localSignedPreKeyPrivateKeyHex: rotatedCurrentSpk.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      usedSPKId: 111,
      initiatorDhCount: 3,
      findOpkPrivate: async () => null,
      // …but by-id lookup recovers the keypair the message was actually sealed to.
      findSpkPrivate,
    });

    expect(findSpkPrivate).toHaveBeenCalledWith(111);
    expect(responderSecret).toBe(initResult.sharedSecret);
  });

  test('responder falls back to CURRENT SPK when by-id lookup misses (never fails closed)', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        signedPreKeyId: 222,
      },
    });
    // Lookup returns null (id not retained) → must fall back to the current SPK,
    // which here IS the keypair sealed to, so decryption still succeeds.
    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      usedSPKId: 222,
      initiatorDhCount: 3,
      findOpkPrivate: async () => null,
      findSpkPrivate: async () => null,
    });
    expect(responderSecret).toBe(initResult.sharedSecret);
  });

  test('responder ignores findSpkPrivate when usedSPKId is undefined (legacy initiator)', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
      },
    });
    const findSpkPrivate = jest.fn(async () => 'deadbeef');
    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      initiatorDhCount: 3,
      findOpkPrivate: async () => null,
      findSpkPrivate,
    });
    expect(findSpkPrivate).not.toHaveBeenCalled();
    expect(responderSecret).toBe(initResult.sharedSecret);
  });

  test('a thrown findSpkPrivate is swallowed and falls back to current SPK', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        signedPreKeyId: 333,
      },
    });
    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      usedSPKId: 333,
      initiatorDhCount: 3,
      findOpkPrivate: async () => null,
      findSpkPrivate: async () => {
        throw new Error('storage unavailable');
      },
    });
    expect(responderSecret).toBe(initResult.sharedSecret);
  });
});

// Round-22 P0-A: the OPK-not-found throw carries a STRUCTURED, additive
// discriminator. The legacy surfaces (message text + code 'KEY_MISMATCH')
// must stay byte-identical — DUPLICATE_SKD_BENIGN_CODES and every 1:1
// KEY_MISMATCH recovery flow string/code-match them.
describe('X3DHEngine — round-22 OPK_NOT_FOUND structured discriminator', () => {
  async function captureOpkNotFound(): Promise<any> {
    const initiator = makeParty();
    const responder = makeParty();
    const opk = makeKeyPair();
    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        oneTimePreKey: opk.publicKey,
        oneTimePreKeyId: 114,
      },
    });
    try {
      await X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: responder.identity.privateKey,
        localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: initResult.ephemeralKeyPublic,
        usedOPKId: 114,
        initiatorDhCount: 4,
        findOpkPrivate: async () => null, // burned long ago — the capture's state
      });
    } catch (err) {
      return err;
    }
    throw new Error('expected performResponder to throw');
  }

  test('attaches x3dhFailure=OPK_NOT_FOUND + usedOPKId while keeping message AND code byte-identical', async () => {
    const err = await captureOpkNotFound();
    // Legacy surfaces — unchanged.
    expect(err.message).toBe(
      "X3DH responder: OPK keyId=114 not found locally — cannot match initiator's 4-DH shared secret",
    );
    expect(err.code).toBe('KEY_MISMATCH');
    // New structured discriminator — additive.
    expect(err.x3dhFailure).toBe('OPK_NOT_FOUND');
    expect(err.usedOPKId).toBe(114);
  });

  test('isOpkNotFoundError matches via the structured field', async () => {
    const { isOpkNotFoundError } = require('@/src/services/e2ee/X3DHEngine');
    expect(isOpkNotFoundError(await captureOpkNotFound())).toBe(true);
  });

  test('isOpkNotFoundError falls back to the exact legacy message shape (property-stripped copies)', () => {
    const { isOpkNotFoundError } = require('@/src/services/e2ee/X3DHEngine');
    expect(
      isOpkNotFoundError(
        new Error(
          "X3DH responder: OPK keyId=42 not found locally — cannot match initiator's 4-DH shared secret",
        ),
      ),
    ).toBe(true);
  });

  test('isOpkNotFoundError rejects other KEY_MISMATCH errors and non-errors', () => {
    const { isOpkNotFoundError } = require('@/src/services/e2ee/X3DHEngine');
    expect(isOpkNotFoundError(new Error('authentication tag invalid'))).toBe(false);
    expect(
      isOpkNotFoundError(
        new Error('X3DH responder: dhCount missing from wire envelope — cannot determine 3-DH vs 4-DH'),
      ),
    ).toBe(false);
    expect(isOpkNotFoundError(null)).toBe(false);
    expect(isOpkNotFoundError(undefined)).toBe(false);
    expect(isOpkNotFoundError('OPK keyId=1 not found locally')).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// error5 ROOT CAUSE — dhCount / usedOPKId DIVERGENCE
// ─────────────────────────────────────────────────────────────────────────
describe('X3DHEngine — error5: dhCount must never claim 4-DH without an OPK id', () => {
  // THE FIELD BUG (group offline→reconnect, ALL members stuck on "waiting for
  // decryption"). Every SKD frame in the error5 capture is `hasEphemeral: true,
  // opkId: null` — yet the responder kept throwing KEY_MISMATCH and no reissue
  // ever converged.
  //
  // The initiator derives its two OPK-related wire fields from INDEPENDENT
  // sources:
  //     dhCount   = 4  ⟸  remoteKeyBundle.oneTimePreKey   is truthy
  //     usedOPKId      =  remoteKeyBundle.oneTimePreKeyId  (a SEPARATE field)
  // A bundle carrying an OPK PUBLIC KEY but no keyId therefore produces
  // `dhCount: 4, usedOPKId: undefined`. On the wire that is exactly
  // `dhCount:4, opkId:null` — and performResponder rejects it outright
  // ("initiator claims 4-DH but usedOPKId missing from header"). It is
  // UNRECOVERABLE: every reissue rebuilds the same impossible frame, which is
  // precisely the self-reinforcing storm the group code's own comment describes.
  //
  // A 4-DH whose keyId cannot be shipped is USELESS — the responder can never
  // locate the matching OPK private. Degrading to 3-DH always converges.
  const bundleWithOpkPublicButNoId = (responder: Party, opkPublic: string) => ({
    identityKey: responder.identity.publicKey,
    signedPreKey: responder.signedPreKey.publicKey,
    oneTimePreKey: opkPublic,
    // oneTimePreKeyId: MISSING — the real shape produced by
    // E2EEncryptionService.group.ts:444-445, whose `|| b.oneTimePreKey` fallback
    // can set the public key from a raw string while the id stays undefined.
  });

  test('REGRESSION: an OPK public key with NO keyId must NOT produce a 4-DH claim (it is unanswerable)', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const opk = makeKeyPair();

    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: bundleWithOpkPublicButNoId(responder, opk.publicKey),
    });

    // The invariant: dhCount and usedOPKId must AGREE. Claiming 4-DH while
    // shipping opkId:null is the exact frame that stranded the field groups.
    expect(initResult.usedOPKId).toBeUndefined();
    expect(initResult.dhCount).toBe(3); // pre-fix this was 4 → permanent KEY_MISMATCH

    // And because it degraded honestly, the responder CONVERGES on the same secret.
    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      initiatorDhCount: initResult.dhCount,
      usedOPKId: initResult.usedOPKId,
      findOpkPrivate: async () => null, // responder has no OPK private to offer
    });
    expect(responderSecret).toBe(initResult.sharedSecret);
  });

  test('the frame that CANNOT be answered: dhCount=4 + opkId=null is rejected by the responder (why the divergence is fatal)', async () => {
    // Pins WHY the above matters: if the initiator ever emits this pair, the
    // responder has no legal move — it cannot skip DH4 (wrong secret) and cannot
    // perform it (no id to look up). Every reissue repeats it forever.
    const initiator = makeParty();
    const responder = makeParty();
    await expect(
      X3DHEngine.performResponder({
        localIdentityPrivateKeyHex: responder.identity.privateKey,
        localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
        senderIdentityKeyHex: initiator.identity.publicKey,
        ephemeralKeyHex: makeKeyPair().publicKey,
        initiatorDhCount: 4,
        usedOPKId: undefined,
        findOpkPrivate: async () => null,
      }),
    ).rejects.toMatchObject({ code: 'KEY_MISMATCH' });
  });

  test('a COMPLETE OPK (public key AND keyId) still performs a real 4-DH — no regression', async () => {
    const initiator = makeParty();
    const responder = makeParty();
    const opk = makeKeyPair();

    const initResult = X3DHEngine.performInitiator({
      localIdentityPrivateKeyHex: initiator.identity.privateKey,
      remoteKeyBundle: {
        identityKey: responder.identity.publicKey,
        signedPreKey: responder.signedPreKey.publicKey,
        oneTimePreKey: opk.publicKey,
        oneTimePreKeyId: 42,
      },
    });
    expect(initResult.dhCount).toBe(4);
    expect(initResult.usedOPKId).toBe(42);

    const responderSecret = await X3DHEngine.performResponder({
      localIdentityPrivateKeyHex: responder.identity.privateKey,
      localSignedPreKeyPrivateKeyHex: responder.signedPreKey.privateKey,
      senderIdentityKeyHex: initiator.identity.publicKey,
      ephemeralKeyHex: initResult.ephemeralKeyPublic,
      initiatorDhCount: 4,
      usedOPKId: 42,
      findOpkPrivate: async (id) => (id === 42 ? opk.privateKey : null),
    });
    expect(responderSecret).toBe(initResult.sharedSecret);
  });
});
