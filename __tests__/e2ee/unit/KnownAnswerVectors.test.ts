/**
 * KNOWN-ANSWER (golden-vector) crypto tests.
 *
 * Round-trip tests (send==receive) CANNOT catch a SYMMETRIC crypto-logic bug: if
 * a key-derivation change breaks both the sender and receiver identically, the
 * message still round-trips (both compute the same wrong key). Proven: a no-op
 * `deriveNextChainKey` (chain never advances — a serious forward-secrecy bug)
 * passed every round-trip test, in-process AND over the real backend.
 *
 * These tests pin the EXACT output bytes of the core key derivations for fixed
 * inputs. Any change to a KDF — symmetric or not — fails here. Regenerate the
 * expected values ONLY when the protocol intentionally changes (and bump the
 * wire/protocol version when you do).
 */
import {
  initializeSodium, deriveKey, deriveRatchetKeys, deriveMultipleKeys, deriveMessageKeys,
  hash256, deriveKeyMemoryHard,
  encryptXChaCha20Poly1305WithNonce, decryptXChaCha20Poly1305, hexToBytes, bytesToHex,
} from '@/src/services/SodiumCrypto';
import { deriveNextChainKey, deriveMessageKey } from '@/src/services/e2ee/E2EEKeyDerivation';
import { computeKeyFingerprint, computeContentHash } from '@/src/services/e2ee/E2EEFingerprint';
import { ratchetGroupChainKey, computeGroupKeyFingerprint } from '@/src/services/e2ee/GroupSenderKeyDerivation';
import { computeMAC } from '@/src/services/e2ee/IntegrityMACWrapper';
import { computeDeviceFingerprint } from '@/src/services/e2ee/MultiDeviceFingerprint';
import { SafetyNumber } from '@/src/services/e2ee/SafetyNumber';

const CK = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const KEY_HEX = '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f';
const NONCE_HEX = '303132333435363738393a3b3c3d3e3f4041424344454647';
const PT = 'known-answer plaintext';
const IKM_HEX = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf';

describe('known-answer vectors — catch symmetric KDF bugs round-trip tests miss', () => {
  beforeAll(async () => {
    await initializeSodium();
  });

  test('deriveNextChainKey is byte-exact (golden vector)', () => {
    const c1 = deriveNextChainKey(CK);
    const c2 = deriveNextChainKey(c1);
    expect(c1).toBe('55b96808d05c208f883e10f962446734246238fe5b405249549e3b86390edbac');
    expect(c2).toBe('8211024978ce1f72952f621cbd3e0358281de92d836107e1f075a2b6cc2304e3');
  });

  test('forward secrecy: the chain key actually advances (no-op ratchet fails here)', () => {
    const c1 = deriveNextChainKey(CK);
    const c2 = deriveNextChainKey(c1);
    expect(c1).not.toBe(CK);
    expect(c2).not.toBe(c1);
    expect(new Set([CK, c1, c2]).size).toBe(3);
  });

  test('deriveMessageKey is byte-exact + counter-bound (golden vector)', () => {
    const m0 = deriveMessageKey(CK, 0);
    const m5 = deriveMessageKey(CK, 5);
    expect(m0).toBe('0d950cbf1e3b2bf9cb97c65e6d8844159819e0be23b5391f67df3968cddcb624');
    expect(m5).toBe('035a805494cc04ca23d3a8078f3f7313ee64a7e095dc5d898cb643e92479da3a');
    // Counter 258 = 0x0102 — a big-endian vs little-endian counter-encoding
    // regression (a wire-format detail no round-trip test can catch) fails here.
    expect(deriveMessageKey(CK, 258)).toBe('e1f262aea52072b4ad7bd7ffb9084abcf7f9d5e5ed62428ab198a4997d2943ce');
    // Distinct counters MUST give distinct keys (a counter-blind KDF fails here).
    expect(m0).not.toBe(m5);
    expect(m0).not.toBe(CK);
  });

  test('ratchetGroupChainKey (GROUP + CHANNEL sender-key ratchet) is byte-exact (golden vector)', () => {
    // This is the exact symmetric ratchet behind the rounds 28/34/35 channel forks.
    const r = ratchetGroupChainKey(CK);
    expect(r.messageKey).toBe('2c0db6bb98b0ee65a4a375bbc8799bf325a896245df9ddfbe1d054e26677110e');
    expect(r.newChainKey).toBe('d1fb551e39df370001bd3c9c21d58c12c78d33c1ec5e3200c9a8fc7c2b95b702');
    // Forward secrecy: the chain advances and the message key differs from it.
    expect(r.newChainKey).not.toBe(CK);
    expect(r.messageKey).not.toBe(r.newChainKey);
  });

  test('deriveRatchetKeys (Double Ratchet DH-step root/chain) is byte-exact (golden vector)', () => {
    const k = deriveRatchetKeys(hexToBytes('22'.repeat(32)), hexToBytes('33'.repeat(32)));
    // Reversing the dhOutput||rootKey concat order, or swapping root vs chain, fails here.
    expect(bytesToHex(k.newRootKey)).toBe('a9add5baf53baa7f4c7ae4a8b8ba9ea05153d4b1cd243fb1e627bd0fb8d81a79');
    expect(bytesToHex(k.chainKey)).toBe('ffc99104dfa2121137ce3c331d9d41c811fa3a37e5264f1852a487a8eab95ccf');
    expect(bytesToHex(k.newRootKey)).not.toBe(bytesToHex(k.chainKey));
  });

  test('deriveMultipleKeys (WhisperRatchet context) is byte-exact (golden vector)', () => {
    const m = deriveMultipleKeys(hexToBytes('44'.repeat(32)), 'WhisperRatchet', 2, 32);
    expect(bytesToHex(m[0])).toBe('4b9670cfee9f8da986aabd69a65d2419465a2242a0b9b570ce607286ad4a22a9');
    expect(bytesToHex(m[1])).toBe('125100573bb935e5ce3a86788e867f3bd78428413d20d4ccf82ebf1e91f63efc');
    expect(bytesToHex(m[0])).not.toBe(bytesToHex(m[1]));
  });

  test('deriveKey (HKDF) is byte-exact (golden vector)', () => {
    const INFO = new TextEncoder().encode('e2ee-golden-info');
    expect(bytesToHex(deriveKey(hexToBytes(IKM_HEX), null, INFO, 32)))
      .toBe('0bcb9f57b233fb30dbd1f779fb4bdd89437b46d1a185950d76bc464bb024d6a9');
  });

  test('XChaCha20-Poly1305 AEAD is byte-exact for a fixed key/nonce (golden vector)', () => {
    const KEY = hexToBytes(KEY_HEX);
    const NONCE = hexToBytes(NONCE_HEX);
    const ct = bytesToHex(encryptXChaCha20Poly1305WithNonce(new TextEncoder().encode(PT), KEY, NONCE));
    expect(ct).toBe('9f420472d0d92ef68b55165d97e63cfcff95e475b1a628e2a2eb44386cf70f6e7c04c306d081');
    // And it must decrypt back (proves the pinned bytes are a real ciphertext, not garbage).
    const pt = new TextDecoder().decode(decryptXChaCha20Poly1305(hexToBytes(ct), NONCE, KEY));
    expect(pt).toBe(PT);
  });

  test('computeKeyFingerprint is byte-exact (golden vector)', () => {
    expect(computeKeyFingerprint(CK)).toBe('7f129e850fdf24cf');
  });

  const PUB = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';

  test('deriveMessageKeys (BLAKE2b message + next-chain) is byte-exact (golden vector)', () => {
    const r = deriveMessageKeys(hexToBytes(CK));
    expect(bytesToHex(r.messageKey)).toBe('3594bdfe4888da953c0b19cd3c7fe70b018c4d05f148a9111f753b0efb3c6bdf');
    // The next chain key MUST equal deriveNextChainKey(CK) — cross-derivation consistency.
    expect(bytesToHex(r.nextChainKey)).toBe(deriveNextChainKey(CK));
    expect(bytesToHex(r.messageKey)).not.toBe(bytesToHex(r.nextChainKey));
  });

  test('hash256 (BLAKE2b-256) is byte-exact (golden vector)', () => {
    expect(bytesToHex(hash256(new TextEncoder().encode('lewo-golden-hash'))))
      .toBe('c1bd581f9a2fb93533f505fe3e5b56a28712ec69520a7905c6d3315a2c97acf6');
  });

  test('computeContentHash is byte-exact (golden vector)', () => {
    expect(computeContentHash('lewo-golden-content')).toBe('b2f19c673c32c189');
  });

  test('computeGroupKeyFingerprint is byte-exact (golden vector)', () => {
    expect(computeGroupKeyFingerprint(PUB)).toBe('719A-34EE-8A93-FB72');
  });

  test('IntegrityMAC.computeMAC is byte-exact (golden vector)', () => {
    expect(computeMAC('lewo-golden-mac-data', hexToBytes('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f')))
      .toBe('95a5e6fc06c995462b70baafbc9a232041e3d9c390f584b3431057b426e5a25d');
  });

  test('computeDeviceFingerprint is byte-exact (golden vector)', () => {
    expect(computeDeviceFingerprint(PUB)).toBe('719A 34EE 8A93 FB72');
  });

  test('SafetyNumber.compute (user-facing verification number) is byte-exact (golden vector)', () => {
    expect(SafetyNumber.compute({ ourUserId: 'user-a', ourIdentityKeyHex: CK, theirUserId: 'user-b', theirIdentityKeyHex: PUB }))
      .toBe('842212826744133656457891641482142509705246485691963195307089');
    // Symmetric: both parties compute the SAME number regardless of arg order.
    expect(SafetyNumber.compute({ ourUserId: 'user-b', ourIdentityKeyHex: PUB, theirUserId: 'user-a', theirIdentityKeyHex: CK }))
      .toBe('842212826744133656457891641482142509705246485691963195307089');
  });

  test('deriveKeyMemoryHard (PBKDF2 at-rest key wrap) is byte-exact (golden vector)', () => {
    expect(bytesToHex(deriveKeyMemoryHard(new TextEncoder().encode('golden-pw'), hexToBytes('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'))))
      .toBe('d308d8d28fbd2893c7a7ea5fc0804204c0b1cdcf6bc5a2253c6e7b2633fc9702');
  });
});
