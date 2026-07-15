import { hexToBytes, ed25519Verify } from '../SodiumCrypto';

interface KeyBundleForVerification {
  identityKey?: string;
  signedPreKey?: string;
  signature?: string;
  signingPublicKey?: string;
}

const ED25519_SIGNATURE_HEX_LENGTH = 128;

/**
 * Verifies an Ed25519 signature over a peer's signed pre-key, using the
 * sender's signing public key. Returns false on any structural problem
 * (missing fields, wrong-length signature, no signing key) so the caller
 * can fall through to a plaintext rejection without surfacing crypto
 * exceptions.
 *
 * Pure — no side effects beyond a console.error on internal failure.
 */
export function verifySPKSignature(keyBundle: KeyBundleForVerification): boolean {
  try {
    if (!keyBundle.signature || !keyBundle.identityKey || !keyBundle.signedPreKey) {
      return false;
    }
    if (keyBundle.signature.length !== ED25519_SIGNATURE_HEX_LENGTH || !keyBundle.signingPublicKey) {
      return false;
    }

    const signatureBytes = hexToBytes(keyBundle.signature);
    const spkPublicKeyBytes = hexToBytes(keyBundle.signedPreKey);
    const signingPublicKeyBytes = hexToBytes(keyBundle.signingPublicKey);
    return ed25519Verify(spkPublicKeyBytes, signatureBytes, signingPublicKeyBytes);
  } catch (error) {
    console.error('❌ [SPK VERIFY] Error during verification:', error);
    return false;
  }
}
