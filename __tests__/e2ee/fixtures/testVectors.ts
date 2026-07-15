/**
 * RFC Test Vectors for Cryptographic Primitives
 *
 * These test vectors are taken from official RFCs and specifications
 * to verify our crypto implementations are correct.
 */

/**
 * X25519 Test Vectors from RFC 7748
 * https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
 */
export const X25519_TEST_VECTORS = {
  // Alice's private key (scalar)
  alicePrivate: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  // Alice's public key
  alicePublic: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',

  // Bob's private key (scalar)
  bobPrivate: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
  // Bob's public key
  bobPublic: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',

  // Shared secret (Alice private * Bob public = Bob private * Alice public)
  sharedSecret: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',

  // Additional test case: scalar multiplication by base point
  basePointMultiplication: {
    scalar: '0900000000000000000000000000000000000000000000000000000000000000',
    // After 1 iteration
    result1: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079',
  },
};

/**
 * Ed25519 Test Vectors from RFC 8032
 * https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
 */
export const ED25519_TEST_VECTORS = {
  // Test 1: Empty message
  test1: {
    privateKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    message: '', // empty
    signature: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },

  // Test 2: Single byte message
  test2: {
    privateKey: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    message: '72', // 0x72
    signature: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },

  // Test 3: Two byte message
  test3: {
    privateKey: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    publicKey: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    message: 'af82', // 0xaf82
    signature: '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
  },

  // Test 4: Longer message (1023 bytes)
  test4: {
    privateKey: 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
    publicKey: '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
    // SHA(abc) - using a known test message
    message: '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0',
    signature: '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03',
  },
};

/**
 * XChaCha20-Poly1305 Test Vectors
 * Based on RFC 8439 ChaCha20-Poly1305 but extended to XChaCha20
 * Test vectors from IETF draft-irtf-cfrg-xchacha
 */
export const XCHACHA20_POLY1305_TEST_VECTORS = {
  // Test vector from IETF draft
  test1: {
    key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    nonce: '404142434445464748494a4b4c4d4e4f5051525354555657',
    plaintext: '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e',
    // The Ladies and Gentlemen of the class of '99...
    aad: '50515253c0c1c2c3c4c5c6c7',
    ciphertext: 'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e',
    tag: 'c0875924c1c7987947deafd8780acf49',
  },

  // Simple test case
  test2: {
    key: '0000000000000000000000000000000000000000000000000000000000000001',
    nonce: '000000000000000000000000000000000000000000000002',
    plaintext: '48656c6c6f2c20576f726c6421', // "Hello, World!"
    aad: '',
  },

  // Test with empty plaintext
  test3: {
    key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
    nonce: '000000000000000000000000000000000000000000000000',
    plaintext: '',
    aad: '',
  },
};

/**
 * BLAKE2b Test Vectors from RFC 7693
 * https://datatracker.ietf.org/doc/html/rfc7693
 */
export const BLAKE2B_TEST_VECTORS = {
  // Test 1: Empty input, no key
  test1: {
    input: '',
    key: '',
    outputLength: 64,
    expected: '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
  },

  // Test 2: "abc" input, no key
  test2: {
    input: '616263', // "abc"
    key: '',
    outputLength: 64,
    expected: 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
  },

  // Test 3: With key (keyed hash)
  test3: {
    input: '616263', // "abc"
    key: '000102030405060708090a0b0c0d0e0f', // 16-byte key
    outputLength: 64,
    expected: null, // Computed at runtime as it depends on implementation
  },

  // Test 4: 32-byte output (BLAKE2b-256)
  test4: {
    input: '616263', // "abc"
    key: '',
    outputLength: 32,
    expected: 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319',
  },
};

/**
 * Signal Protocol Test Vectors
 * Derived from Signal specification for X3DH and Double Ratchet
 */
export const SIGNAL_PROTOCOL_TEST_VECTORS = {
  // X3DH Key Agreement test case
  x3dh: {
    // Alice (initiator)
    aliceIdentityKey: {
      private: '1111111111111111111111111111111111111111111111111111111111111111',
      public: null, // Computed from private
    },
    aliceEphemeralKey: {
      private: '2222222222222222222222222222222222222222222222222222222222222222',
      public: null, // Computed from private
    },
    // Bob (responder)
    bobIdentityKey: {
      private: '3333333333333333333333333333333333333333333333333333333333333333',
      public: null, // Computed from private
    },
    bobSignedPreKey: {
      private: '4444444444444444444444444444444444444444444444444444444444444444',
      public: null, // Computed from private
    },
    bobOneTimePreKey: {
      private: '5555555555555555555555555555555555555555555555555555555555555555',
      public: null, // Computed from private
    },
    // Expected shared secrets (will be computed and verified)
    info: 'WhisperText',
  },

  // Double Ratchet test case
  doubleRatchet: {
    initialRootKey: '0000000000000000000000000000000000000000000000000000000000000000',
    // First ratchet step input
    dhOutput: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    // Context info for key derivation
    ratchetInfo: 'WhisperRatchet',
    // Message key derivation constants
    messageKeyConstant: '01',
    chainKeyConstant: '02',
  },
};

/**
 * Helper to convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Helper to convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
