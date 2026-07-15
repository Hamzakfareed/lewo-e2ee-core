/**
 * Pre-generated Test Key Pairs
 *
 * Fixed key pairs for deterministic tests.
 * DO NOT use these keys in production!
 */

/**
 * Test X25519 Key Pairs
 * These are deterministic keys for testing purposes only.
 */
export const TEST_X25519_KEYS = {
  // Alice's key pair
  alice: {
    privateKey: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    publicKey: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
  },

  // Bob's key pair
  bob: {
    privateKey: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
    publicKey: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
  },

  // Charlie's key pair (for group tests)
  charlie: {
    privateKey: '7a076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a',
    publicKey: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  },

  // Dave's key pair (for group tests)
  dave: {
    privateKey: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    publicKey: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
  },

  // Eve's key pair (for security tests - attacker)
  eve: {
    privateKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af46600',
    publicKey: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
  },
};

/**
 * Test Ed25519 Key Pairs (for signing)
 * These are deterministic keys for testing purposes only.
 */
export const TEST_ED25519_KEYS = {
  // Alice's signing key pair
  alice: {
    privateKey: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    publicKey: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    // Seed (first 32 bytes of private key)
    seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  },

  // Bob's signing key pair
  bob: {
    privateKey: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  },

  // Charlie's signing key pair (for group admin)
  charlie: {
    privateKey: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    publicKey: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    seed: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
  },
};

/**
 * Test encryption keys (32-byte symmetric keys)
 */
export const TEST_SYMMETRIC_KEYS = {
  // Root keys
  rootKey1: '0000000000000000000000000000000000000000000000000000000000000001',
  rootKey2: '0000000000000000000000000000000000000000000000000000000000000002',

  // Chain keys
  chainKey1: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  chainKey2: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',

  // Message keys
  messageKey1: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  messageKey2: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',

  // Sender keys (for group encryption)
  senderKey1: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  senderKey2: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
};

/**
 * Test nonces (24-byte for XChaCha20)
 */
export const TEST_NONCES = {
  nonce1: '000000000000000000000000000000000000000000000001',
  nonce2: '000000000000000000000000000000000000000000000002',
  nonce3: '404142434445464748494a4b4c4d4e4f5051525354555657',
  randomNonce: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6',
};

/**
 * Test messages
 */
export const TEST_MESSAGES = {
  short: 'Hello',
  medium: 'Hello, World! This is a test message for encryption.',
  long: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.',
  empty: '',
  unicode: 'Hello \u{1F44B} World \u{1F30D}! Afghan text: سلام',
  binary: new Uint8Array([0x00, 0x01, 0x02, 0xfe, 0xff]),
};

/**
 * Test conversation IDs
 */
export const TEST_CONVERSATION_IDS = {
  aliceBob: 'conv-alice-bob-001',
  aliceCharlie: 'conv-alice-charlie-001',
  bobCharlie: 'conv-bob-charlie-001',
  groupChat: 'group-chat-001',
  channel: 'channel-001',
  business: 'business-conv-001',
};

/**
 * Test user IDs
 */
export const TEST_USER_IDS = {
  alice: 'user-alice-001',
  bob: 'user-bob-001',
  charlie: 'user-charlie-001',
  dave: 'user-dave-001',
  eve: 'user-eve-001', // Attacker
  business: 'business-shop-001',
};

/**
 * Helper to convert hex to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Get test key pair as Uint8Array
 */
export function getX25519KeyPair(name: keyof typeof TEST_X25519_KEYS): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const keys = TEST_X25519_KEYS[name];
  return {
    publicKey: hexToBytes(keys.publicKey),
    privateKey: hexToBytes(keys.privateKey),
  };
}

/**
 * Get test Ed25519 key pair as Uint8Array
 */
export function getEd25519KeyPair(name: keyof typeof TEST_ED25519_KEYS): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  seed: Uint8Array;
} {
  const keys = TEST_ED25519_KEYS[name];
  return {
    publicKey: hexToBytes(keys.publicKey),
    privateKey: hexToBytes(keys.privateKey),
    seed: hexToBytes(keys.seed),
  };
}

/**
 * Get test symmetric key as Uint8Array
 */
export function getSymmetricKey(name: keyof typeof TEST_SYMMETRIC_KEYS): Uint8Array {
  return hexToBytes(TEST_SYMMETRIC_KEYS[name]);
}

/**
 * Get test nonce as Uint8Array
 */
export function getNonce(name: keyof typeof TEST_NONCES): Uint8Array {
  return hexToBytes(TEST_NONCES[name]);
}
