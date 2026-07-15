/**
 * Mock Conversation States for E2EE Tests
 *
 * Pre-configured conversation states for testing various scenarios.
 */

import { TEST_X25519_KEYS, TEST_SYMMETRIC_KEYS, hexToBytes } from './keyPairs';

/**
 * Initial conversation state (before any messages)
 */
export const INITIAL_CONVERSATION_STATE = {
  conversationId: 'conv-initial-001',
  established: false,
  rootKey: null,
  sendingChainKey: null,
  receivingChainKey: null,
  sendingRatchetKey: null,
  receivingRatchetPublicKey: null,
  messageCounter: 0,
  previousSendingChainLength: 0,
  ratchetStep: 0,
  createdAt: Date.now(),
  lastActivityAt: Date.now(),
};

/**
 * Established conversation state (after X3DH)
 */
export const ESTABLISHED_CONVERSATION_STATE = {
  conversationId: 'conv-established-001',
  established: true,
  rootKey: TEST_SYMMETRIC_KEYS.rootKey1,
  sendingChainKey: TEST_SYMMETRIC_KEYS.chainKey1,
  receivingChainKey: TEST_SYMMETRIC_KEYS.chainKey2,
  sendingRatchetKey: {
    publicKey: TEST_X25519_KEYS.alice.publicKey,
    privateKey: TEST_X25519_KEYS.alice.privateKey,
  },
  receivingRatchetPublicKey: TEST_X25519_KEYS.bob.publicKey,
  messageCounter: 0,
  previousSendingChainLength: 0,
  ratchetStep: 1,
  createdAt: Date.now() - 60000, // Created 1 minute ago
  lastActivityAt: Date.now(),
};

/**
 * Active conversation state (after several messages)
 */
export const ACTIVE_CONVERSATION_STATE = {
  conversationId: 'conv-active-001',
  established: true,
  rootKey: TEST_SYMMETRIC_KEYS.rootKey2,
  sendingChainKey: TEST_SYMMETRIC_KEYS.chainKey1,
  receivingChainKey: TEST_SYMMETRIC_KEYS.chainKey2,
  sendingRatchetKey: {
    publicKey: TEST_X25519_KEYS.alice.publicKey,
    privateKey: TEST_X25519_KEYS.alice.privateKey,
  },
  receivingRatchetPublicKey: TEST_X25519_KEYS.bob.publicKey,
  messageCounter: 15, // 15 messages sent
  previousSendingChainLength: 10,
  ratchetStep: 5, // Multiple ratchet steps
  createdAt: Date.now() - 3600000, // Created 1 hour ago
  lastActivityAt: Date.now() - 300000, // Last activity 5 minutes ago
};

/**
 * Conversation state with skipped message keys
 */
export const CONVERSATION_WITH_SKIPPED_KEYS = {
  conversationId: 'conv-skipped-001',
  established: true,
  rootKey: TEST_SYMMETRIC_KEYS.rootKey1,
  sendingChainKey: TEST_SYMMETRIC_KEYS.chainKey1,
  receivingChainKey: TEST_SYMMETRIC_KEYS.chainKey2,
  sendingRatchetKey: {
    publicKey: TEST_X25519_KEYS.alice.publicKey,
    privateKey: TEST_X25519_KEYS.alice.privateKey,
  },
  receivingRatchetPublicKey: TEST_X25519_KEYS.bob.publicKey,
  messageCounter: 5,
  previousSendingChainLength: 3,
  ratchetStep: 2,
  skippedMessageKeys: {
    // Format: "ratchetPublicKey:messageIndex" -> messageKey
    [`${TEST_X25519_KEYS.bob.publicKey}:2`]: TEST_SYMMETRIC_KEYS.messageKey1,
    [`${TEST_X25519_KEYS.bob.publicKey}:4`]: TEST_SYMMETRIC_KEYS.messageKey2,
  },
  createdAt: Date.now() - 1800000,
  lastActivityAt: Date.now(),
};

/**
 * Group conversation state
 */
export const GROUP_CONVERSATION_STATE = {
  groupId: 'group-001',
  members: ['alice', 'bob', 'charlie'],
  adminId: 'alice',
  myMemberId: 'alice',
  signingKeyPair: {
    publicKey: hexToBytes(TEST_X25519_KEYS.alice.publicKey),
    privateKey: hexToBytes(TEST_X25519_KEYS.alice.privateKey),
  },
  senderKey: hexToBytes(TEST_SYMMETRIC_KEYS.senderKey1),
  senderKeyChainKey: hexToBytes(TEST_SYMMETRIC_KEYS.chainKey1),
  messageCounter: 0,
  epoch: 1,
  memberSenderKeys: {
    bob: {
      senderKey: hexToBytes(TEST_SYMMETRIC_KEYS.senderKey2),
      signingPublicKey: hexToBytes(TEST_X25519_KEYS.bob.publicKey),
      messageCounter: 0,
    },
    charlie: {
      senderKey: hexToBytes(TEST_SYMMETRIC_KEYS.rootKey1),
      signingPublicKey: hexToBytes(TEST_X25519_KEYS.charlie.publicKey),
      messageCounter: 0,
    },
  },
  createdAt: Date.now() - 86400000, // Created 1 day ago
  lastActivityAt: Date.now(),
};

/**
 * Channel state (admin perspective)
 */
export const CHANNEL_ADMIN_STATE = {
  channelId: 'channel-001',
  isAdmin: true,
  adminId: 'alice',
  signingKeyPair: {
    publicKey: hexToBytes(TEST_X25519_KEYS.alice.publicKey),
    privateKey: hexToBytes(TEST_X25519_KEYS.alice.privateKey),
  },
  senderKey: hexToBytes(TEST_SYMMETRIC_KEYS.senderKey1),
  senderKeyChainKey: hexToBytes(TEST_SYMMETRIC_KEYS.chainKey1),
  messageCounter: 0,
  keyId: 'key-admin-001',
  subscriberCount: 100,
  createdAt: Date.now() - 604800000, // Created 1 week ago
  lastPostAt: Date.now() - 3600000,
};

/**
 * Channel state (subscriber perspective)
 */
export const CHANNEL_SUBSCRIBER_STATE = {
  channelId: 'channel-001',
  isAdmin: false,
  adminPublicKey: hexToBytes(TEST_X25519_KEYS.alice.publicKey),
  senderKey: hexToBytes(TEST_SYMMETRIC_KEYS.senderKey1),
  keyId: 'key-admin-001',
  lastReceivedCounter: 5,
  subscribedAt: Date.now() - 259200000, // Subscribed 3 days ago
};

/**
 * B2C conversation state
 */
export const B2C_CONVERSATION_STATE = {
  conversationId: 'b2c-conv-001',
  businessId: 'business-shop-001',
  customerId: 'user-alice-001',
  established: true,
  rootKey: TEST_SYMMETRIC_KEYS.rootKey1,
  sendingChainKey: TEST_SYMMETRIC_KEYS.chainKey1,
  receivingChainKey: TEST_SYMMETRIC_KEYS.chainKey2,
  sendingRatchetKey: {
    publicKey: TEST_X25519_KEYS.alice.publicKey,
    privateKey: TEST_X25519_KEYS.alice.privateKey,
  },
  receivingRatchetPublicKey: TEST_X25519_KEYS.bob.publicKey,
  messageCounter: 3,
  previousSendingChainLength: 2,
  ratchetStep: 2,
  productContext: {
    productId: 'product-001',
    productName: 'Test Product',
    productPrice: 99.99,
  },
  createdAt: Date.now() - 7200000,
  lastActivityAt: Date.now() - 1800000,
};

/**
 * Call E2EE session state
 */
export const CALL_SESSION_STATE = {
  callId: 'call-001',
  peerId: 'user-bob-001',
  localKeyPair: {
    publicKey: hexToBytes(TEST_X25519_KEYS.alice.publicKey),
    privateKey: hexToBytes(TEST_X25519_KEYS.alice.privateKey),
  },
  peerPublicKey: hexToBytes(TEST_X25519_KEYS.bob.publicKey),
  sharedSecret: hexToBytes(TEST_SYMMETRIC_KEYS.rootKey1),
  frameCounter: 0,
  established: true,
  callType: 'audio',
  startedAt: Date.now() - 120000, // Started 2 minutes ago
};

/**
 * Factory function to create a custom conversation state
 */
export function createConversationState(overrides: Record<string, any> = {}) {
  return {
    ...ESTABLISHED_CONVERSATION_STATE,
    conversationId: `conv-${Date.now()}`,
    createdAt: Date.now(),
    lastActivityAt: Date.now(),
    ...overrides,
  };
}

/**
 * Factory function to create a group state with specific members
 */
export function createGroupState(groupId: string, members: string[], adminId: string) {
  return {
    ...GROUP_CONVERSATION_STATE,
    groupId,
    members,
    adminId,
    createdAt: Date.now(),
    lastActivityAt: Date.now(),
  };
}

/**
 * Serialize state for storage (converts Uint8Array to base64)
 */
export function serializeState(state: Record<string, any>): string {
  return JSON.stringify(state, (key, value) => {
    if (value instanceof Uint8Array) {
      return {
        __type: 'Uint8Array',
        data: Array.from(value),
      };
    }
    return value;
  });
}

/**
 * Deserialize state from storage (converts base64 back to Uint8Array)
 */
export function deserializeState(json: string): Record<string, any> {
  return JSON.parse(json, (key, value) => {
    if (value && typeof value === 'object' && value.__type === 'Uint8Array') {
      return new Uint8Array(value.data);
    }
    return value;
  });
}
