/* In-memory stand-in for expo-secure-store. The crypto tests exercise the
 * primitives and protocol, not the device keychain, so a memory map is enough. */
const store = new Map();
module.exports = {
  WHEN_UNLOCKED: 'WHEN_UNLOCKED',
  AFTER_FIRST_UNLOCK: 'AFTER_FIRST_UNLOCK',
  getItemAsync: async (k) => (store.has(k) ? store.get(k) : null),
  setItemAsync: async (k, v) => { store.set(k, String(v)); },
  deleteItemAsync: async (k) => { store.delete(k); },
  isAvailableAsync: async () => true,
};
