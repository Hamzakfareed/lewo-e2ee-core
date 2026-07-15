/* In-memory stand-in for @react-native-async-storage/async-storage. */
const store = new Map();
module.exports = {
  __esModule: true,
  default: {
    getItem: async (k) => (store.has(k) ? store.get(k) : null),
    setItem: async (k, v) => { store.set(k, String(v)); },
    removeItem: async (k) => { store.delete(k); },
    multiRemove: async (ks) => { (ks || []).forEach((k) => store.delete(k)); },
    getAllKeys: async () => [...store.keys()],
    clear: async () => { store.clear(); },
  },
};
