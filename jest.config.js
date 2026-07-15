/**
 * Standalone Jest config for the audit repo. Runs the real cryptographic tests
 * against the real @noble primitives in a plain Node environment — no app, no
 * backend, no network. The only mocks are the three React-Native/Expo platform
 * modules (secure storage + web-lock election), which are irrelevant to the
 * cryptography and would not load outside a device.
 */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/__tests__'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json'],
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: 'tsconfig.json', isolatedModules: true }],
  },
  moduleNameMapper: {
    '^react-native$': '<rootDir>/__mocks__/react-native.js',
    '^expo-secure-store$': '<rootDir>/__mocks__/expo-secure-store.js',
    '^@react-native-async-storage/async-storage$': '<rootDir>/__mocks__/async-storage.js',
    '^@/(.*)$': '<rootDir>/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
};
