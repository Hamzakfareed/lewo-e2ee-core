/* Ambient declarations for the standalone audit build.
 *
 * __DEV__ is a React-Native build-time global (a boolean) referenced by a few
 * sources for dev-only logging. The three module declarations satisfy the
 * type-checker for the platform packages that are mocked at test runtime
 * (see jest.config.js moduleNameMapper) and are irrelevant to the cryptography. */
declare const __DEV__: boolean;
declare module 'react-native';
declare module '@react-native-async-storage/async-storage';
declare module 'expo-secure-store' {
  export type SecureStoreOptions = { keychainService?: string; keychainAccessible?: unknown };
  export const WHEN_UNLOCKED: string;
  export const AFTER_FIRST_UNLOCK: string;
  export const WHEN_UNLOCKED_THIS_DEVICE_ONLY: string;
  export const AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: string;
  export function getItemAsync(key: string, options?: SecureStoreOptions): Promise<string | null>;
  export function setItemAsync(key: string, value: string, options?: SecureStoreOptions): Promise<void>;
  export function deleteItemAsync(key: string, options?: SecureStoreOptions): Promise<void>;
  export function isAvailableAsync(): Promise<boolean>;
}
