/* Global test environment flags. __DEV__ is a React-Native global the source
 * checks to gate dev-only logging; set it false so the crypto runs its
 * production path under test. */
(global as any).__DEV__ = false;
