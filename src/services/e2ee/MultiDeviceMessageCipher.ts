/**
 * MultiDeviceMessageCipher
 *
 * The fan-out encrypt + per-device decrypt loops for `MultiDeviceE2EEService`.
 * Pulled out so the per-device encrypt/decrypt sequencing is exercised
 * without needing to spin up a real device-id store.
 *
 * The actual 1:1 encrypt/decrypt happens in `e2eEncryptionService` via the
 * caller-provided callbacks. This module owns:
 *   - the per-device conversation-id derivation (via MultiDeviceFanOut)
 *   - the success/failure tracking (DeviceFanOutCollector)
 *   - the discriminated decrypt result shape
 */

import {
  multiDeviceConversationId,
  DeviceFanOutCollector,
} from './MultiDeviceFanOut';

export interface DevicePerEncryption {
  encryptedContent: string;
  messageCounter: number;
  ratchetHeader: string;
  keyFingerprint?: string;
}

export interface MultiDeviceFanOutResult {
  /** Map of recipient deviceId -> per-device ciphertext metadata. */
  deviceEncryptions: Record<string, DevicePerEncryption>;
  /** Devices that failed to encrypt and were dropped. */
  failedDeviceIds: string[];
  /** Devices that successfully received a ciphertext entry. */
  succeededDeviceIds: string[];
  /** True if at least one device was dropped during encryption. */
  hadPartialFailure: boolean;
}

export type MultiDeviceDecryptResult =
  | { status: 'success'; content: string }
  | { status: 'not_for_device' }
  | { status: 'failed'; error: string };

/**
 * Encrypt the same plaintext separately for each recipient device. Skips
 * (logs + records failure) for any device that throws during encrypt.
 */
export async function encryptForRecipientDevices(args: {
  senderDeviceId: string;
  recipientUserId: string;
  recipientDeviceIds: string[];
  plaintext: string;
  encryptForDevice: (
    deviceConversationId: string,
    plaintext: string,
    senderDeviceId: string,
    recipientUserId: string
  ) => Promise<{
    encryptedContent: string;
    messageCounter: number;
    ivData: string;
    keyFingerprint?: string;
  }>;
}): Promise<MultiDeviceFanOutResult> {
  const collector = new DeviceFanOutCollector(args.recipientDeviceIds);

  for (const deviceId of args.recipientDeviceIds) {
    try {
      const deviceConvoId = multiDeviceConversationId(args.senderDeviceId, deviceId);
      const encrypted = await args.encryptForDevice(
        deviceConvoId,
        args.plaintext,
        args.senderDeviceId,
        args.recipientUserId
      );
      collector.recordSuccess(deviceId, {
        encryptedContent: encrypted.encryptedContent,
        messageCounter: encrypted.messageCounter,
        ratchetHeader: encrypted.ivData,
        keyFingerprint: encrypted.keyFingerprint || '',
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      console.warn(`⚠️ [MultiDeviceMessageCipher] Encrypt failed for device ${deviceId} (recipient=${args.recipientUserId}): ${errorMsg}`);
      collector.recordFailure(deviceId);
    }
  }

  const summary = collector.summary();
  return {
    deviceEncryptions: collector.getEntries(),
    failedDeviceIds: summary.failedDeviceIds,
    succeededDeviceIds: summary.succeededDeviceIds,
    hadPartialFailure: collector.hadPartialFailure(),
  };
}

/**
 * Find the entry for `myDeviceId` and run it through the caller's decrypt
 * function. Returns a discriminated result so callers can distinguish
 * "no entry" (message wasn't for this device) from a real failure.
 */
export async function decryptForOurDevice(args: {
  myDeviceId: string;
  senderDeviceId: string;
  senderUserId: string;
  deviceEncryptions: Record<string, DevicePerEncryption>;
  decryptForDevice: (
    deviceConversationId: string,
    encryptedContent: string,
    messageCounter: number,
    ratchetHeader: string,
    senderUserId: string,
    myDeviceId: string,
    keyFingerprint?: string
  ) => Promise<string>;
}): Promise<MultiDeviceDecryptResult> {
  const entry = args.deviceEncryptions[args.myDeviceId];
  if (!entry) {
    return { status: 'not_for_device' };
  }

  const deviceConvoId = multiDeviceConversationId(args.senderDeviceId, args.myDeviceId);
  try {
    const content = await args.decryptForDevice(
      deviceConvoId,
      entry.encryptedContent,
      entry.messageCounter,
      entry.ratchetHeader,
      args.senderUserId,
      args.myDeviceId,
      entry.keyFingerprint
    );
    return { status: 'success', content };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    return { status: 'failed', error: errorMsg };
  }
}
