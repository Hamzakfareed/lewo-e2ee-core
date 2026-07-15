/**
 * MultiDeviceFanOut
 *
 * Helpers for the WhatsApp-style multi-device fan-out:
 * - The device-conversation ID format used by both encrypt and decrypt sides
 * - The accumulator that collects per-device encryption results, including
 *   logging which devices failed so the caller can diagnose partial sends.
 *
 * The format is `multidev:<senderDeviceId>:<recipientDeviceId>` — encrypt and
 * decrypt MUST produce the same string from each side, so it lives in one
 * place rather than being duplicated.
 */

export interface DeviceEncryptionEntry {
  encryptedContent: string;
  messageCounter: number;
  ratchetHeader: string;
  keyFingerprint: string;
}

/**
 * Build the per-pair conversation ID used by the Double Ratchet for one
 * (sender device, recipient device) leg of a multi-device fan-out.
 */
export function multiDeviceConversationId(
  senderDeviceId: string,
  recipientDeviceId: string
): string {
  return `multidev:${senderDeviceId}:${recipientDeviceId}`;
}

interface FanOutSummary {
  succeededDeviceIds: string[];
  failedDeviceIds: string[];
  totalRequested: number;
}

/**
 * Collect per-device encryption results during fan-out. Tracks which device
 * IDs succeeded vs. failed so the caller can log a single summary instead of
 * one log per device.
 */
export class DeviceFanOutCollector {
  private readonly entries: Record<string, DeviceEncryptionEntry> = {};
  private readonly failed: string[] = [];

  constructor(private readonly requestedDeviceIds: string[]) {}

  recordSuccess(deviceId: string, entry: DeviceEncryptionEntry): void {
    this.entries[deviceId] = entry;
  }

  recordFailure(deviceId: string): void {
    this.failed.push(deviceId);
  }

  getEntries(): Record<string, DeviceEncryptionEntry> {
    return this.entries;
  }

  summary(): FanOutSummary {
    return {
      succeededDeviceIds: Object.keys(this.entries),
      failedDeviceIds: [...this.failed],
      totalRequested: this.requestedDeviceIds.length,
    };
  }

  /** True when at least one device failed to encrypt. */
  hadPartialFailure(): boolean {
    return this.failed.length > 0;
  }
}
