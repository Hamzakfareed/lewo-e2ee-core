import {
  MetadataCipher,
  PADDING_BLOCK_SIZE,
  PADDING_MAGIC,
} from '@/src/services/e2ee/MetadataCipher';
import {
  initializeSodium,
  bytesToHex,
  randomBytes,
} from '@/src/services/SodiumCrypto';

let messageKeyHex: string;

beforeAll(async () => {
  await initializeSodium();
  messageKeyHex = bytesToHex(randomBytes(32));
});

describe('MetadataCipher.encryptMetadata / decryptMetadata', () => {
  test('round-trips', () => {
    const meta = { conversationId: 'c-1', timestamp: 12345, senderUserId: 'alice' };
    const sealed = MetadataCipher.encryptMetadata(meta, messageKeyHex);
    const out = MetadataCipher.decryptMetadata(sealed, messageKeyHex);
    expect(out).toEqual(meta);
  });

  test('encryptMetadata produces v=xchacha20-poly1305-v1 mv=2 envelope', () => {
    const sealed = JSON.parse(MetadataCipher.encryptMetadata({ x: 1 }, messageKeyHex));
    expect(sealed.v).toBe('xchacha20-poly1305-v1');
    expect(sealed.mv).toBe(2);
    expect(sealed.n).toMatch(/^[0-9a-f]+$/);
    expect(sealed.c).toMatch(/^[0-9a-f]+$/);
  });

  test('decryptMetadata returns null on wrong key', () => {
    const sealed = MetadataCipher.encryptMetadata({ x: 1 }, messageKeyHex);
    const wrongKey = bytesToHex(randomBytes(32));
    expect(MetadataCipher.decryptMetadata(sealed, wrongKey)).toBeNull();
  });

  test('decryptMetadata returns null on garbage input', () => {
    expect(MetadataCipher.decryptMetadata('{not json', messageKeyHex)).toBeNull();
    expect(MetadataCipher.decryptMetadata(JSON.stringify({ v: 'wrong' }), messageKeyHex)).toBeNull();
  });

  test('legacy mv-undefined envelope decrypts with the message key directly', () => {
    // Hand-craft a legacy envelope (no mv field) — should still decrypt with messageKey-as-key.
    // The current encrypt path always emits mv=2 so we exercise the back-compat path
    // by constructing the envelope manually.
    const { encryptXChaCha20Poly1305, hexToBytes } = require('@/src/services/SodiumCrypto');
    const keyBytes = hexToBytes(messageKeyHex);
    const meta = { legacy: true };
    const enc = encryptXChaCha20Poly1305(
      new TextEncoder().encode(JSON.stringify(meta)),
      keyBytes,
    );
    const legacy = JSON.stringify({
      v: 'xchacha20-poly1305-v1',
      n: bytesToHex(enc.nonce),
      c: bytesToHex(enc.ciphertext),
    });
    expect(MetadataCipher.decryptMetadata(legacy, messageKeyHex)).toEqual(meta);
  });
});

describe('MetadataCipher.applyPadding / removePadding', () => {
  test('applyPadding rounds up to next PADDING_BLOCK_SIZE multiple', () => {
    const empty = new Uint8Array(0);
    const padded = MetadataCipher.applyPadding(empty);
    expect(padded.length).toBe(PADDING_BLOCK_SIZE);
    expect(padded[0]).toBe(PADDING_MAGIC);
  });

  test('applyPadding writes 0x80 immediately after plaintext', () => {
    const plain = new TextEncoder().encode('hi');
    const padded = MetadataCipher.applyPadding(plain);
    expect(padded[plain.length]).toBe(PADDING_MAGIC);
    for (let i = plain.length + 1; i < padded.length; i++) {
      expect(padded[i]).toBe(0);
    }
  });

  test('round-trip: removePadding(applyPadding(x)) === x', () => {
    const plain = new TextEncoder().encode('hello world');
    const padded = MetadataCipher.applyPadding(plain);
    const recovered = MetadataCipher.removePadding(padded);
    expect(Array.from(recovered)).toEqual(Array.from(plain));
  });

  test('removePadding throws INVALID_PADDING on aligned payload missing the marker', () => {
    const allZeros = new Uint8Array(PADDING_BLOCK_SIZE);
    expect(() => MetadataCipher.removePadding(allZeros)).toThrow(/INVALID_PADDING/);
  });

  test('removePadding tolerates legacy unaligned unpadded payload', () => {
    const legacy = new TextEncoder().encode('legacy unpadded');
    const out = MetadataCipher.removePadding(legacy);
    expect(Array.from(out)).toEqual(Array.from(legacy));
  });
});

describe('MetadataCipher.unwrapEnvelope', () => {
  test('returns plaintext + null envelope for non-JSON v1 content', () => {
    const out = MetadataCipher.unwrapEnvelope('hello');
    expect(out.content).toBe('hello');
    expect(out.envelope).toBeNull();
  });

  test('extracts v2 envelope fields', () => {
    const v2 = JSON.stringify({
      v: 2,
      c: 'inner content',
      t: 'IMAGE',
      m: ['url-1'],
      meta: { foo: 'bar' },
      replyTo: 'msg-uuid',
    });
    const out = MetadataCipher.unwrapEnvelope(v2);
    expect(out.content).toBe('inner content');
    expect(out.envelope).toEqual({
      messageType: 'IMAGE',
      mediaUrls: ['url-1'],
      metadata: { foo: 'bar' },
      replyToMessageUuid: 'msg-uuid',
    });
  });

  test('JSON without v=2 is treated as plaintext', () => {
    const json = JSON.stringify({ unrelated: true });
    const out = MetadataCipher.unwrapEnvelope(json);
    expect(out.content).toBe(json);
    expect(out.envelope).toBeNull();
  });

  test('v2 envelope with missing optional fields fills sensible defaults', () => {
    const v2 = JSON.stringify({ v: 2, c: 'x' });
    const out = MetadataCipher.unwrapEnvelope(v2);
    expect(out.content).toBe('x');
    expect(out.envelope).toEqual({
      messageType: 'TEXT',
      mediaUrls: null,
      metadata: null,
      replyToMessageUuid: null,
    });
  });
});

describe('MetadataCipher.computeKeyedMAC', () => {
  // Production callers always pass ≥16-byte messages (SPK public key = 32 bytes,
  // message keys = 32 bytes). deriveKey enforces a 16-byte IKM minimum.
  let msg: string;
  let key: string;
  beforeAll(() => {
    msg = bytesToHex(new Uint8Array(32).fill(1));
    key = bytesToHex(new Uint8Array(32).fill(2));
  });

  test('deterministic for fixed (message, key)', () => {
    expect(MetadataCipher.computeKeyedMAC(msg, key)).toBe(
      MetadataCipher.computeKeyedMAC(msg, key),
    );
  });

  test('different keys produce different MACs', () => {
    const k2 = bytesToHex(new Uint8Array(32).fill(3));
    expect(MetadataCipher.computeKeyedMAC(msg, key)).not.toBe(
      MetadataCipher.computeKeyedMAC(msg, k2),
    );
  });

  test('different messages produce different MACs', () => {
    const m2 = bytesToHex(new Uint8Array(32).fill(4));
    expect(MetadataCipher.computeKeyedMAC(msg, key)).not.toBe(
      MetadataCipher.computeKeyedMAC(m2, key),
    );
  });

  test('hashes oversized keys before MAC (no throw)', () => {
    const longKey = 'aa'.repeat(100);
    expect(() => MetadataCipher.computeKeyedMAC(msg, longKey)).not.toThrow();
  });

  test('non-hex keys fall back to UTF-8 encoding', () => {
    const utf8Key = 'plain-text-key-with-enough-entropy-bytes';
    expect(() => MetadataCipher.computeKeyedMAC(msg, utf8Key)).not.toThrow();
  });
});
