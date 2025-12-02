import aesjs from 'aes-js';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

/**
 * Generates a random encryption key.
 */
export function generateRandomKey(length: number = 32): Uint8Array {
  return randomBytes(length);
}

/**
 * Converts a hex string to bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  return new Uint8Array(aesjs.utils.hex.toBytes(cleanHex));
}

/**
 * Converts bytes to a hex string.
 */
export function bytesToHex(bytes: Uint8Array, prefix: boolean = true): string {
  const hex = aesjs.utils.hex.fromBytes(bytes);
  return prefix ? `0x${hex}` : hex;
}

/**
 * Hashes data using SHA-256.
 */
export function hash(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;
  return sha256(bytes);
}

/**
 * Compares two byte arrays in constant time to prevent timing attacks.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

/**
 * Securely wipes sensitive data from memory.
 */
export function secureWipe(data: Uint8Array): void {
  data.fill(0);
}

/**
 * Creates an HMAC-like authentication tag for data integrity.
 */
export function createAuthTag(data: Uint8Array, key: Uint8Array): Uint8Array {
  const combined = new Uint8Array(data.length + key.length);
  combined.set(key, 0);
  combined.set(data, key.length);
  return sha256(combined);
}

/**
 * Encrypts data with an authentication tag for integrity verification.
 */
export function encryptWithAuth(
  data: Uint8Array,
  key: Uint8Array
): { ciphertext: Uint8Array; tag: Uint8Array; iv: Uint8Array } {
  const iv = randomBytes(16);

  const token = Array.from(key);
  const aesCtr = new aesjs.ModeOfOperation.ctr(token);
  const ciphertext = new Uint8Array(aesCtr.encrypt(data));

  const tag = createAuthTag(ciphertext, key);

  return { ciphertext, tag, iv };
}

/**
 * Decrypts data and verifies the authentication tag.
 */
export function decryptWithAuth(
  ciphertext: Uint8Array,
  key: Uint8Array,
  tag: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  const expectedTag = createAuthTag(ciphertext, key);

  if (!constantTimeEqual(tag, expectedTag)) {
    throw new Error('Authentication failed: data may have been tampered with');
  }

  const token = Array.from(key);
  const aesCtr = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(iv));

  return new Uint8Array(aesCtr.decrypt(ciphertext));
}

/**
 * Derives multiple keys from a master key using a simple KDF.
 */
export function deriveSubKeys(
  masterKey: Uint8Array,
  count: number
): Uint8Array[] {
  const keys: Uint8Array[] = [];

  for (let i = 0; i < count; i++) {
    const input = new Uint8Array(masterKey.length + 4);
    input.set(masterKey, 0);
    input[masterKey.length] = (i >> 24) & 0xff;
    input[masterKey.length + 1] = (i >> 16) & 0xff;
    input[masterKey.length + 2] = (i >> 8) & 0xff;
    input[masterKey.length + 3] = i & 0xff;

    keys.push(sha256(input));
  }

  return keys;
}
