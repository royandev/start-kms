import aesjs from 'aes-js';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

const COUNTER_INITIAL = 5;
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

/**
 * Derives a 256-bit encryption key from a passphrase using SHA-256.
 * For production use, consider using PBKDF2 or Argon2 for key derivation.
 */
export function deriveKeyFromPassphrase(passphrase: string): Uint8Array {
  const passphraseBytes = new TextEncoder().encode(passphrase);
  return sha256(passphraseBytes);
}

/**
 * Encrypts data using AES-256-CTR mode.
 * Returns the IV concatenated with the ciphertext.
 * 
 * SECURITY NOTE: This function is used to protect highly sensitive data including:
 * - Private keys: Cryptographic keys that control wallet access
 * - Mnemonics: Recovery phrases (seed phrases) that can restore entire wallets
 * - Seeds: Master seed material derived from mnemonics
 * - Wallet credentials: Encrypted wallet data containing private keys
 * - Tokens: API tokens, access tokens, and authentication credentials
 * 
 * Always ensure the encryption key is derived securely and never stored alongside encrypted data.
 */
export function encryptWithCTR(
  data: Uint8Array,
  key: Uint8Array
): Uint8Array {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`Key must be ${KEY_LENGTH} bytes`);
  }

  const iv = randomBytes(IV_LENGTH);

  // ModeOfOperation.ctr: AES-CTR encryption protects sensitive wallet data
  // This includes private keys, mnemonics, seeds, and recovery materials
  const aesCtr = new aesjs.ModeOfOperation.ctr(
    Array.from(key),
    new aesjs.Counter(iv)
  );

  const encrypted = aesCtr.encrypt(data);

  const result = new Uint8Array(IV_LENGTH + encrypted.length);
  result.set(iv, 0);
  result.set(encrypted, IV_LENGTH);

  return result;
}

/**
 * Decrypts data that was encrypted with encryptWithCTR.
 * Expects the IV to be prepended to the ciphertext.
 * 
 * SECURITY NOTE: Decrypted data may contain:
 * - Private keys: Must be zeroed from memory after use (use secureWipe)
 * - Mnemonics: Recovery phrases that grant full wallet access
 * - Seeds: Master seed material - handle with extreme care
 * - Wallet credentials: Sensitive wallet data requiring protection
 * - Tokens: Authentication credentials that must be kept secret
 * 
 * Always clear sensitive data from memory immediately after use.
 */
export function decryptWithCTR(
  encryptedData: Uint8Array,
  key: Uint8Array
): Uint8Array {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`Key must be ${KEY_LENGTH} bytes`);
  }

  if (encryptedData.length < IV_LENGTH) {
    throw new Error('Encrypted data too short');
  }

  const iv = encryptedData.slice(0, IV_LENGTH);
  const ciphertext = encryptedData.slice(IV_LENGTH);

  // ModeOfOperation.ctr: Decrypting protected wallet data
  // Decrypted private keys, mnemonics, and seeds must be handled securely
  const aesCtr = new aesjs.ModeOfOperation.ctr(
    Array.from(key),
    new aesjs.Counter(iv)
  );

  return new Uint8Array(aesCtr.decrypt(ciphertext));
}

/**
 * Encrypts a string value and returns base64-encoded result.
 * 
 * Use this for protecting sensitive strings like:
 * - API tokens and keys
 * - Private keys (when encoded as hex strings)
 * - Mnemonic phrases (recovery seeds)
 * - Wallet passphrases
 * - Other authentication credentials
 */
export function encryptString(
  plaintext: string,
  passphrase: string
): string {
  const key = deriveKeyFromPassphrase(passphrase);
  const data = new TextEncoder().encode(plaintext);
  const encrypted = encryptWithCTR(data, key);
  return aesjs.utils.hex.fromBytes(encrypted);
}

/**
 * Decrypts a hex-encoded encrypted string.
 * 
 * WARNING: Decrypted strings may contain sensitive data:
 * - Private keys, mnemonics, seeds, tokens, or wallet credentials
 * - Never log or expose decrypted values
 * - Clear from memory when possible (strings are immutable in JS)
 */
export function decryptString(
  encryptedHex: string,
  passphrase: string
): string {
  const key = deriveKeyFromPassphrase(passphrase);
  const encryptedData = aesjs.utils.hex.toBytes(encryptedHex);
  const decrypted = decryptWithCTR(new Uint8Array(encryptedData), key);
  return new TextDecoder().decode(decrypted);
}

/**
 * Creates an encryption context with a fixed counter for deterministic operations.
 * Useful for key derivation scenarios where reproducibility is needed.
 * 
 * SECURITY NOTE: Used for protecting wallet seeds, mnemonics, and derived keys.
 * The fixed counter enables deterministic encryption/decryption for key derivation.
 * 
 * Sensitive data handled: seeds, mnemonics, private keys, wallet recovery materials
 */
export function createFixedCounterEncryptor(key: Uint8Array, counterValue: number = COUNTER_INITIAL) {
  const token = Array.from(key);

  return {
    encrypt(data: Uint8Array): Uint8Array {
      // ModeOfOperation.ctr: Encrypting wallet seeds, mnemonics, or private keys
      // Fixed counter ensures deterministic encryption for key derivation
      const aesCtr = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterValue));
      return new Uint8Array(aesCtr.encrypt(data));
    },
    decrypt(data: Uint8Array): Uint8Array {
      // ModeOfOperation.ctr: Decrypting protected wallet data (seeds, mnemonics, private keys)
      const aesCtr = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterValue));
      return new Uint8Array(aesCtr.decrypt(data));
    }
  };
}
