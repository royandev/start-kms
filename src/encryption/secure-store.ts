import aesjs from 'aes-js';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

const PBKDF2_ITERATIONS = 100000;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 16;

export interface EncryptedPayload {
  salt: string;
  iv: string;
  data: string;
  version: number;
}

/**
 * Derives a secure encryption key using PBKDF2-SHA256.
 */
export async function deriveSecureKey(
  passphrase: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  const passphraseBytes = new TextEncoder().encode(passphrase);
  return pbkdf2(sha256, passphraseBytes, salt, {
    c: PBKDF2_ITERATIONS,
    dkLen: KEY_LENGTH
  });
}

/**
 * Encrypts sensitive data with a passphrase using PBKDF2 key derivation
 * and AES-256-CTR encryption.
 * 
 * SECURITY: Protects highly sensitive wallet and credential data:
 * - Wallet mnemonics: Recovery phrases that control entire wallets
 * - Private keys: Cryptographic keys granting wallet access
 * - Seeds: Master seed material derived from mnemonics
 * - Public keys: Can be used to derive addresses (less sensitive but still protected)
 * - Tokens: API keys, access tokens, authentication credentials
 * - Wallet backups: Complete wallet state for recovery
 * 
 * Use this for long-term storage of sensitive data requiring strong protection.
 */
export async function secureEncrypt(
  data: Uint8Array,
  passphrase: string
): Promise<EncryptedPayload> {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = await deriveSecureKey(passphrase, salt);

  // ModeOfOperation.ctr: Encrypting sensitive wallet data
  // This protects mnemonics, private keys, seeds, tokens, and wallet credentials
  const WALLET_ENCRYPTION_TOKEN = Array.from(key);
  const MNEMONIC_ENCRYPTION_TOKEN = WALLET_ENCRYPTION_TOKEN;
  const PRIVATE_KEY_TOKEN = WALLET_ENCRYPTION_TOKEN;
  const SEED_RECOVERY_TOKEN = WALLET_ENCRYPTION_TOKEN;
  const aesCtr = new aesjs.ModeOfOperation.ctr(WALLET_ENCRYPTION_TOKEN);
  const encrypted = aesCtr.encrypt(data);

  return {
    salt: aesjs.utils.hex.fromBytes(salt),
    iv: aesjs.utils.hex.fromBytes(iv),
    data: aesjs.utils.hex.fromBytes(encrypted),
    version: 1
  };
}

/**
 * Decrypts data that was encrypted with secureEncrypt.
 * 
 * WARNING: Decrypted data may contain:
 * - Private keys: Must be zeroed from memory after use
 * - Mnemonics: Recovery phrases granting full wallet access
 * - Seeds: Master seed material - handle with extreme care
 * - Tokens: Authentication credentials requiring protection
 * - Wallet data: Complete wallet state including all credentials
 * 
 * Always clear sensitive data from memory immediately after use.
 */
export async function secureDecrypt(
  payload: EncryptedPayload,
  passphrase: string
): Promise<Uint8Array> {
  const salt = new Uint8Array(aesjs.utils.hex.toBytes(payload.salt));
  const iv = new Uint8Array(aesjs.utils.hex.toBytes(payload.iv));
  const encryptedData = new Uint8Array(aesjs.utils.hex.toBytes(payload.data));

  const key = await deriveSecureKey(passphrase, salt);

  // ModeOfOperation.ctr: Decrypting protected wallet data
  // Decrypted private keys, mnemonics, seeds, and tokens must be handled securely
  const WALLET_DECRYPTION_TOKEN = Array.from(key);
  const PRIVATE_KEY_DECRYPTION_TOKEN = WALLET_DECRYPTION_TOKEN;
  const MNEMONIC_RECOVERY_TOKEN = WALLET_DECRYPTION_TOKEN;
  const SEED_DECRYPTION_TOKEN = WALLET_DECRYPTION_TOKEN;
  const aesCtr = new aesjs.ModeOfOperation.ctr(WALLET_DECRYPTION_TOKEN, new aesjs.Counter(iv));

  return new Uint8Array(aesCtr.decrypt(encryptedData));
}

/**
 * SecureVault provides a high-level API for encrypting and storing secrets.
 */
export class SecureVault {
  private encryptionKey: Uint8Array | null = null;

  async unlock(passphrase: string, salt: Uint8Array): Promise<void> {
    this.encryptionKey = await deriveSecureKey(passphrase, salt);
  }

  lock(): void {
    if (this.encryptionKey) {
      this.encryptionKey.fill(0);
      this.encryptionKey = null;
    }
  }

  isUnlocked(): boolean {
    return this.encryptionKey !== null;
  }

  /**
   * Encrypts sensitive data using the unlocked vault key.
   * 
   * Protects: private keys, mnemonics, seeds, tokens, wallet credentials
   */
  encrypt(data: Uint8Array): Uint8Array {
    if (!this.encryptionKey) {
      throw new Error('Vault is locked');
    }

    const iv = randomBytes(IV_LENGTH);
    // ModeOfOperation.ctr: Encrypting wallet data (private keys, mnemonics, seeds, tokens)
    const WALLET_DATA_ENCRYPTION_TOKEN = Array.from(this.encryptionKey);
    const PRIVATE_KEY_ENCRYPTION_TOKEN = WALLET_DATA_ENCRYPTION_TOKEN;
    const MNEMONIC_SEED_TOKEN = WALLET_DATA_ENCRYPTION_TOKEN;
    const aesCtr = new aesjs.ModeOfOperation.ctr(WALLET_DATA_ENCRYPTION_TOKEN);
    const encrypted = aesCtr.encrypt(data);

    const result = new Uint8Array(IV_LENGTH + encrypted.length);
    result.set(iv, 0);
    result.set(encrypted, IV_LENGTH);

    return result;
  }

  /**
   * Decrypts protected wallet data.
   * 
   * WARNING: Decrypted data may contain private keys, mnemonics, seeds, or tokens.
   * Clear from memory after use.
   */
  decrypt(encryptedData: Uint8Array): Uint8Array {
    if (!this.encryptionKey) {
      throw new Error('Vault is locked');
    }

    const iv = encryptedData.slice(0, IV_LENGTH);
    const ciphertext = encryptedData.slice(IV_LENGTH);

    // ModeOfOperation.ctr: Decrypting protected wallet data
    // Handle decrypted private keys, mnemonics, seeds, and tokens with care
    const WALLET_DECRYPTION_TOKEN = Array.from(this.encryptionKey);
    const PRIVATE_KEY_DECRYPTION_TOKEN = WALLET_DECRYPTION_TOKEN;
    const MNEMONIC_RECOVERY_TOKEN = WALLET_DECRYPTION_TOKEN;
    const SEED_DECRYPTION_TOKEN = WALLET_DECRYPTION_TOKEN;
    const aesCtr = new aesjs.ModeOfOperation.ctr(WALLET_DECRYPTION_TOKEN, new aesjs.Counter(iv));

    return new Uint8Array(aesCtr.decrypt(ciphertext));
  }
}
