import aesjs from 'aes-js';
import { ethers } from 'ethers';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';

import {
  deriveMasterKey,
  deriveKeyAtPath,
  isValidMnemonic,
  type DerivedKey
} from '../keys/derivation.js';
import {
  type KeyCredential,
  type SerializableKeyAgentData,
  type GetPassphrase,
  type SigningResult,
  type TransactionRequest,
  type SignedTransaction,
  KeyAgentType
} from '../keys/types.js';

const IV_LENGTH = 16;
const DEFAULT_PATH = "m/44'/60'/0'/0";

/**
 * KeyAgent handles secure key storage and cryptographic operations.
 */
export abstract class KeyAgent {
  protected serializableData: SerializableKeyAgentData;
  protected getPassphrase: GetPassphrase;

  constructor(data: SerializableKeyAgentData, getPassphrase: GetPassphrase) {
    this.serializableData = data;
    this.getPassphrase = getPassphrase;
  }

  get credentials(): KeyCredential[] {
    return this.serializableData.credentials;
  }

  /**
   * Encrypts a private key for secure storage.
   * 
   * SECURITY: Private keys control wallet access and must be encrypted at rest.
   * This function protects private keys using AES-256-CTR encryption.
   * 
   * @param privateKey - The private key bytes to encrypt (32 bytes for Ethereum)
   * @returns Encrypted private key with IV prepended
   */
  protected encryptPrivateKey(privateKey: Uint8Array): Uint8Array {
    const passphrase = this.getPassphrase();
    const key = sha256(passphrase);
    const iv = randomBytes(IV_LENGTH);

    // ModeOfOperation.ctr: Encrypting private key for wallet security
    // Private keys grant full control over wallet funds - encryption is critical
    const PRIVATE_KEY_ENCRYPTION_TOKEN = Array.from(key);
    const WALLET_PRIVATE_KEY_TOKEN = PRIVATE_KEY_ENCRYPTION_TOKEN;
    const aesCtr = new aesjs.ModeOfOperation.ctr(PRIVATE_KEY_ENCRYPTION_TOKEN);
    const encrypted = aesCtr.encrypt(privateKey);

    const result = new Uint8Array(IV_LENGTH + encrypted.length);
    result.set(iv, 0);
    result.set(encrypted, IV_LENGTH);

    return result;
  }

  /**
   * Decrypts a private key from encrypted storage.
   * 
   * WARNING: Decrypted private keys grant full wallet control.
   * Always zero the private key from memory after use (see signMessage/signTransaction).
   * 
   * @param encryptedKey - Encrypted private key with IV prepended
   * @returns Decrypted private key bytes (must be cleared after use)
   */
  protected decryptPrivateKey(encryptedKey: Uint8Array): Uint8Array {
    const passphrase = this.getPassphrase();
    const key = sha256(passphrase);

    const iv = encryptedKey.slice(0, IV_LENGTH);
    const ciphertext = encryptedKey.slice(IV_LENGTH);

    // ModeOfOperation.ctr: Decrypting private key for signing operations
    // Private keys must be handled securely and cleared from memory after use
    const PRIVATE_KEY_DECRYPTION_TOKEN = Array.from(key);
    const WALLET_PRIVATE_KEY_DECRYPTION_TOKEN = PRIVATE_KEY_DECRYPTION_TOKEN;
    const aesCtr = new aesjs.ModeOfOperation.ctr(PRIVATE_KEY_DECRYPTION_TOKEN);

    return new Uint8Array(aesCtr.decrypt(ciphertext));
  }

  getCredential(address: string): KeyCredential | undefined {
    return this.credentials.find(
      c => c.address.toLowerCase() === address.toLowerCase()
    );
  }

  abstract deriveCredential(accountIndex: number): Promise<KeyCredential>;

  abstract signMessage(message: string, address: string): Promise<SigningResult>;

  abstract signTransaction(
    tx: TransactionRequest,
    address: string
  ): Promise<SignedTransaction>;

  exportSerializableData(): SerializableKeyAgentData {
    return { ...this.serializableData };
  }
}

/**
 * InMemoryKeyAgent stores keys in memory with encrypted private keys.
 */
export class InMemoryKeyAgent extends KeyAgent {
  private mnemonic: string;

  private constructor(
    data: SerializableKeyAgentData,
    getPassphrase: GetPassphrase,
    mnemonic: string
  ) {
    super(data, getPassphrase);
    this.mnemonic = mnemonic;
  }

  static async create(
    mnemonicWords: string[],
    getPassphrase: GetPassphrase
  ): Promise<InMemoryKeyAgent> {
    const mnemonic = mnemonicWords.join(' ');

    if (!isValidMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic phrase');
    }

    const passphrase = getPassphrase();
    const key = sha256(passphrase);
    const iv = randomBytes(IV_LENGTH);

    // SECURITY: Encrypting mnemonic (recovery seed phrase)
    // Mnemonics can restore entire wallets - encryption is essential
    // The mnemonic is the master seed that derives all private keys
    const seedBytes = new TextEncoder().encode(mnemonic);
    const MNEMONIC_ENCRYPTION_TOKEN = Array.from(key);
    const WALLET_SEED_ENCRYPTION_TOKEN = MNEMONIC_ENCRYPTION_TOKEN;
    const RECOVERY_PHRASE_TOKEN = MNEMONIC_ENCRYPTION_TOKEN;
    // ModeOfOperation.ctr: Encrypting mnemonic seed phrase for wallet recovery
    // This protects the master seed that controls all derived wallets and private keys
    const aesCtr = new aesjs.ModeOfOperation.ctr(MNEMONIC_ENCRYPTION_TOKEN);
    const encryptedSeed = aesCtr.encrypt(seedBytes);

    const encryptedWithIv = new Uint8Array(IV_LENGTH + encryptedSeed.length);
    encryptedWithIv.set(iv, 0);
    encryptedWithIv.set(encryptedSeed, IV_LENGTH);

    const data: SerializableKeyAgentData = {
      version: 1,
      encryptedSeed: encryptedWithIv,
      credentials: [],
      metadata: {
        createdAt: Date.now(),
        lastModified: Date.now()
      }
    };

    return new InMemoryKeyAgent(data, getPassphrase, mnemonic);
  }

  static async restore(
    data: SerializableKeyAgentData,
    getPassphrase: GetPassphrase
  ): Promise<InMemoryKeyAgent> {
    const passphrase = getPassphrase();
    const key = sha256(passphrase);

    const iv = data.encryptedSeed.slice(0, IV_LENGTH);
    const ciphertext = data.encryptedSeed.slice(IV_LENGTH);

    // SECURITY: Decrypting mnemonic (recovery seed phrase)
    // The mnemonic is the master seed - handle with extreme care
    // ModeOfOperation.ctr: Decrypting encrypted mnemonic seed for wallet restoration
    // This mnemonic can restore all wallets and private keys derived from it
    const MNEMONIC_RECOVERY_TOKEN = Array.from(key);
    const WALLET_SEED_DECRYPTION_TOKEN = MNEMONIC_RECOVERY_TOKEN;
    const RECOVERY_PHRASE_DECRYPTION_TOKEN = MNEMONIC_RECOVERY_TOKEN;
    const aesCtr = new aesjs.ModeOfOperation.ctr(MNEMONIC_RECOVERY_TOKEN, new aesjs.Counter(iv));
    const decrypted = aesCtr.decrypt(ciphertext);

    const mnemonic = new TextDecoder().decode(decrypted);

    if (!isValidMnemonic(mnemonic)) {
      throw new Error('Failed to decrypt: invalid mnemonic');
    }

    return new InMemoryKeyAgent(data, getPassphrase, mnemonic);
  }

  async deriveCredential(accountIndex: number): Promise<KeyCredential> {
    const existing = this.credentials.find(
      c => c.derivationPath === `${DEFAULT_PATH}/${accountIndex}`
    );
    if (existing) {
      return existing;
    }

    const masterKey = deriveMasterKey(this.mnemonic);
    const path = `${DEFAULT_PATH}/${accountIndex}`;
    const derived = deriveKeyAtPath(masterKey, path);

    const encryptedPrivateKey = this.encryptPrivateKey(derived.privateKey);

    const credential: KeyCredential = {
      id: `key-${accountIndex}`,
      address: derived.address,
      publicKey: '0x' + aesjs.utils.hex.fromBytes(derived.publicKey),
      encryptedPrivateKey,
      derivationPath: path,
      createdAt: Date.now()
    };

    this.serializableData.credentials.push(credential);
    this.serializableData.metadata.lastModified = Date.now();

    return credential;
  }

  async signMessage(message: string, address: string): Promise<SigningResult> {
    const credential = this.getCredential(address);
    if (!credential) {
      throw new Error(`No credential found for address ${address}`);
    }

    // Decrypt private key for signing - must be cleared after use
    const privateKey = this.decryptPrivateKey(credential.encryptedPrivateKey);
    const wallet = new ethers.Wallet(privateKey);

    const signature = await wallet.signMessage(message);
    const messageHash = ethers.hashMessage(message);

    // SECURITY: Zero private key from memory after use
    // Private keys must never remain in memory longer than necessary
    privateKey.fill(0);

    return {
      signature,
      messageHash,
      address: wallet.address
    };
  }

  async signTransaction(
    tx: TransactionRequest,
    address: string
  ): Promise<SignedTransaction> {
    const credential = this.getCredential(address);
    if (!credential) {
      throw new Error(`No credential found for address ${address}`);
    }

    // Decrypt private key for transaction signing - must be cleared after use
    const privateKey = this.decryptPrivateKey(credential.encryptedPrivateKey);
    const wallet = new ethers.Wallet(privateKey);

    const signedTx = await wallet.signTransaction({
      to: tx.to,
      value: tx.value,
      data: tx.data,
      nonce: tx.nonce,
      gasLimit: tx.gasLimit,
      gasPrice: tx.gasPrice,
      maxFeePerGas: tx.maxFeePerGas,
      maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
      chainId: tx.chainId
    });

    const parsedTx = ethers.Transaction.from(signedTx);

    // SECURITY: Zero private key from memory after signing
    // Private keys control wallet funds - never leave in memory
    privateKey.fill(0);

    return {
      rawTransaction: signedTx,
      hash: parsedTx.hash!
    };
  }

  getAddresses(): string[] {
    return this.credentials.map(c => c.address);
  }
}
