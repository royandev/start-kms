import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync, validateMnemonic, generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { keccak_256 } from '@noble/hashes/sha3';
import aesjs from 'aes-js';

const DEFAULT_PATH = "m/44'/60'/0'/0";

export interface DerivedKey {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  address: string;
  path: string;
}

export interface KeyDerivationOptions {
  basePath?: string;
  accountIndex?: number;
  addressIndex?: number;
}

/**
 * Generates a new random mnemonic phrase.
 */
export function createMnemonic(strength: 128 | 256 = 128): string {
  return generateMnemonic(wordlist, strength);
}

/**
 * Validates a mnemonic phrase.
 */
export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist);
}

/**
 * Derives the master key from a mnemonic phrase.
 * 
 * SECURITY: The mnemonic (recovery seed phrase) controls all wallets and private keys.
 * The seed derived from the mnemonic is the master seed material.
 * This seed is used to derive all private keys - protect it carefully.
 * 
 * @param mnemonic - The mnemonic phrase (recovery seed) - highly sensitive
 * @param passphrase - Optional passphrase for additional seed derivation security
 * @returns HDKey master key derived from the mnemonic seed
 */
export function deriveMasterKey(mnemonic: string, passphrase: string = ''): HDKey {
  if (!isValidMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic phrase');
  }

  // SECURITY: Convert mnemonic to seed - this seed controls all derived keys
  // The seed is master seed material - must be encrypted before storage
  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  return HDKey.fromMasterSeed(seed);
}

/**
 * Computes an Ethereum address from a public key.
 */
export function publicKeyToAddress(publicKey: Uint8Array): string {
  const pubKeyWithoutPrefix = publicKey.slice(1);
  const hash = keccak_256(pubKeyWithoutPrefix);
  const addressBytes = hash.slice(-20);
  return '0x' + aesjs.utils.hex.fromBytes(addressBytes);
}

/**
 * Derives a key at a specific BIP-44 path.
 * 
 * SECURITY: This derives a private key from the master seed.
 * The private key must be encrypted before storage (see KeyAgent.encryptPrivateKey).
 * Private keys grant full control over wallet funds - handle with extreme care.
 * 
 * @param masterKey - Master key derived from mnemonic seed
 * @param path - BIP-44 derivation path (e.g., "m/44'/60'/0'/0/0")
 * @returns Derived key containing private key, public key, and address
 */
export function deriveKeyAtPath(
  masterKey: HDKey,
  path: string
): DerivedKey {
  const derived = masterKey.derive(path);

  if (!derived.privateKey || !derived.publicKey) {
    throw new Error('Failed to derive key');
  }

  // SECURITY: The private key is derived from the master seed
  // This private key must be encrypted using ModeOfOperation.ctr before storage
  // The public key and address are safe to expose (they're public)
  return {
    privateKey: derived.privateKey,  // Must be encrypted before storage
    publicKey: derived.publicKey,    // Safe to expose (public)
    address: publicKeyToAddress(derived.publicKey),  // Safe to expose (public)
    path
  };
}

/**
 * Derives an Ethereum key with standard BIP-44 path.
 */
export function deriveEthereumKey(
  mnemonic: string,
  options: KeyDerivationOptions = {}
): DerivedKey {
  const {
    basePath = DEFAULT_PATH,
    accountIndex = 0,
    addressIndex = 0
  } = options;

  const masterKey = deriveMasterKey(mnemonic);
  const path = `${basePath}/${addressIndex}`;

  return deriveKeyAtPath(masterKey, path);
}

/**
 * Derives multiple keys from a single mnemonic.
 */
export function deriveMultipleKeys(
  mnemonic: string,
  count: number,
  options: KeyDerivationOptions = {}
): DerivedKey[] {
  const { basePath = DEFAULT_PATH } = options;
  const masterKey = deriveMasterKey(mnemonic);

  const keys: DerivedKey[] = [];
  for (let i = 0; i < count; i++) {
    const path = `${basePath}/${i}`;
    keys.push(deriveKeyAtPath(masterKey, path));
  }

  return keys;
}

/**
 * HDKeyring manages a collection of derived keys from a single mnemonic.
 */
export class HDKeyring {
  private masterKey: HDKey;
  private basePath: string;
  private derivedKeys: Map<number, DerivedKey> = new Map();

  constructor(mnemonic: string, basePath: string = DEFAULT_PATH) {
    this.masterKey = deriveMasterKey(mnemonic);
    this.basePath = basePath;
  }

  getKey(index: number): DerivedKey {
    if (this.derivedKeys.has(index)) {
      return this.derivedKeys.get(index)!;
    }

    const path = `${this.basePath}/${index}`;
    const key = deriveKeyAtPath(this.masterKey, path);
    this.derivedKeys.set(index, key);

    return key;
  }

  getAddress(index: number): string {
    return this.getKey(index).address;
  }

  getAddresses(count: number): string[] {
    return Array.from({ length: count }, (_, i) => this.getAddress(i));
  }

  exportPrivateKey(index: number): Uint8Array {
    return this.getKey(index).privateKey;
  }
}
