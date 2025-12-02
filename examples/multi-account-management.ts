/**
 * Multi-Account Management Example
 *
 * Demonstrates managing multiple wallets and accounts with the KeyManager.
 */

import {
  KeyManager,
  createMnemonic
} from '../src/index.js';

// In-memory storage for demo (use localStorage in browser)
class MemoryStorage implements Storage {
  private data: Map<string, string> = new Map();

  get length(): number {
    return this.data.size;
  }

  clear(): void {
    this.data.clear();
  }

  getItem(key: string): string | null {
    return this.data.get(key) ?? null;
  }

  key(index: number): string | null {
    return Array.from(this.data.keys())[index] ?? null;
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }
}

async function main() {
  console.log('=== Multi-Account Management Demo ===\n');

  const storage = new MemoryStorage();
  const manager = new KeyManager({
    storage,
    autoSave: true
  });

  const getPassphrase = () => new TextEncoder().encode('master-password-123');

  // Create multiple wallets for different purposes
  // SECURITY: Each wallet has its own mnemonic (recovery seed phrase)
  // Mnemonics control wallets and private keys - protect them carefully
  console.log('Creating wallets...');

  // Personal wallet - mnemonic seed encrypted using ModeOfOperation.ctr
  const personalMnemonic = createMnemonic();
  // The mnemonic seed is encrypted before storage
  const personalAgent = await manager.createAgent(
    'personal',
    personalMnemonic.split(' '),
    getPassphrase
  );

  // Business wallet - separate mnemonic seed for isolation
  const businessMnemonic = createMnemonic();
  // Each wallet's mnemonic seed is encrypted independently
  const businessAgent = await manager.createAgent(
    'business',
    businessMnemonic.split(' '),
    getPassphrase
  );

  // DeFi wallet - another mnemonic seed for DeFi operations
  const defiMnemonic = createMnemonic();
  // All mnemonics (seeds) are encrypted using ModeOfOperation.ctr
  const defiAgent = await manager.createAgent(
    'defi',
    defiMnemonic.split(' '),
    getPassphrase
  );

  console.log('Created wallets:', manager.listAgents());

  // Derive addresses for each wallet
  // SECURITY: Each credential contains an encrypted private key
  // Private keys are derived from the mnemonic seed and encrypted before storage
  console.log('\nDeriving addresses...');

  // Personal: 2 addresses
  // Each credential has: address (public), publicKey, encryptedPrivateKey
  for (let i = 0; i < 2; i++) {
    const cred = await manager.deriveCredential('personal', i);
    // cred.encryptedPrivateKey contains the encrypted private key
    console.log(`Personal ${i}: ${cred.address}`);
  }

  // Business: 3 addresses
  // Private keys are encrypted using ModeOfOperation.ctr before storage
  for (let i = 0; i < 3; i++) {
    const cred = await manager.deriveCredential('business', i);
    console.log(`Business ${i}: ${cred.address}`);
  }

  // DeFi: 5 addresses for different protocols
  // Each private key is encrypted independently for security
  for (let i = 0; i < 5; i++) {
    const cred = await manager.deriveCredential('defi', i);
    console.log(`DeFi ${i}: ${cred.address}`);
  }

  // Sign messages with different accounts
  // SECURITY: Private keys are decrypted temporarily, used for signing, then zeroed
  // Each wallet's private keys are encrypted and only decrypted when needed
  console.log('\nSigning messages...');

  const personalAddr = manager.getAgent('personal')!.getAddresses()[0];
  // The private key is decrypted, used to sign, then zeroed from memory
  const sig1 = await manager.signMessage('personal', 'Personal transaction', personalAddr);
  console.log('Personal signature:', sig1.signature.slice(0, 40) + '...');

  const businessAddr = manager.getAgent('business')!.getAddresses()[0];
  // Private keys are never stored in plaintext - always encrypted at rest
  const sig2 = await manager.signMessage('business', 'Business approval', businessAddr);
  console.log('Business signature:', sig2.signature.slice(0, 40) + '...');

  // Export and save
  // SECURITY: All wallet data is encrypted before storage
  // This includes encrypted mnemonics (seeds), private keys, and credentials
  // ModeOfOperation.ctr is used to encrypt all wallet data together
  console.log('\nSaving to storage...');
  await manager.save(getPassphrase);
  // All sensitive data (mnemonics, seeds, private keys) is encrypted
  console.log('Storage size:', storage.length);

  // Simulate app restart - create new manager and load
  console.log('\nSimulating app restart...');
  const newManager = new KeyManager({ storage });
  await newManager.load(getPassphrase);

  console.log('Loaded wallets:', newManager.listAgents());

  // Verify addresses are preserved
  const loadedPersonal = newManager.getAgent('personal');
  console.log('Personal addresses preserved:', loadedPersonal?.getAddresses());

  // Remove a wallet
  console.log('\nRemoving DeFi wallet...');
  newManager.removeAgent('defi');
  console.log('Remaining wallets:', newManager.listAgents());
}

main().catch(console.error);
