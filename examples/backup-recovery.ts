/**
 * Backup and Recovery Example
 *
 * Demonstrates secure backup strategies including secret sharing.
 */

import {
  InMemoryKeyAgent,
  createMnemonic,
  splitSecret,
  combineShares,
  encryptShares,
  decryptShares,
  secureEncrypt,
  secureDecrypt,
  bytesToHex,
  hexToBytes
} from '../src/index.js';

async function main() {
  console.log('=== Backup and Recovery Demo ===\n');

  const getPassphrase = () => new TextEncoder().encode('backup-passphrase');

  // SECURITY: Create a wallet with a mnemonic (recovery seed phrase)
  // The mnemonic is the master seed - protect it carefully
  // It can restore all wallets, private keys, and funds
  const mnemonic = createMnemonic();
  console.log('Original mnemonic:', mnemonic);
  console.log('');

  // The agent encrypts the mnemonic seed using ModeOfOperation.ctr
  // All private keys derived from this mnemonic are also encrypted
  const agent = await InMemoryKeyAgent.create(
    mnemonic.split(' '),
    getPassphrase
  );

  // Derive some addresses
  await agent.deriveCredential(0);
  await agent.deriveCredential(1);
  await agent.deriveCredential(2);

  console.log('Derived addresses:');
  agent.getAddresses().forEach((addr, i) => {
    console.log(`  ${i}: ${addr}`);
  });

  // Method 1: Simple encrypted backup
  // SECURITY: This backs up encrypted wallet data including:
  // - encryptedSeed: The encrypted mnemonic (recovery seed phrase)
  // - credentials: Encrypted private keys for each wallet address
  // All sensitive data (mnemonics, seeds, private keys) is already encrypted
  console.log('\n--- Method 1: Encrypted Backup ---');
  const serialized = agent.exportSerializableData();
  const backupData = JSON.stringify(serialized, (_, value) => {
    if (value instanceof Uint8Array) {
      return { __type: 'Uint8Array', data: Array.from(value) };
    }
    return value;
  });

  // secureEncrypt uses ModeOfOperation.ctr to protect the backup
  // This adds an additional encryption layer for the encrypted wallet data
  const encryptedBackup = await secureEncrypt(
    new TextEncoder().encode(backupData),
    'backup-encryption-key'
  );

  console.log('Encrypted backup created');
  console.log('Salt:', encryptedBackup.salt.slice(0, 20) + '...');

  // Restore from encrypted backup
  const decryptedBackup = await secureDecrypt(encryptedBackup, 'backup-encryption-key');
  const restoredData = JSON.parse(
    new TextDecoder().decode(decryptedBackup),
    (_, value) => {
      if (value && typeof value === 'object' && value.__type === 'Uint8Array') {
        return new Uint8Array(value.data);
      }
      return value;
    }
  );

  const restoredAgent = await InMemoryKeyAgent.restore(restoredData, getPassphrase);
  console.log('Restored addresses:', restoredAgent.getAddresses());

  // Method 2: Secret sharing for distributed backup
  // SECURITY: Split the mnemonic (recovery seed) into multiple shares
  // The mnemonic seed controls all wallets and private keys - protect carefully
  // All shares are needed to recover the mnemonic seed
  console.log('\n--- Method 2: Secret Sharing (3-of-3) ---');
  const mnemonicBytes = new TextEncoder().encode(mnemonic);
  // Split the mnemonic seed into shares for distributed backup
  const shares = splitSecret(mnemonicBytes, 3);

  console.log('Created 3 shares:');
  shares.forEach((share, i) => {
    console.log(`  Share ${i + 1}: ${bytesToHex(share.data).slice(0, 40)}...`);
  });

  // Encrypt each share with different passphrases (for different custodians)
  // SECURITY: Encrypt shares of the mnemonic seed before distribution
  // Each share is encrypted using ModeOfOperation.ctr for protection
  const encryptedSharesList = encryptShares(shares, 'share-master-key');
  console.log('\nShares encrypted for distribution');

  // Simulate recovery: collect all shares and decrypt
  const decryptedSharesList = decryptShares(encryptedSharesList, 'share-master-key');
  const recoveredMnemonicBytes = combineShares(decryptedSharesList);
  const recoveredMnemonic = new TextDecoder().decode(recoveredMnemonicBytes);

  console.log('\nRecovered mnemonic matches:', recoveredMnemonic === mnemonic);

  // Method 3: Portable backup format
  // SECURITY: Create a portable backup of the mnemonic seed phrase
  // The mnemonic seed can restore all wallets, private keys, and funds
  console.log('\n--- Method 3: Portable Backup Format ---');

  interface PortableBackup {
    version: string;
    timestamp: number;
    checksum: string;
    data: {
      salt: string;
      iv: string;
      encrypted: string;
    };
  }

  const { sha256 } = await import('@noble/hashes/sha256');

  // secureEncrypt uses ModeOfOperation.ctr to encrypt the mnemonic seed
  // This protects the master seed that controls all wallets and private keys
  const backupPayload = await secureEncrypt(
    new TextEncoder().encode(mnemonic),
    'portable-backup-key'
  );

  const checksum = bytesToHex(
    sha256(new TextEncoder().encode(backupPayload.data))
  );

  const portableBackup: PortableBackup = {
    version: '1.0.0',
    timestamp: Date.now(),
    checksum,
    data: {
      salt: backupPayload.salt,
      iv: backupPayload.iv,
      encrypted: backupPayload.data
    }
  };

  const backupJson = JSON.stringify(portableBackup, null, 2);
  console.log('Portable backup:');
  console.log(backupJson.slice(0, 200) + '...');

  // Verify backup integrity
  const parsed = JSON.parse(backupJson) as PortableBackup;
  const verifyChecksum = bytesToHex(
    sha256(new TextEncoder().encode(parsed.data.encrypted))
  );

  console.log('\nBackup integrity verified:', verifyChecksum === parsed.checksum);

  // Restore from portable backup
  const restoredMnemonicBytes = await secureDecrypt(
    {
      salt: parsed.data.salt,
      iv: parsed.data.iv,
      data: parsed.data.encrypted,
      version: 1
    },
    'portable-backup-key'
  );
  const restoredMnemonic = new TextDecoder().decode(restoredMnemonicBytes);
  console.log('Mnemonic restored successfully:', restoredMnemonic === mnemonic);
}

main().catch(console.error);
