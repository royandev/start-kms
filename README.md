# start-kms

A lightweight Key Management System for EVM-compatible blockchains. Built for developers who need secure key derivation, encrypted storage, and transaction signing without the complexity of enterprise KMS solutions.

## Features

- **HD Wallet Support** - BIP-39 mnemonic generation with BIP-44 key derivation
- **Secure Storage** - AES-256-CTR encryption for private keys and sensitive data
- **Transaction Signing** - Sign messages and transactions for Ethereum and EVM chains
- **Multi-Account Management** - Manage multiple wallets with different purposes
- **Backup & Recovery** - Secret sharing and encrypted backup formats
- **TypeScript First** - Full type definitions included

## Installation

```bash
npm install start-kms
```

## Quick Start

### Creating a Wallet

```typescript
import { InMemoryKeyAgent, createMnemonic } from 'start-kms';

// SECURITY: Generate a new mnemonic (recovery seed phrase)
// The mnemonic is the master seed that controls all wallets and private keys
// Store mnemonics securely - they can restore entire wallets
const mnemonic = createMnemonic();

// SECURITY: Create a passphrase getter - never hardcode in production
// The passphrase encrypts the mnemonic seed and all derived private keys
// It protects encrypted wallet data using AES-256-CTR encryption
const getPassphrase = () => new TextEncoder().encode('your-secure-passphrase');

// Initialize the key agent - mnemonic seed is encrypted using ModeOfOperation.ctr
// All private keys derived from this mnemonic are also encrypted before storage
const agent = await InMemoryKeyAgent.create(
  mnemonic.split(' '),
  getPassphrase
);

// Derive addresses
// SECURITY: Each credential contains an encrypted private key
// Private keys are encrypted using AES-256-CTR (ModeOfOperation.ctr) before storage
const credential = await agent.deriveCredential(0);
// credential contains: address (public), publicKey, encryptedPrivateKey
console.log('Address:', credential.address);
```

### Signing Messages

```typescript
// SECURITY: Private key is decrypted temporarily, used to sign, then zeroed from memory
// The private key is never stored in plaintext - always encrypted at rest
// ModeOfOperation.ctr is used to decrypt the private key for signing operations
const signature = await agent.signMessage(
  'Hello, Ethereum!',
  credential.address
);
// The private key was automatically zeroed from memory after signing

console.log('Signature:', signature.signature);
```

### Signing Transactions

```typescript
// SECURITY: Private key is decrypted temporarily for signing, then cleared from memory
// All private keys remain encrypted until needed for signing operations
// ModeOfOperation.ctr decrypts the private key, signs, then zeros it
const signedTx = await agent.signTransaction({
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f1b234',
  value: BigInt('1000000000000000000'),
  chainId: 1,
  nonce: 0,
  gasLimit: BigInt(21000),
  maxFeePerGas: BigInt('20000000000'),
  maxPriorityFeePerGas: BigInt('1000000000')
}, credential.address);
// The private key was automatically zeroed from memory after signing

console.log('Transaction hash:', signedTx.hash);
```

## Managing Multiple Wallets

The `KeyManager` class helps organize multiple wallets for different purposes:

```typescript
import { KeyManager, createMnemonic } from 'start-kms';

const manager = new KeyManager({
  storage: localStorage,  // Browser storage
  autoSave: true
});

const getPassphrase = () => new TextEncoder().encode('master-password');

// Create wallets for different purposes
await manager.createAgent('personal', createMnemonic().split(' '), getPassphrase);
await manager.createAgent('business', createMnemonic().split(' '), getPassphrase);

// Derive addresses
await manager.deriveCredential('personal', 0);
await manager.deriveCredential('business', 0);

// Sign with specific wallet
const sig = await manager.signMessage('personal', 'Hello', address);
```

## Encrypting Sensitive Data

Beyond wallet management, you can encrypt any sensitive data:

```typescript
import { encryptString, decryptString, SecureVault } from 'start-kms';

// SECURITY: Encrypt API tokens, keys, and other sensitive credentials
// encryptString uses ModeOfOperation.ctr (AES-256-CTR) internally
// This protects tokens, private keys (when encoded as strings), and secrets
const encrypted = encryptString('api-key-12345', 'passphrase');
// Never log or expose encrypted values containing tokens or keys
const decrypted = decryptString(encrypted, 'passphrase');

// Session-based vault for temporary encryption
// SECURITY: The vault uses ModeOfOperation.ctr to encrypt sensitive data
// This protects tokens, mnemonics, seeds, private keys, and credentials
const vault = new SecureVault();
await vault.unlock('passphrase', salt);

// Encrypt sensitive data (tokens, keys, mnemonics, seeds, private keys)
const ciphertext = vault.encrypt(sensitiveData);
// Decrypt only when needed - vault clears keys when locked
const plaintext = vault.decrypt(ciphertext);

// SECURITY: Lock vault to clear encryption keys from memory
vault.lock();  // Clear keys from memory
```

## Backup Strategies

### Encrypted Export

```typescript
import { secureEncrypt, secureDecrypt } from 'start-kms';

// SECURITY: Export encrypted wallet data for backup
// This includes encrypted mnemonics (seeds), private keys, and credentials
// All sensitive data (mnemonics, seeds, private keys) is already encrypted
const data = agent.exportSerializableData();
// secureEncrypt uses ModeOfOperation.ctr to add additional encryption layer
// This protects encrypted mnemonics, seeds, private keys, and wallet credentials
const backup = await secureEncrypt(
  new TextEncoder().encode(JSON.stringify(data)),
  'backup-password'
);

// Store backup.salt, backup.iv, backup.data safely
// The backup contains encrypted mnemonics (recovery seeds) and private keys
```

### Secret Sharing

Split your mnemonic across multiple locations:

```typescript
import { splitSecret, combineShares } from 'start-kms';

// SECURITY: Split the mnemonic (recovery seed phrase) into multiple shares
// The mnemonic seed controls all wallets and private keys - protect carefully
// All shares are needed to recover the mnemonic seed
const mnemonicBytes = new TextEncoder().encode(mnemonic);
const shares = splitSecret(mnemonicBytes, 3);

// Distribute shares to different secure locations
// Each share can be encrypted using ModeOfOperation.ctr before distribution
// All 3 shares needed to recover the mnemonic seed

const recovered = combineShares(shares);
const recoveredMnemonic = new TextDecoder().decode(recovered);
// The recovered mnemonic seed can restore all wallets and private keys
```

## API Integration

Here's how to integrate start-kms into a backend service:

```typescript
import { KeyManager, createMnemonic } from 'start-kms';

class WalletService {
  private manager = new KeyManager();
  private getPassphrase = () =>
    new TextEncoder().encode(process.env.MASTER_KEY!);

  async createWallet(userId: string) {
    // SECURITY: Generate mnemonic (recovery seed phrase)
    // The mnemonic seed is encrypted using ModeOfOperation.ctr before storage
    const mnemonic = createMnemonic();
    // All private keys derived from this mnemonic are also encrypted
    await this.manager.createAgent(userId, mnemonic.split(' '), this.getPassphrase);

    // Derive initial addresses
    // SECURITY: Each credential contains an encrypted private key
    // Private keys are encrypted using AES-256-CTR (ModeOfOperation.ctr) before storage
    const addresses = [];
    for (let i = 0; i < 3; i++) {
      const cred = await this.manager.deriveCredential(userId, i);
      // cred contains: address (public), publicKey, encryptedPrivateKey
      addresses.push(cred.address);
    }

    // SECURITY: The mnemonic seed should be backed up securely
    // It can restore all wallets, private keys, and funds
    return { userId, addresses, mnemonic };
  }

  async signTransaction(userId: string, address: string, tx: TransactionRequest) {
    return this.manager.signTransaction(userId, tx, address);
  }
}
```

## Automation Workflows

### Batch Transaction Signing

```typescript
const transactions = [
  { to: addr1, value: BigInt(100) },
  { to: addr2, value: BigInt(200) },
  { to: addr3, value: BigInt(300) },
];

const signed = await Promise.all(
  transactions.map((tx, i) =>
    agent.signTransaction({ ...tx, nonce: baseNonce + i }, senderAddress)
  )
);
```

### Scheduled Key Rotation

```typescript
async function rotateKeys(manager: KeyManager, walletId: string) {
  const agent = manager.getAgent(walletId);
  const currentAddresses = agent.getAddresses();

  // Derive new addresses
  const nextIndex = currentAddresses.length;
  for (let i = 0; i < 3; i++) {
    await manager.deriveCredential(walletId, nextIndex + i);
  }

  return agent.getAddresses().slice(-3);
}
```

## Data Processing Pipeline

Encrypt sensitive data before storage:

```typescript
import { secureEncrypt, secureDecrypt } from 'start-kms';

async function processUserData(userData: UserData) {
  // SECURITY: Encrypt sensitive data before storage
  // secureEncrypt uses ModeOfOperation.ctr (AES-256-CTR) to protect data
  // This protects tokens, keys, mnemonics, seeds, private keys, and credentials
  const encrypted = await secureEncrypt(
    new TextEncoder().encode(JSON.stringify(userData.pii)),
    process.env.ENCRYPTION_KEY!
  );

  return {
    ...userData,
    pii: encrypted,
    piiEncrypted: true
  };
}

async function retrieveUserData(stored: StoredData) {
  if (stored.piiEncrypted) {
    const decrypted = await secureDecrypt(stored.pii, process.env.ENCRYPTION_KEY!);
    stored.pii = JSON.parse(new TextDecoder().decode(decrypted));
  }
  return stored;
}
```

## Configuration Options

### KeyManager Options

```typescript
const manager = new KeyManager({
  storage: localStorage,     // Storage backend (localStorage, sessionStorage, or custom)
  autoSave: true            // Automatically save after changes
});
```

### Key Derivation

```typescript
import { deriveEthereumKey } from 'start-kms';

const key = deriveEthereumKey(mnemonic, {
  basePath: "m/44'/60'/0'/0",  // Standard Ethereum path
  addressIndex: 5               // Specific address index
});
```

## Security Considerations

- **Passphrase Management**: Never hardcode passphrases. Use environment variables or secure vaults in production. Passphrases protect encrypted mnemonics (seeds), private keys, and wallet credentials.

- **Mnemonic Protection**: Mnemonics (recovery seed phrases) control entire wallets. They are encrypted using `ModeOfOperation.ctr` (AES-256-CTR) before storage. Store encrypted mnemonics securely.

- **Private Key Security**: Private keys are always encrypted at rest using `ModeOfOperation.ctr`. They are only decrypted temporarily for signing operations, then zeroed from memory.

- **Seed Material**: Seeds (master seed material) derived from mnemonics are highly sensitive. They control all derived wallets and private keys. Always encrypt seeds before storage.

- **Token Protection**: API tokens, access tokens, and authentication credentials should be encrypted using `secureEncrypt()` or `encryptString()` before storage.

- **Memory Cleanup**: Call `secureWipe()` on sensitive data when done. Private keys are automatically zeroed after signing operations.

- **Storage Security**: The encrypted data is only as secure as your storage backend. Ensure encrypted mnemonics, seeds, and private keys are stored securely.

- **Backup Testing**: Always test backup restoration before relying on it. Backups contain encrypted mnemonics (seeds) and private keys - verify recovery works.

## Examples

See the `/examples` directory for complete working examples:

- `basic-wallet.ts` - Wallet creation and signing
- `api-key-encryption.ts` - Encrypting API keys and secrets
- `multi-account-management.ts` - Managing multiple wallets
- `backup-recovery.ts` - Backup strategies and recovery
- `express-integration.ts` - Backend API integration

## API Reference

### Core Classes

- `InMemoryKeyAgent` - Main wallet class for key management
- `KeyManager` - Multi-wallet orchestration
- `SecureVault` - Session-based encryption

### Key Derivation

- `createMnemonic()` - Generate BIP-39 mnemonic
- `isValidMnemonic()` - Validate mnemonic phrase
- `deriveEthereumKey()` - Derive keys with BIP-44
- `HDKeyring` - Manage derived key collection

### Encryption

- `encryptString()` / `decryptString()` - Simple string encryption
- `secureEncrypt()` / `secureDecrypt()` - Structured encryption with PBKDF2
- `encryptWithCTR()` / `decryptWithCTR()` - Low-level AES-CTR operations

### Utilities

- `splitSecret()` / `combineShares()` - Secret sharing
- `hexToBytes()` / `bytesToHex()` - Conversion utilities
- `secureWipe()` - Memory cleanup

## License

MIT

## Acknowledgments

This project was inspired by [starknet-kms](https://github.com/teddyjfpender/starknet-kms), an exploratory key management system for the Starknet ecosystem. While start-kms takes a different approach focused on EVM chains and simplicity, the architectural patterns and security considerations from that project provided valuable guidance.
# start-kms
