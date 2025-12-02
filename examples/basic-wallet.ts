/**
 * Basic Wallet Example
 *
 * Demonstrates how to create a wallet, derive addresses, and sign transactions.
 */

import {
  InMemoryKeyAgent,
  createMnemonic
} from '../src/index.js';

async function main() {
  // SECURITY: Generate a new mnemonic (recovery seed phrase)
  // The mnemonic is the master seed that controls all wallets and private keys
  // Store mnemonics securely - they can restore entire wallets
  const mnemonic = createMnemonic();
  console.log('Generated mnemonic:', mnemonic);

  // SECURITY: Create a passphrase getter - in production, this would prompt the user
  // Never hardcode passphrases - they protect encrypted private keys and seeds
  // The passphrase encrypts the mnemonic seed and all derived private keys
  const getPassphrase = () => new TextEncoder().encode('my-secure-passphrase');

  // Create a new key agent - this encrypts the mnemonic seed internally
  // The mnemonic seed is encrypted using ModeOfOperation.ctr before storage
  const agent = await InMemoryKeyAgent.create(
    mnemonic.split(' '),
    getPassphrase
  );

  // Derive the first few addresses
  // SECURITY: Each credential contains an encrypted private key
  // Private keys are encrypted using AES-256-CTR before storage
  // The public key and address are derived from the private key
  console.log('\nDeriving addresses...');
  for (let i = 0; i < 3; i++) {
    const credential = await agent.deriveCredential(i);
    // credential contains: address (public), publicKey, encryptedPrivateKey
    // The private key is encrypted - never expose encryptedPrivateKey
    console.log(`Address ${i}: ${credential.address}`);
  }

  // Get the first address
  const addresses = agent.getAddresses();
  const primaryAddress = addresses[0];

  // Sign a message
  // SECURITY: This decrypts the private key, signs, then zeros it from memory
  // The private key is only decrypted temporarily for signing operations
  console.log('\nSigning a message...');
  const message = 'Hello, Ethereum!';
  const signature = await agent.signMessage(message, primaryAddress);
  // The private key was automatically zeroed from memory after signing
  console.log('Message:', message);
  console.log('Signature:', signature.signature);

  // Sign a transaction (example - won't be broadcast)
  console.log('\nSigning a transaction...');
  const tx = {
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f1b234',
    value: BigInt('1000000000000000000'), // 1 ETH
    chainId: 1,
    nonce: 0,
    gasLimit: BigInt(21000),
    maxFeePerGas: BigInt('20000000000'),
    maxPriorityFeePerGas: BigInt('1000000000')
  };

  const signedTx = await agent.signTransaction(tx, primaryAddress);
  console.log('Transaction hash:', signedTx.hash);
  console.log('Raw transaction:', signedTx.rawTransaction.slice(0, 100) + '...');

  // Export serializable data for storage
  // SECURITY: This exports encrypted data including:
  // - encryptedSeed: The encrypted mnemonic (recovery seed phrase)
  // - credentials: Array with encrypted private keys for each wallet
  // All sensitive data (mnemonics, seeds, private keys) is already encrypted
  const exportedData = agent.exportSerializableData();
  console.log('\nExported data version:', exportedData.version);
  console.log('Number of credentials:', exportedData.credentials.length);
  // Each credential contains encryptedPrivateKey - safe to store when encrypted
}

main().catch(console.error);
