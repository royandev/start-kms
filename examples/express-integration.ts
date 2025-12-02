/**
 * Express.js Integration Example
 *
 * Shows how to integrate start-kms into a backend API service.
 * This is a conceptual example - requires express to be installed.
 */

import {
  KeyManager,
  InMemoryKeyAgent,
  createMnemonic,
  secureEncrypt,
  secureDecrypt,
  type TransactionRequest
} from '../src/index.js';

// Types for the API
interface SignMessageRequest {
  walletId: string;
  address: string;
  message: string;
}

interface SignTransactionRequest {
  walletId: string;
  address: string;
  transaction: TransactionRequest;
}

interface CreateWalletResponse {
  walletId: string;
  addresses: string[];
  mnemonic?: string; // Only returned on creation, should be backed up
}

/**
 * WalletService manages wallets for an application.
 * In production, passphrases would come from a secure source like HSM or environment.
 */
class WalletService {
  private manager: KeyManager;
  private masterPassphrase: string;

  constructor(masterPassphrase: string) {
    this.masterPassphrase = masterPassphrase;
    this.manager = new KeyManager();
  }

  private getPassphrase = () => {
    return new TextEncoder().encode(this.masterPassphrase);
  };

  async createWallet(
    walletId: string,
    mnemonic?: string
  ): Promise<CreateWalletResponse> {
    // SECURITY: Generate or use provided mnemonic (recovery seed phrase)
    // The mnemonic seed controls all wallets and private keys - protect carefully
    const mnemonicPhrase = mnemonic || createMnemonic();

    // The mnemonic seed is encrypted using ModeOfOperation.ctr before storage
    // All private keys derived from this seed are also encrypted
    await this.manager.createAgent(
      walletId,
      mnemonicPhrase.split(' '),
      this.getPassphrase
    );

    // Derive first 3 addresses
    // SECURITY: Each credential contains an encrypted private key
    // Private keys are encrypted using AES-256-CTR before storage
    const addresses: string[] = [];
    for (let i = 0; i < 3; i++) {
      const cred = await this.manager.deriveCredential(walletId, i);
      // cred contains: address (public), publicKey, encryptedPrivateKey
      addresses.push(cred.address);
    }

    return {
      walletId,
      addresses,
      mnemonic: mnemonic ? undefined : mnemonicPhrase
    };
  }

  async importWallet(
    walletId: string,
    mnemonic: string
  ): Promise<CreateWalletResponse> {
    return this.createWallet(walletId, mnemonic);
  }

  async deriveAddress(walletId: string, index: number): Promise<string> {
    const cred = await this.manager.deriveCredential(walletId, index);
    return cred.address;
  }

  async signMessage(
    walletId: string,
    address: string,
    message: string
  ) {
    // SECURITY: Private key is decrypted temporarily, used to sign, then zeroed
    // The private key is never stored in plaintext - always encrypted at rest
    return this.manager.signMessage(walletId, message, address);
  }

  async signTransaction(
    walletId: string,
    address: string,
    tx: TransactionRequest
  ) {
    // SECURITY: Private key is decrypted temporarily for signing, then cleared
    // All private keys remain encrypted until needed for signing operations
    return this.manager.signTransaction(walletId, tx, address);
  }

  listWallets(): string[] {
    return this.manager.listAgents();
  }

  getAddresses(walletId: string): string[] {
    const agent = this.manager.getAgent(walletId);
    return agent?.getAddresses() || [];
  }
}

// Example API routes (pseudo-code, would need express)
async function main() {
  console.log('=== Express Integration Demo ===\n');

  // Initialize service with master passphrase from environment
  // SECURITY: Never hardcode passphrases - they encrypt mnemonics and private keys
  // The passphrase protects encrypted wallet data (mnemonics, seeds, private keys)
  const service = new WalletService(
    process.env.MASTER_PASSPHRASE || 'demo-passphrase'
  );

  // Simulate API calls

  // POST /wallets - Create new wallet
  // SECURITY: The mnemonic seed is encrypted using ModeOfOperation.ctr
  // All private keys derived from this mnemonic are also encrypted
  console.log('Creating wallet...');
  const wallet1 = await service.createWallet('user-123');
  // The mnemonic seed phrase should be backed up securely - it can restore the wallet
  console.log('Created wallet:', {
    walletId: wallet1.walletId,
    addresses: wallet1.addresses,
    mnemonicWords: wallet1.mnemonic?.split(' ').length
  });

  // POST /wallets/import - Import existing wallet
  // SECURITY: Importing mnemonic seed - it's encrypted using ModeOfOperation.ctr
  // The mnemonic seed controls all wallets and private keys - handle with care
  console.log('\nImporting wallet...');
  const testMnemonic = createMnemonic();
  // The mnemonic seed is encrypted before storage
  const wallet2 = await service.importWallet('user-456', testMnemonic);
  console.log('Imported wallet:', {
    walletId: wallet2.walletId,
    addresses: wallet2.addresses
  });

  // GET /wallets - List all wallets
  console.log('\nListing wallets:', service.listWallets());

  // GET /wallets/:id/addresses - Get addresses
  console.log('\nAddresses for user-123:', service.getAddresses('user-123'));

  // POST /wallets/:id/addresses - Derive new address
  console.log('\nDeriving new address...');
  const newAddr = await service.deriveAddress('user-123', 3);
  console.log('New address:', newAddr);

  // POST /wallets/:id/sign-message
  console.log('\nSigning message...');
  const signResult = await service.signMessage(
    'user-123',
    wallet1.addresses[0],
    'Please sign this message to verify ownership'
  );
  console.log('Signature:', signResult.signature.slice(0, 50) + '...');

  // POST /wallets/:id/sign-transaction
  console.log('\nSigning transaction...');
  const txResult = await service.signTransaction(
    'user-123',
    wallet1.addresses[0],
    {
      to: '0x742d35Cc6634C0532925a3b844Bc9e7595f1b234',
      value: BigInt(1000000000000000),
      chainId: 1,
      nonce: 0,
      gasLimit: BigInt(21000),
      maxFeePerGas: BigInt(20000000000),
      maxPriorityFeePerGas: BigInt(1000000000)
    }
  );
  console.log('Transaction hash:', txResult.hash);

  console.log('\n=== Express Route Examples ===');
  console.log(`
// Example Express routes:

app.post('/wallets', async (req, res) => {
  const { walletId } = req.body;
  const result = await walletService.createWallet(walletId);
  res.json(result);
});

app.post('/wallets/:id/sign-message', async (req, res) => {
  const { address, message } = req.body;
  const result = await walletService.signMessage(
    req.params.id,
    address,
    message
  );
  res.json(result);
});

app.post('/wallets/:id/sign-transaction', async (req, res) => {
  const { address, transaction } = req.body;
  const result = await walletService.signTransaction(
    req.params.id,
    address,
    transaction
  );
  res.json(result);
});
`);
}

main().catch(console.error);
