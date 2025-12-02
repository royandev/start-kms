// Core exports
export { KeyAgent, InMemoryKeyAgent } from './core/KeyAgent.js';
export { KeyManager, type KeyManagerConfig, type StoredData } from './core/KeyManager.js';

// Key derivation exports
export {
  createMnemonic,
  isValidMnemonic,
  deriveMasterKey,
  publicKeyToAddress,
  deriveKeyAtPath,
  deriveEthereumKey,
  deriveMultipleKeys,
  HDKeyring,
  type DerivedKey,
  type KeyDerivationOptions
} from './keys/index.js';

// Encryption exports
export {
  deriveKeyFromPassphrase,
  encryptWithCTR,
  decryptWithCTR,
  encryptString,
  decryptString,
  createFixedCounterEncryptor,
  deriveSecureKey,
  secureEncrypt,
  secureDecrypt,
  SecureVault,
  type EncryptedPayload
} from './encryption/index.js';

// Utility exports
export {
  generateRandomKey,
  hexToBytes,
  bytesToHex,
  hash,
  constantTimeEqual,
  secureWipe,
  createAuthTag,
  encryptWithAuth,
  decryptWithAuth,
  deriveSubKeys,
  splitSecret,
  combineShares,
  encryptShares,
  decryptShares,
  type SecretShare
} from './utils/index.js';

// Type exports
export {
  type HexString,
  type KeyCredential,
  type SerializableKeyAgentData,
  type KeyAgentMetadata,
  type SigningResult,
  type TransactionRequest,
  type SignedTransaction,
  type GetPassphrase,
  KeyAgentType
} from './keys/types.js';
