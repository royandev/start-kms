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
  deriveSubKeys
} from './crypto-helpers.js';

export {
  splitSecret,
  combineShares,
  encryptShares,
  decryptShares,
  type SecretShare
} from './secret-sharing.js';
