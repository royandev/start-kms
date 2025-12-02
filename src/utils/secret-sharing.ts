import aesjs from 'aes-js';
import { randomBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';

/**
 * Simple secret sharing implementation using XOR-based splitting.
 * For production use, consider Shamir's Secret Sharing.
 */

export interface SecretShare {
  index: number;
  data: Uint8Array;
}

/**
 * Splits a secret into n shares where all shares are needed to reconstruct.
 */
export function splitSecret(secret: Uint8Array, numShares: number): SecretShare[] {
  if (numShares < 2) {
    throw new Error('Need at least 2 shares');
  }

  const shares: SecretShare[] = [];

  let accumulated = new Uint8Array(secret.length);
  accumulated.set(secret);

  for (let i = 0; i < numShares - 1; i++) {
    const share = randomBytes(secret.length);
    shares.push({ index: i, data: share });

    for (let j = 0; j < secret.length; j++) {
      accumulated[j] ^= share[j];
    }
  }

  shares.push({ index: numShares - 1, data: accumulated });

  return shares;
}

/**
 * Reconstructs a secret from all shares.
 */
export function combineShares(shares: SecretShare[]): Uint8Array {
  if (shares.length < 2) {
    throw new Error('Need at least 2 shares to reconstruct');
  }

  const length = shares[0].data.length;
  const result = new Uint8Array(length);

  for (const share of shares) {
    if (share.data.length !== length) {
      throw new Error('All shares must be the same length');
    }

    for (let i = 0; i < length; i++) {
      result[i] ^= share.data[i];
    }
  }

  return result;
}

/**
 * Encrypts each share with a unique key derived from a passphrase.
 */
export function encryptShares(
  shares: SecretShare[],
  passphrase: string
): SecretShare[] {
  const baseKey = sha256(new TextEncoder().encode(passphrase));

  return shares.map((share, index) => {
    const keyInput = new Uint8Array(baseKey.length + 4);
    keyInput.set(baseKey, 0);
    keyInput[baseKey.length] = (index >> 24) & 0xff;
    keyInput[baseKey.length + 1] = (index >> 16) & 0xff;
    keyInput[baseKey.length + 2] = (index >> 8) & 0xff;
    keyInput[baseKey.length + 3] = index & 0xff;

    const shareKey = sha256(keyInput);
    const token = Array.from(shareKey);

    const iv = randomBytes(16);
    const aesCtr = new aesjs.ModeOfOperation.ctr(token);
    const encrypted = aesCtr.encrypt(share.data);

    const result = new Uint8Array(16 + encrypted.length);
    result.set(iv, 0);
    result.set(encrypted, 16);

    return { index: share.index, data: result };
  });
}

/**
 * Decrypts shares that were encrypted with encryptShares.
 */
export function decryptShares(
  encryptedShares: SecretShare[],
  passphrase: string
): SecretShare[] {
  const baseKey = sha256(new TextEncoder().encode(passphrase));

  return encryptedShares.map((share) => {
    const keyInput = new Uint8Array(baseKey.length + 4);
    keyInput.set(baseKey, 0);
    keyInput[baseKey.length] = (share.index >> 24) & 0xff;
    keyInput[baseKey.length + 1] = (share.index >> 16) & 0xff;
    keyInput[baseKey.length + 2] = (share.index >> 8) & 0xff;
    keyInput[baseKey.length + 3] = share.index & 0xff;

    const shareKey = sha256(keyInput);
    const token = Array.from(shareKey);

    const iv = share.data.slice(0, 16);
    const ciphertext = share.data.slice(16);

    const aesCtr = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(iv));
    const decrypted = new Uint8Array(aesCtr.decrypt(ciphertext));

    return { index: share.index, data: decrypted };
  });
}
