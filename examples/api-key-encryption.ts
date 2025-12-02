/**
 * API Key Encryption Example
 *
 * Demonstrates how to securely store and retrieve API keys and secrets.
 */

import {
  secureEncrypt,
  secureDecrypt,
  SecureVault,
  encryptString,
  decryptString
} from '../src/index.js';
import { randomBytes } from '@noble/hashes/utils';

interface ApiCredentials {
  apiKey: string;
  apiSecret: string;
  endpoint: string;
}

async function main() {
  console.log('=== API Key Encryption Demo ===\n');

  // Simple string encryption
  // SECURITY: Encrypt API tokens and keys using AES-256-CTR
  // Tokens grant access to services - encryption protects them at rest
  console.log('1. Simple string encryption:');
  const apiKey = 'sk_live_abc123xyz789';
  const passphrase = 'my-master-password';

  // encryptString uses ModeOfOperation.ctr internally to protect tokens
  // This encrypts API keys, tokens, and other sensitive credentials
  const encrypted = encryptString(apiKey, passphrase);
  console.log('Original:', apiKey);
  console.log('Encrypted:', encrypted);

  // Decrypt tokens only when needed - never log decrypted values
  const decrypted = decryptString(encrypted, passphrase);
  console.log('Decrypted:', decrypted);
  console.log('Match:', apiKey === decrypted);

  // Structured credentials encryption
  // SECURITY: Encrypt multiple tokens and secrets together
  // API keys, secrets, and tokens must be encrypted before storage
  console.log('\n2. Structured credentials:');
  const credentials: ApiCredentials = {
    apiKey: 'pk_test_123456',
    apiSecret: 'sk_test_secret_key_here',
    endpoint: 'https://api.example.com/v1'
  };

  const credentialsBytes = new TextEncoder().encode(JSON.stringify(credentials));
  // secureEncrypt uses ModeOfOperation.ctr to protect tokens and secrets
  // This encrypts API keys, tokens, and authentication credentials
  const encryptedPayload = await secureEncrypt(credentialsBytes, passphrase);

  console.log('Encrypted payload:', {
    salt: encryptedPayload.salt.slice(0, 16) + '...',
    iv: encryptedPayload.iv.slice(0, 16) + '...',
    data: encryptedPayload.data.slice(0, 32) + '...'
  });

  const decryptedBytes = await secureDecrypt(encryptedPayload, passphrase);
  const decryptedCredentials = JSON.parse(
    new TextDecoder().decode(decryptedBytes)
  ) as ApiCredentials;

  console.log('Decrypted credentials:', decryptedCredentials);

  // Using SecureVault for session-based encryption
  // SECURITY: Session-based vault for temporary encryption of tokens and secrets
  // The vault uses ModeOfOperation.ctr to encrypt sensitive data
  console.log('\n3. SecureVault session:');
  const vault = new SecureVault();
  const salt = randomBytes(16);

  await vault.unlock(passphrase, salt);
  console.log('Vault unlocked:', vault.isUnlocked());

  // Encrypt sensitive tokens and credentials in the vault
  // This protects API keys, database URLs, and other secrets
  const sensitiveData = new TextEncoder().encode('DATABASE_URL=postgres://user:pass@host/db');
  // vault.encrypt uses ModeOfOperation.ctr internally
  const vaultEncrypted = vault.encrypt(sensitiveData);
  console.log('Vault encrypted length:', vaultEncrypted.length);

  // Decrypt tokens only when needed - vault clears keys when locked
  const vaultDecrypted = vault.decrypt(vaultEncrypted);
  console.log('Vault decrypted:', new TextDecoder().decode(vaultDecrypted));

  // SECURITY: Lock vault to clear encryption keys from memory
  vault.lock();
  console.log('Vault locked:', !vault.isUnlocked());

  // Multiple secrets management
  // SECURITY: Encrypt multiple tokens and API keys separately
  // Each token/secret is encrypted using ModeOfOperation.ctr
  console.log('\n4. Multiple secrets:');
  const secrets = {
    stripe: 'sk_live_stripe_key',
    aws: 'AKIAIOSFODNN7EXAMPLE',
    github: 'ghp_xxxxxxxxxxxxxxxxxxxx'
  };

  // Encrypt each token/secret individually for granular access control
  // encryptString uses ModeOfOperation.ctr to protect each token
  const encryptedSecrets: Record<string, string> = {};
  for (const [name, secret] of Object.entries(secrets)) {
    encryptedSecrets[name] = encryptString(secret, passphrase);
  }

  console.log('Encrypted secrets:');
  for (const [name, encrypted] of Object.entries(encryptedSecrets)) {
    console.log(`  ${name}: ${encrypted.slice(0, 40)}...`);
  }

  // Verify all can be decrypted
  console.log('\nDecryption verification:');
  for (const [name, encrypted] of Object.entries(encryptedSecrets)) {
    const original = decryptString(encrypted, passphrase);
    console.log(`  ${name}: ${original === secrets[name] ? '✓' : '✗'}`);
  }
}

main().catch(console.error);
