# Security Guide

This document outlines security best practices when using start-kms.

## Encryption Details

### AES-256-CTR Mode

start-kms uses AES-256 in Counter (CTR) mode for symmetric encryption. CTR mode provides:

- **Stream cipher behavior**: Encrypts data of any length without padding
- **Parallelizable**: Encryption/decryption can be performed in parallel
- **Random access**: Any block can be decrypted independently

```typescript
import aesjs from 'aes-js';

// Basic CTR encryption pattern used internally
const token = Array.from(key);  // 32-byte key
const aesCtr = new aesjs.ModeOfOperation.ctr(token);
const encrypted = aesCtr.encrypt(plaintext);
```

### Key Derivation

For passphrase-based encryption, keys are derived using PBKDF2-SHA256:

- **100,000 iterations** by default
- **32-byte derived key** (256 bits)
- **Random 16-byte salt** for each encryption

```typescript
import { deriveSecureKey } from 'start-kms';

const key = await deriveSecureKey(passphrase, salt);
```

## Secure Memory Handling

### Clearing Sensitive Data

Always clear sensitive data from memory when no longer needed:

```typescript
import { secureWipe } from 'start-kms';

const privateKey = deriveKey(...);
try {
  // Use the key
  await signTransaction(privateKey);
} finally {
  secureWipe(privateKey);  // Overwrite with zeros
}
```

### Vault Pattern

Use `SecureVault` for session-based operations:

```typescript
const vault = new SecureVault();

// Unlock at session start
await vault.unlock(passphrase, salt);

// Perform operations
const encrypted = vault.encrypt(data);

// Lock when done - clears key from memory
vault.lock();
```

## Passphrase Management

### Do Not Hardcode

Never hardcode passphrases in source code:

```typescript
// Bad
const getPassphrase = () => new TextEncoder().encode('hardcoded-secret');

// Good - from environment
const getPassphrase = () => new TextEncoder().encode(process.env.KMS_PASSPHRASE!);

// Good - from secure input
const getPassphrase = () => promptUserForPassphrase();
```

### Environment Variables

```bash
# Use strong, random passphrases
export KMS_PASSPHRASE=$(openssl rand -base64 32)
```

### Secret Management Services

In production, consider using:

- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- Google Secret Manager

```typescript
import { SecretsManager } from '@aws-sdk/client-secrets-manager';

const client = new SecretsManager();

async function getPassphrase(): Promise<Uint8Array> {
  const response = await client.getSecretValue({
    SecretId: 'kms-master-passphrase'
  });
  return new TextEncoder().encode(response.SecretString!);
}
```

## Storage Security

### Encrypted at Rest

Always encrypt wallet data before storing:

```typescript
const data = agent.exportSerializableData();
const encrypted = await secureEncrypt(
  new TextEncoder().encode(JSON.stringify(data)),
  process.env.STORAGE_KEY!
);

// Store encrypted.salt, encrypted.iv, encrypted.data
```

### Access Controls

- Restrict file permissions: `chmod 600 wallet-data.enc`
- Use database-level encryption
- Implement application-level access control

### Backup Security

- Encrypt backups with a different key than primary storage
- Store backup keys separately from backups
- Test backup restoration regularly

```typescript
const backupKey = process.env.BACKUP_ENCRYPTION_KEY!;  // Different from storage key
const backup = await secureEncrypt(walletData, backupKey);
```

## Network Security

### Transport Encryption

Always use HTTPS/TLS for API communications:

```typescript
// Express with HTTPS
import https from 'https';
import fs from 'fs';

https.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt')
}, app).listen(443);
```

### Rate Limiting

Protect signing endpoints from abuse:

```typescript
import rateLimit from 'express-rate-limit';

const signingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100  // 100 requests per window
});

app.use('/api/sign', signingLimiter);
```

## Audit Logging

Log all sensitive operations:

```typescript
async function signTransaction(walletId: string, tx: TransactionRequest) {
  const startTime = Date.now();

  try {
    const result = await manager.signTransaction(walletId, tx, address);

    logger.info('Transaction signed', {
      walletId,
      address,
      txHash: result.hash,
      duration: Date.now() - startTime
    });

    return result;
  } catch (error) {
    logger.error('Transaction signing failed', {
      walletId,
      error: error.message,
      duration: Date.now() - startTime
    });
    throw error;
  }
}
```

## Common Vulnerabilities

### Timing Attacks

Use constant-time comparison for sensitive data:

```typescript
import { constantTimeEqual } from 'start-kms';

// Good - constant time
if (constantTimeEqual(providedTag, expectedTag)) {
  // Valid
}

// Bad - variable time
if (providedTag === expectedTag) {  // Don't do this
  // Valid
}
```

### Side Channel Attacks

- Don't log sensitive data
- Clear variables after use
- Be cautious with error messages

```typescript
// Bad - leaks information
throw new Error(`Invalid key for address ${address}`);

// Good - generic error
throw new Error('Authentication failed');
```

## Checklist

Before deploying to production:

- [ ] Passphrases loaded from secure source (not hardcoded)
- [ ] All storage encrypted at rest
- [ ] HTTPS enabled for all endpoints
- [ ] Rate limiting configured
- [ ] Audit logging enabled
- [ ] Backup encryption keys stored separately
- [ ] Memory cleared after sensitive operations
- [ ] Error messages don't leak sensitive information
- [ ] Access controls implemented
- [ ] Regular security audits scheduled
