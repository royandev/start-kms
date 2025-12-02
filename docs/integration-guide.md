# Integration Guide

This guide covers common integration patterns for start-kms in different environments.

## Node.js Backend

### Express.js Setup

```typescript
import express from 'express';
import { KeyManager, createMnemonic } from 'start-kms';

const app = express();
app.use(express.json());

const manager = new KeyManager();
const getPassphrase = () => new TextEncoder().encode(process.env.KMS_PASSPHRASE!);

app.post('/api/wallets', async (req, res) => {
  try {
    const { walletId } = req.body;
    const mnemonic = createMnemonic();

    await manager.createAgent(walletId, mnemonic.split(' '), getPassphrase);

    const cred = await manager.deriveCredential(walletId, 0);

    res.json({
      walletId,
      address: cred.address,
      mnemonic // Return only on creation for backup
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/wallets/:id/sign', async (req, res) => {
  try {
    const { message, address } = req.body;
    const result = await manager.signMessage(req.params.id, message, address);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

### Fastify Setup

```typescript
import Fastify from 'fastify';
import { KeyManager, createMnemonic } from 'start-kms';

const fastify = Fastify();
const manager = new KeyManager();

fastify.post('/wallets', async (request, reply) => {
  const { walletId } = request.body as { walletId: string };
  const mnemonic = createMnemonic();

  await manager.createAgent(
    walletId,
    mnemonic.split(' '),
    () => new TextEncoder().encode(process.env.KMS_PASSPHRASE!)
  );

  return { walletId, mnemonic };
});
```

## Browser Environment

### React Hook

```typescript
import { useState, useCallback } from 'react';
import { InMemoryKeyAgent, createMnemonic } from 'start-kms';

export function useWallet() {
  const [agent, setAgent] = useState<InMemoryKeyAgent | null>(null);
  const [addresses, setAddresses] = useState<string[]>([]);

  const createWallet = useCallback(async (passphrase: string) => {
    const mnemonic = createMnemonic();
    const getPassphrase = () => new TextEncoder().encode(passphrase);

    const newAgent = await InMemoryKeyAgent.create(
      mnemonic.split(' '),
      getPassphrase
    );

    const cred = await newAgent.deriveCredential(0);

    setAgent(newAgent);
    setAddresses([cred.address]);

    return { mnemonic, address: cred.address };
  }, []);

  const signMessage = useCallback(async (message: string) => {
    if (!agent || addresses.length === 0) {
      throw new Error('Wallet not initialized');
    }
    return agent.signMessage(message, addresses[0]);
  }, [agent, addresses]);

  return { createWallet, signMessage, addresses };
}
```

### Vue Composable

```typescript
import { ref } from 'vue';
import { InMemoryKeyAgent, createMnemonic } from 'start-kms';

export function useWallet() {
  const agent = ref<InMemoryKeyAgent | null>(null);
  const addresses = ref<string[]>([]);

  async function createWallet(passphrase: string) {
    const mnemonic = createMnemonic();
    const getPassphrase = () => new TextEncoder().encode(passphrase);

    agent.value = await InMemoryKeyAgent.create(
      mnemonic.split(' '),
      getPassphrase
    );

    const cred = await agent.value.deriveCredential(0);
    addresses.value = [cred.address];

    return { mnemonic, address: cred.address };
  }

  return { createWallet, agent, addresses };
}
```

## Database Storage

### PostgreSQL with Encrypted Storage

```typescript
import { Pool } from 'pg';
import { secureEncrypt, secureDecrypt } from 'start-kms';

const pool = new Pool();

async function saveWalletData(userId: string, data: any) {
  const encrypted = await secureEncrypt(
    new TextEncoder().encode(JSON.stringify(data)),
    process.env.DB_ENCRYPTION_KEY!
  );

  await pool.query(
    'INSERT INTO wallets (user_id, salt, iv, data) VALUES ($1, $2, $3, $4)',
    [userId, encrypted.salt, encrypted.iv, encrypted.data]
  );
}

async function loadWalletData(userId: string) {
  const result = await pool.query(
    'SELECT salt, iv, data FROM wallets WHERE user_id = $1',
    [userId]
  );

  if (result.rows.length === 0) return null;

  const { salt, iv, data } = result.rows[0];
  const decrypted = await secureDecrypt(
    { salt, iv, data, version: 1 },
    process.env.DB_ENCRYPTION_KEY!
  );

  return JSON.parse(new TextDecoder().decode(decrypted));
}
```

### Redis Caching

```typescript
import Redis from 'ioredis';
import { encryptString, decryptString } from 'start-kms';

const redis = new Redis();

async function cacheSignature(key: string, signature: string, ttl: number) {
  const encrypted = encryptString(signature, process.env.CACHE_KEY!);
  await redis.setex(key, ttl, encrypted);
}

async function getCachedSignature(key: string) {
  const encrypted = await redis.get(key);
  if (!encrypted) return null;
  return decryptString(encrypted, process.env.CACHE_KEY!);
}
```

## Message Queue Integration

### Bull Queue Worker

```typescript
import Queue from 'bull';
import { KeyManager } from 'start-kms';

const signQueue = new Queue('transaction-signing');
const manager = new KeyManager();

signQueue.process(async (job) => {
  const { walletId, address, transaction } = job.data;

  const signed = await manager.signTransaction(walletId, transaction, address);

  return { hash: signed.hash, rawTransaction: signed.rawTransaction };
});

// Add job
await signQueue.add({
  walletId: 'user-123',
  address: '0x...',
  transaction: { to: '0x...', value: BigInt(1000) }
});
```

## Environment Configuration

### Required Environment Variables

```bash
# Master encryption passphrase
KMS_PASSPHRASE=your-secure-master-passphrase

# Database encryption key
DB_ENCRYPTION_KEY=your-database-encryption-key

# Optional: Different keys for different purposes
BACKUP_ENCRYPTION_KEY=your-backup-key
CACHE_ENCRYPTION_KEY=your-cache-key
```

### Docker Configuration

```dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY dist ./dist

ENV NODE_ENV=production

CMD ["node", "dist/server.js"]
```

```yaml
# docker-compose.yml
services:
  kms-service:
    build: .
    environment:
      - KMS_PASSPHRASE=${KMS_PASSPHRASE}
      - DB_ENCRYPTION_KEY=${DB_ENCRYPTION_KEY}
    secrets:
      - kms_passphrase

secrets:
  kms_passphrase:
    external: true
```

## Error Handling

```typescript
import { InMemoryKeyAgent, createMnemonic } from 'start-kms';

class WalletError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'WalletError';
  }
}

async function createWalletSafe(passphrase: string) {
  try {
    const mnemonic = createMnemonic();
    const agent = await InMemoryKeyAgent.create(
      mnemonic.split(' '),
      () => new TextEncoder().encode(passphrase)
    );
    return { success: true, agent, mnemonic };
  } catch (error) {
    if (error.message.includes('Invalid mnemonic')) {
      throw new WalletError('Failed to generate valid mnemonic', 'INVALID_MNEMONIC');
    }
    throw new WalletError('Wallet creation failed', 'CREATION_FAILED');
  }
}
```

## Testing

```typescript
import { InMemoryKeyAgent, createMnemonic } from 'start-kms';

describe('Wallet Operations', () => {
  const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const getPassphrase = () => new TextEncoder().encode('test-passphrase');

  let agent: InMemoryKeyAgent;

  beforeEach(async () => {
    agent = await InMemoryKeyAgent.create(
      TEST_MNEMONIC.split(' '),
      getPassphrase
    );
  });

  it('should derive deterministic addresses', async () => {
    const cred = await agent.deriveCredential(0);
    expect(cred.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
  });

  it('should sign messages', async () => {
    const cred = await agent.deriveCredential(0);
    const result = await agent.signMessage('test', cred.address);
    expect(result.signature).toBeDefined();
  });
});
```
