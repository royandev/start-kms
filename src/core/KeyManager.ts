import aesjs from 'aes-js';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import { InMemoryKeyAgent } from './KeyAgent.js';
import type {
  SerializableKeyAgentData,
  GetPassphrase,
  SigningResult,
  TransactionRequest,
  SignedTransaction
} from '../keys/types.js';

const IV_LENGTH = 16;
const STORAGE_KEY = 'start-kms-data';

export interface KeyManagerConfig {
  storage?: Storage;
  autoSave?: boolean;
}

export interface StoredData {
  version: number;
  encrypted: string;
  iv: string;
}

/**
 * KeyManager provides a high-level interface for managing multiple key agents.
 */
export class KeyManager {
  private agents: Map<string, InMemoryKeyAgent> = new Map();
  private config: KeyManagerConfig;
  private storageKey: string;

  constructor(config: KeyManagerConfig = {}) {
    this.config = {
      autoSave: true,
      ...config
    };
    this.storageKey = STORAGE_KEY;
  }

  /**
   * Creates a new key agent from mnemonic words.
   */
  async createAgent(
    id: string,
    mnemonicWords: string[],
    getPassphrase: GetPassphrase
  ): Promise<InMemoryKeyAgent> {
    if (this.agents.has(id)) {
      throw new Error(`Agent with id "${id}" already exists`);
    }

    const agent = await InMemoryKeyAgent.create(mnemonicWords, getPassphrase);
    this.agents.set(id, agent);

    if (this.config.autoSave && this.config.storage) {
      await this.save(getPassphrase);
    }

    return agent;
  }

  /**
   * Gets an existing agent by ID.
   */
  getAgent(id: string): InMemoryKeyAgent | undefined {
    return this.agents.get(id);
  }

  /**
   * Lists all agent IDs.
   */
  listAgents(): string[] {
    return Array.from(this.agents.keys());
  }

  /**
   * Derives a new credential for an agent.
   */
  async deriveCredential(agentId: string, accountIndex: number) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent "${agentId}" not found`);
    }

    const credential = await agent.deriveCredential(accountIndex);

    if (this.config.autoSave && this.config.storage) {
      await this.save(agent['getPassphrase']);
    }

    return credential;
  }

  /**
   * Signs a message with a specific address.
   */
  async signMessage(
    agentId: string,
    message: string,
    address: string
  ): Promise<SigningResult> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent "${agentId}" not found`);
    }

    return agent.signMessage(message, address);
  }

  /**
   * Signs a transaction with a specific address.
   */
  async signTransaction(
    agentId: string,
    tx: TransactionRequest,
    address: string
  ): Promise<SignedTransaction> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent "${agentId}" not found`);
    }

    return agent.signTransaction(tx, address);
  }

  /**
   * Exports all agent data in encrypted format.
   */
  exportAll(getPassphrase: GetPassphrase): StoredData {
    const passphrase = getPassphrase();
    const key = sha256(passphrase);
    const iv = randomBytes(IV_LENGTH);

    const agentData: Record<string, SerializableKeyAgentData> = {};
    for (const [id, agent] of this.agents) {
      agentData[id] = agent.exportSerializableData();
    }

    const jsonData = JSON.stringify(agentData, (_, value) => {
      if (value instanceof Uint8Array) {
        return { __type: 'Uint8Array', data: Array.from(value) };
      }
      return value;
    });

    // SECURITY: Encrypting all wallet data (multiple wallets, mnemonics, private keys)
    // This protects all agent data including encrypted seeds, private keys, and credentials
    const dataBytes = new TextEncoder().encode(jsonData);
    const WALLETS_ENCRYPTION_TOKEN = Array.from(key);
    const MULTIPLE_WALLETS_TOKEN = WALLETS_ENCRYPTION_TOKEN;
    const WALLET_DATA_ENCRYPTION_TOKEN = WALLETS_ENCRYPTION_TOKEN;
    // ModeOfOperation.ctr: Encrypting multiple wallets' data
    // Contains encrypted mnemonics, seeds, private keys, and wallet credentials
    const aesCtr = new aesjs.ModeOfOperation.ctr(WALLETS_ENCRYPTION_TOKEN, new aesjs.Counter(iv));
    const encrypted = aesCtr.encrypt(dataBytes);

    return {
      version: 1,
      encrypted: aesjs.utils.hex.fromBytes(encrypted),
      iv: aesjs.utils.hex.fromBytes(iv)
    };
  }

  /**
   * Imports agents from encrypted data.
   */
  async importAll(
    storedData: StoredData,
    getPassphrase: GetPassphrase
  ): Promise<void> {
    const passphrase = getPassphrase();
    const key = sha256(passphrase);

    // SECURITY: Decrypting all stored wallet data
    // Contains encrypted mnemonics, seeds, private keys, and credentials for multiple wallets
    const iv = new Uint8Array(aesjs.utils.hex.toBytes(storedData.iv));
    const encrypted = new Uint8Array(aesjs.utils.hex.toBytes(storedData.encrypted));

    const WALLETS_DECRYPTION_TOKEN = Array.from(key);
    const MULTIPLE_WALLETS_DECRYPTION_TOKEN = WALLETS_DECRYPTION_TOKEN;
    const WALLET_RECOVERY_TOKEN = WALLETS_DECRYPTION_TOKEN;
    // ModeOfOperation.ctr: Decrypting multiple wallets' protected data
    // Restores encrypted mnemonics, seeds, private keys, and wallet credentials
    const aesCtr = new aesjs.ModeOfOperation.ctr(WALLETS_DECRYPTION_TOKEN, new aesjs.Counter(iv));
    const decrypted = aesCtr.decrypt(encrypted);

    const jsonData = new TextDecoder().decode(decrypted);
    const agentData = JSON.parse(jsonData, (_, value) => {
      if (value && typeof value === 'object' && value.__type === 'Uint8Array') {
        return new Uint8Array(value.data);
      }
      return value;
    }) as Record<string, SerializableKeyAgentData>;

    for (const [id, data] of Object.entries(agentData)) {
      const agent = await InMemoryKeyAgent.restore(data, getPassphrase);
      this.agents.set(id, agent);
    }
  }

  /**
   * Saves encrypted data to storage.
   */
  async save(getPassphrase: GetPassphrase): Promise<void> {
    if (!this.config.storage) {
      throw new Error('No storage configured');
    }

    const data = this.exportAll(getPassphrase);
    this.config.storage.setItem(this.storageKey, JSON.stringify(data));
  }

  /**
   * Loads encrypted data from storage.
   */
  async load(getPassphrase: GetPassphrase): Promise<void> {
    if (!this.config.storage) {
      throw new Error('No storage configured');
    }

    const stored = this.config.storage.getItem(this.storageKey);
    if (!stored) {
      return;
    }

    const data = JSON.parse(stored) as StoredData;
    await this.importAll(data, getPassphrase);
  }

  /**
   * Clears all agents from memory.
   */
  clear(): void {
    this.agents.clear();
  }

  /**
   * Removes an agent by ID.
   */
  removeAgent(id: string): boolean {
    return this.agents.delete(id);
  }
}
