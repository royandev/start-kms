export type HexString = `0x${string}`;

export interface KeyCredential {
  id: string;
  address: string;
  publicKey: string;
  encryptedPrivateKey: Uint8Array;
  derivationPath: string;
  createdAt: number;
}

export interface SerializableKeyAgentData {
  version: number;
  encryptedSeed: Uint8Array;
  credentials: KeyCredential[];
  metadata: KeyAgentMetadata;
}

export interface KeyAgentMetadata {
  createdAt: number;
  lastModified: number;
  name?: string;
  description?: string;
}

export interface SigningResult {
  signature: string;
  messageHash: string;
  address: string;
}

export interface TransactionRequest {
  to: string;
  value?: bigint;
  data?: string;
  nonce?: number;
  gasLimit?: bigint;
  gasPrice?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  chainId?: number;
}

export interface SignedTransaction {
  rawTransaction: string;
  hash: string;
}

export type GetPassphrase = () => Uint8Array;

export enum KeyAgentType {
  InMemory = 'InMemory',
  Encrypted = 'Encrypted'
}
