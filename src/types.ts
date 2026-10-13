export enum ChainType {
  ETHEREUM = 'ETHEREUM',
  SOLANA = 'SOLANA',
  BITCOIN = 'BITCOIN',
}

export enum CurveType {
  SECP256K1 = 'SECP256K1',
  ED25519 = 'ED25519',
}

export interface MpcSeedShards {
  shardA: Buffer;
  shardB: Buffer;
  mnemonic: string;
  entropy: Buffer;
}

export interface DerivedWallet {
  privateKey: Buffer;
  publicKey: Buffer;
  address: string;
  chainType: ChainType;
  derivationPath: string;
  curveType: CurveType;
}

export interface EncryptedShard {
  encrypted: string;
  iv: string;
  tag: string;
  salt?: string;
}

export interface MpcConfig {
  serverSecret?: string;
  serverSalt?: string;
  pbkdf2Iterations?: number;
}
