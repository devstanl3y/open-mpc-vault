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
  /** BIP-39 mnemonic; empty string for raw private-key imports. */
  mnemonic: string;
  /** Raw secret that was split: BIP-39 entropy or a 32-byte private key. */
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
  /** Hex ciphertext. */
  encrypted: string;
  /** Hex IV. */
  iv: string;
  /** Hex GCM authentication tag. */
  tag: string;
  /** Hex PBKDF2 salt. Absent only in the legacy `salt:ciphertext` format. */
  salt?: string;
}
