# open-mpc-vault

Non-custodial 2-of-2 threshold secret sharing vault and multi-chain hierarchical deterministic (HD) wallet derivation engine for TypeScript and Node.js.

## Overview

`open-mpc-vault` implements a threshold key management model where private key material is never persisted or transmitted in plaintext. Entropy (BIP-39 mnemonic seeds or raw cryptographic secrets) is split using a 2-of-2 Shamir Secret Sharing Scheme (SSSS) evaluated over the secp256k1 prime order field.

- **Shard A (Client)**: Stored by the end-user or client runtime, encrypted using AES-256-GCM with a PBKDF2-stretched key derived from user credentials (PIN, passphrase, or passkey entropy).
- **Shard B (Server)**: Stored server-side, encrypted using AES-256-GCM with server-held secrets and independent per-record salts.
- **Signing Execution**: Neither shard in isolation can derive addresses or sign transactions. During an authorized transaction flow, both shards are decrypted into memory, the original secret is reconstructed via Lagrange polynomial interpolation, the target chain keypair is derived, the payload is signed, and all intermediate buffers are explicitly zeroized.

## Architecture

```
                 [ Master Secret / Entropy (16 or 32 Bytes) ]
                                      |
                     Shamir's Secret Sharing (k=2, n=2)
                                      |
               +----------------------+----------------------+
               |                                             |
          [ Shard A ]                                   [ Shard B ]
               |                                             |
      PBKDF2-HMAC-SHA512                             Server Key Derivation
      AES-256-GCM Encrypted                          AES-256-GCM Encrypted
               |                                             |
       [ Client Device ]                             [ Storage Backend ]
               \                                             /
                \--- Ephemeral Session Authorization -------/
                                      |
                       [ In-Memory Lagrange Reconstruction ]
                                      |
                 +--------------------+--------------------+
                 |                    |                    |
             Ethereum               Solana              Bitcoin
             secp256k1             Ed25519             secp256k1
          BIP-44 (m/44'/60')    BIP-44 (m/44'/501')  BIP-84 (m/84'/0')
```

## Cryptographic Specifications

| Component | Primitive / Standard | Parameters / Details |
|---|---|---|
| Secret Sharing | Shamir Secret Sharing (k=2, n=2) | Field prime $p = 2^{256} - 2^{32} - 977$ |
| Key Derivation (Client) | PBKDF2-HMAC-SHA512 | 100,000 iterations, 16-byte random salt, 32-byte key |
| Shard Encryption | AES-256-GCM (Authenticated Encryption) | 12-byte IV, 16-byte authentication tag |
| Mnemonic Handling | BIP-39 | English wordlist, 128-bit (12 words) or 256-bit (24 words) entropy |
| EVM Derivation | BIP-32 / BIP-44 (secp256k1) | Path `m/44'/60'/account'/0/addressIndex`, Keccak-256 address hashing |
| Solana Derivation | SLIP-0010 / BIP-44 (Ed25519) | Path `m/44'/501'/account'/0'`, Base58 public key encoding |
| Bitcoin Derivation | BIP-84 (Native SegWit / P2WPKH) | Path `m/84'/0'/account'/0/addressIndex`, Bech32 encoding (`bc1...`) |

## Threat Model and Security Guarantees

### Trust Assumptions
- **Client Compromise Only**: An attacker with access to the client storage acquires only encrypted Shard A. Without the user PIN/passphrase and without Shard B, the private key cannot be derived.
- **Server Compromise Only**: An attacker with read access to the database acquires only encrypted Shard B. Without the server encryption secret and without Shard A, the private key cannot be derived.
- **Network Adversary**: Shards are never transmitted in plaintext. Signing sessions require authenticated, end-to-end encrypted transport.

### Memory Safety and Zeroization
Node.js garbage collection does not guarantee immediate overwrite of deallocated memory. To minimize exposure:
- Intermediate buffers (`shardA`, `shardB`, `privateKey`, `seed`) must be overwritten via `buffer.fill(0)` immediately after use.
- The library provides utility zeroization routines and recommends executing all cryptographic operations in scoped `try...finally` blocks.

## Generalized Non-Blockchain Applications

While `open-mpc-vault` includes built-in HD derivation for Web3 runtimes (Ethereum, Solana, Bitcoin), the underlying 2-of-2 Shamir Secret Sharing scheme and authenticated shard encryption operate on arbitrary 16-byte, 32-byte, or n-byte payloads. This makes the architecture directly applicable to broader security and infrastructure use cases:

- **Distributed Master Key Encryption (Envelope Encryption)**: Split database or filesystem Key Encryption Keys (KEKs) between a client application and a cloud key broker. Neither the cloud infrastructure nor a compromised endpoint can decrypt customer data at rest independently.
- **High-Privilege API Credential Escrow**: Protect sensitive production root tokens (e.g., AWS root credentials, Stripe restricted keys, OpenAI admin tokens). Access requires an ephemeral handshake between two isolated services or dual-custody administrator sign-offs.
- **CI/CD Release and Artifact Signing**: Distribute code-signing keys (GPG keys, Apple Developer certificates, Android release keys) such that automated build machines cannot sign releases without explicit, cryptographic quorum from a release authorization server.
- **Zero-Knowledge Passwordless Account Recovery**: Split an identity or encryption seed between a user's local secure element/passkey and an authentication service to enable account recovery without server-side plaintext escrow.
- **Multi-Institution Confidential Data Sharing**: Encrypt sensitive medical records or financial datasets where decryption keys require multi-party consensus across distinct legal entities.

## Installation

```bash
npm install open-mpc-vault
```

Peer requirements: Node.js >= 18.0.0.

## API Usage

### 1. Provisioning a New Vault Seed

```typescript
import { MpcKeyGenerator, ShardEncryption } from 'open-mpc-vault';

// Generate a 12-word BIP-39 seed split into 2-of-2 shards
const { shardA, shardB, mnemonic, entropy } = MpcKeyGenerator.createMpcSeed(12);

// Encrypt Shard A on the client using user credentials
const userPin = '749201';
const encryptedShardA = ShardEncryption.encryptShardA(shardA, userPin);

// Encrypt Shard B using the server master secret
const encryptedShardB = ShardEncryption.encryptShardB(shardB);

// Securely wipe raw memory buffers after persistence
shardA.fill(0);
shardB.fill(0);
entropy.fill(0);
```

### 2. Ephemeral Reconstruction and Multi-Chain Derivation

```typescript
import {
  ShardEncryption,
  deriveWalletFromShards,
  ChainType,
  CurveType,
} from 'open-mpc-vault';

let decryptedA: Buffer | undefined;
let decryptedB: Buffer | undefined;

try {
  // Decrypt Shard A with the user PIN and stored salt/IV/tag
  decryptedA = ShardEncryption.decryptShardA(
    encryptedShardA.encrypted,
    encryptedShardA.iv,
    encryptedShardA.tag,
    userPin,
    encryptedShardA.salt
  );

  // Decrypt Shard B with server credentials
  decryptedB = ShardEncryption.decryptShardB(encryptedShardB);

  // 1. Derive EVM Wallet (Ethereum / Polygon / Arbitrum / Base)
  const evmWallet = deriveWalletFromShards({
    shardA: decryptedA,
    shardB: decryptedB,
    chainType: ChainType.ETHEREUM,
    curveType: CurveType.SECP256K1,
    accountIndex: 0,
    addressIndex: 0,
  });
  console.log('EVM Address:', evmWallet.address);

  // 2. Derive Solana Wallet (Ed25519)
  const solanaWallet = deriveWalletFromShards({
    shardA: decryptedA,
    shardB: decryptedB,
    chainType: ChainType.SOLANA,
    curveType: CurveType.ED25519,
    accountIndex: 0,
  });
  console.log('Solana Address:', solanaWallet.address);

  // 3. Derive Bitcoin Wallet (BIP-84 Native SegWit)
  const btcWallet = deriveWalletFromShards({
    shardA: decryptedA,
    shardB: decryptedB,
    chainType: ChainType.BITCOIN,
    accountIndex: 0,
    addressIndex: 0,
  });
  console.log('Bitcoin Address:', btcWallet.address);

} finally {
  // Mandatory buffer cleanup
  if (decryptedA) decryptedA.fill(0);
  if (decryptedB) decryptedB.fill(0);
}
```

### 3. Importing an Existing Seed Phrase

```typescript
import { SeedPhraseUtils } from 'open-mpc-vault';

const userMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Validate BIP-39 checksum
if (!SeedPhraseUtils.validateMnemonic(userMnemonic)) {
  throw new Error('Invalid seed phrase checksum');
}

// Convert to entropy and split into threshold shards
const { shardA, shardB } = SeedPhraseUtils.splitMnemonicIntoShards(userMnemonic);
```

### 4. Storage Adapter Interface

`open-mpc-vault` decouples shard persistence through the `ShardStorageAdapter` interface:

```typescript
export interface ShardStorageAdapter {
  storeShardB(shardBId: string, userId: number, shardBData: Buffer): Promise<void>;
  retrieveShardB(shardBId: string, userId: number): Promise<Buffer | null>;
  deleteShardB(shardBId: string, userId: number): Promise<boolean>;
}
```

An in-memory reference adapter (`InMemoryShardStorageAdapter`) is provided for testing and local integration. Production deployments can supply adapters targeting PostgreSQL, Redis, DynamoDB, or hardware security modules (HSMs).

## Development and Verification

### Prerequisites
- Node.js >= 18.0.0
- npm >= 9.0.0

### Build
```bash
npm run build
```

### Test Suite
Tests execute using Node.js native test runner and verify cryptographic correctness against standard vectors:
```bash
npm test
```

Test coverage includes:
- Shamir secret reconstruction and threshold boundary enforcement
- PBKDF2 derivation and AES-256-GCM authentication failure detection
- BIP-39 mnemonic parsing and entropy round-trip verification
- Deterministic BIP-44 and BIP-84 multi-chain address derivation
- End-to-end threshold lifecycle flows

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
