# Open MPC Vault (`open-mpc-vault`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org/)

A production-grade, non-custodial **2-of-2 Multi-Party Computation (MPC) Threshold Secret Sharing Vault** with multi-chain HD wallet derivation (Ethereum, Solana, Bitcoin) and hardened AES-256-GCM shard encryption.

---

## 🌟 Overview

`open-mpc-vault` implements a non-custodial threshold key management architecture where no single party holds a full private key or seed phrase:
- **Client Shard (Shard A)**: Held by the user or client app, encrypted locally via AES-256-GCM using PBKDF2-stretched credentials (e.g. user PIN or passkey).
- **Server Shard (Shard B)**: Stored server-side in encrypted format with independent salts and server secrets.
- **Threshold Reconstruction**: The original entropy is split using a **2-of-2 Shamir's Secret Sharing Scheme** over the secp256k1 field and only reconstituted ephemerally in-memory during authorized signing sessions.

```
       [ Seed Phrase / Random Entropy (16 or 32 bytes) ]
                                |
               Shamir's Secret Sharing (2-of-2)
                                |
            +-------------------+-------------------+
            |                                       |
        [ Shard A ]                             [ Shard B ]
            |                                       |
    AES-256-GCM Encrypted                   AES-256-GCM Encrypted
   (User PIN + PBKDF2)                    (Server Secret + Salt)
            |                                       |
    [ Client / Device ]                      [ Vault Server ]
            \                                       /
             \--- Ephemeral Handshake (Signing) ---/
                                |
                   [ In-Memory Reconstruction ]
                                |
             +------------------+------------------+
             |                  |                  |
           EVM               Solana             Bitcoin
      (BIP-44 m/60')     (BIP-44 m/501')     (BIP-84 m/84')
```

---

## 🚀 Features

- **2-of-2 Shamir Secret Sharing**: Finite-field polynomial secret sharing over secp256k1 prime order with Lagrange interpolation.
- **Client-Side Shard Encryption**: AES-256-GCM authenticated encryption with 100,000 PBKDF2 iterations (SHA-512) and unique salts.
- **Multi-Chain Hierarchical Deterministic (HD) Derivation**:
  - **Ethereum / EVM**: BIP-44 (`m/44'/60'/account'/0/index`) via secp256k1 and Keccak-256.
  - **Solana**: BIP-44 (`m/44'/501'/account'/0'`) via Ed25519 curve keypairs.
  - **Bitcoin**: BIP-84 Native SegWit (`m/84'/0'/account'/0/index`) via P2WPKH (`bc1...`).
- **BIP-39 Mnemonic Support**: Standard 12-word and 24-word seed phrase generation, validation, and entropy conversion.
- **Pluggable Storage Adapters**: Built-in memory adapter and interfaces for Redis, PostgreSQL, SQLite, or custom backends.
- **Zero Heavy Framework Lock-In**: Decoupled, modular TypeScript library with zero database dependencies.

---

## 📦 Installation

```bash
npm install open-mpc-vault
# or
pnpm add open-mpc-vault
# or
yarn add open-mpc-vault
```

---

## 🛠️ Quickstart

### 1. Generating & Splitting an MPC Wallet Seed

```typescript
import { MpcKeyGenerator, ShardEncryption } from 'open-mpc-vault';

// 1. Generate a new 12-word MPC seed split into 2-of-2 threshold shards
const { shardA, shardB, mnemonic, entropy } = MpcKeyGenerator.createMpcSeed(12);

console.log('Mnemonic phrase (backup):', mnemonic);

// 2. Encrypt Shard A on client using user PIN / passphrase
const userPin = '839201';
const encryptedShardA = ShardEncryption.encryptShardA(shardA, userPin);

// 3. Encrypt Shard B server-side using server secret
const encryptedShardB = ShardEncryption.encryptShardB(shardB);
```

### 2. Signing / Reconstituting & Deriving Addresses

```typescript
import {
  ShardEncryption,
  ShamirSecretSharing,
  deriveWalletFromShards,
  ChainType,
  CurveType,
} from 'open-mpc-vault';

// 1. Decrypt both shards during an authorized signing session
const decryptedShardA = ShardEncryption.decryptShardA(
  encryptedShardA.encrypted,
  encryptedShardA.iv,
  encryptedShardA.tag,
  userPin,
  encryptedShardA.salt
);

const decryptedShardB = ShardEncryption.decryptShardB(encryptedShardB);

// 2. Derive multi-chain wallets directly from shards
const ethWallet = deriveWalletFromShards({
  shardA: decryptedShardA,
  shardB: decryptedShardB,
  chainType: ChainType.ETHEREUM,
  curveType: CurveType.SECP256K1,
  accountIndex: 0,
  addressIndex: 0,
});

console.log('Ethereum Address:', ethWallet.address); // 0x...

const solWallet = deriveWalletFromShards({
  shardA: decryptedShardA,
  shardB: decryptedShardB,
  chainType: ChainType.SOLANA,
  curveType: CurveType.ED25519,
  accountIndex: 0,
});

console.log('Solana Address:', solWallet.address);

const btcWallet = deriveWalletFromShards({
  shardA: decryptedShardA,
  shardB: decryptedShardB,
  chainType: ChainType.BITCOIN,
  accountIndex: 0,
  addressIndex: 0,
});

console.log('Bitcoin Address:', btcWallet.address); // bc1...
```

---

## 🔒 Security Architecture

1. **Threshold Guarantee**: Neither party (User with only Shard A, nor Server with only Shard B) can reconstruct the private key independently.
2. **Field Arithmetic**: Secret sharing is computed over the finite prime field $p = 2^{256} - 2^{32} - 977$ matching secp256k1.
3. **AEAD Encryption**: All shards are encrypted with AES-256-GCM with authentication tags ensuring ciphertext integrity and tampering detection.
4. **Key Zeroization**: Sensitive decrypted byte buffers should be zeroized (`buffer.fill(0)`) immediately after transaction signing.

---

## 🧪 Running Tests

```bash
npm test
```

All unit tests run using Node.js native test runner testing:
- Shamir secret splitting and Lagrange polynomial reconstruction
- AES-256-GCM encryption with valid and invalid PINs
- BIP-44 / BIP-84 HD wallet derivation across Ethereum, Solana, and Bitcoin
- Complete end-to-end lifecycle verification

---

## 📄 License

[MIT License](LICENSE)
