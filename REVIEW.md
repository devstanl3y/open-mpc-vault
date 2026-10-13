# Senior Engineering Architecture Review & Security Audit

**Repository**: `open-mpc-vault`  
**Date**: October 2026  
**Status**: Comprehensive Refactor Completed

---

## 1. Executive Summary

`open-mpc-vault` provides a 2-of-2 Shamir Secret Sharing Scheme (SSSS) vault and multi-chain hierarchical deterministic (HD) wallet derivation engine for Node.js/TypeScript. 

During the engineering review, the codebase was restructured to clearly separate:
1. **Core Library (`src/`)**: A clean, zero-dependency (outside of audited noble crypto and bip32/bip39 libraries) standalone npm package.
2. **Reference Implementations (`examples/`)**: Decoupled Express/Prisma backend controllers, React hooks, and an `ethers-rs` Rust loader.

This document details the critical cryptographic and architectural bugs resolved, the fundamental difference between Shamir Secret Sharing and true Multi-Party Computation (MPC), and remaining architectural recommendations requiring future migration paths.

---

## 2. Architectural Classification: Shamir Secret Sharing vs. True MPC/TSS

The repository is branded as `open-mpc-vault`. From a cryptographic systems perspective, it is critical to clarify that this system is **not** a Multi-Party Computation (MPC) or Threshold Signature Scheme (TSS):

```
Threshold Signatures (FROST / GG20 / CMP):
  Party A (Shard A) --- [Partial Sig Round 1] ---> Coordinator
  Party B (Shard B) --- [Partial Sig Round 2] ---> Coordinator -> Valid Signature
  * The complete private key NEVER exists anywhere in memory *

Shamir Secret Sharing (open-mpc-vault):
  Party A (Encrypted Shard A) ---\
                                  +--> [Ephemeral Reconstruction Node]
  Party B (Encrypted Shard B) ---/     (Private Key assembled in RAM -> Signs -> Zeroized)
```

### Threat Model Implications
- **In True MPC/TSS**: Even if the execution node's RAM is dumped (via root exploit, memory scraping, or cold-boot attack), the attacker obtains only a single share and cannot sign transactions.
- **In SSS (this library)**: During the millisecond window where `deriveWalletFromShards` reconstructs the key, the full unencrypted private key exists in application memory. 
- **Senior Recommendation**: If advertising this project for enterprise custody, clearly state that this is **Threshold Secret Sharing (TSS/SSS) with ephemeral in-memory reconstruction**, not distributed multi-party computation.

---

## 3. Cryptographic & Implementation Bugs Resolved

### Bug 1: Catastrophic 24-Hour Default TTL on Server Shards
- **Issue**: `ShardStorage.storeShardB` previously stored Shard B with `DEFAULT_TTL = 24 * 60 * 60` (24 hours).
- **Impact**: Any production deployment using a TTL-aware storage adapter (e.g., Redis, DynamoDB, Memcached) would permanently delete Shard B after 24 hours. Because 2-of-2 Shamir requires both shards, **every user vault was guaranteed to become permanently unrecoverable after 24 hours**.
- **Fix**: Removed default TTL entirely. Shard B is persisted permanently until explicitly deleted by the user.

### Bug 2: Shamir `splitSecret` Hardcoded Share Count
- **Issue**: `ShamirSecretSharing.splitSecret(secret, threshold, p0)` ignored the third argument and ran a hardcoded loop: `for (let x = 1; x <= 2; x++)`.
- **Impact**: Any attempt to split into more than 2 shares silently produced only 2 shares.
- **Fix**: Renamed parameter to `shareCount`, validated bounds ($2 \le \text{threshold} \le \text{shareCount} \le 255$), and dynamically evaluated polynomial shares.

### Bug 3: Polynomial Modulo Bias and Inversion Robustness
- **Issue**: Random polynomial coefficients were generated as `BigInt('0x' + crypto.randomBytes(32).toString('hex')) % PRIME`. Because $2^{256}$ is not a multiple of $p$, modulo reduction introduces slight statistical bias. Furthermore, modular inversion used a recursive Extended Euclidean algorithm.
- **Impact**: Non-uniform coefficient distribution and unnecessary recursion on BigInts.
- **Fix**: Implemented uniform rejection sampling (draw 32 bytes until candidate $< p$) and replaced Extended GCD with Fermat's Little Theorem: $a^{-1} \equiv a^{p-2} \pmod p$.

### Bug 4: Destructive Shard Rotation & Deletion Ordering
- **Issue**: `ShardStorage.rotateShardB` executed `await this.deleteShardB(oldShardId)` *before* `this.storeShardB(newShard)`.
- **Impact**: If the storage write failed (e.g. database network error), the old shard was already deleted, causing irreversible key loss. Similarly, `deleteMpcWallet` wiped cloud backups and shard B before executing the database delete.
- **Fix**: Reordered all operations: write new records before deleting old ones, and execute database record deletions before cleaning up external storage pointers.

### Bug 5: BIP-32 Path Injection in Wallet Derivation
- **Issue**: User-supplied values for `accountIndex` and `addressIndex` were interpolated directly into derivation strings: `m/44'/60'/${account}'/0/${index}`.
- **Impact**: Callers could pass string payloads like `"0'/1"` or non-standard hardened indices, manipulating key derivation paths.
- **Fix**: Added strict validation in `HDWalletDerivation.buildPath` and controllers ensuring indices are non-negative 31-bit integers ($\le 0\text{x}7fffffff$).

### Bug 6: Dropped secp256k1 Signature Recovery Identifier (`v`)
- **Issue**: `signing.controller.ts` signed digests with `@noble/curves/secp256k1` and returned only the compact 64-byte hex string ($r \parallel s$), discarding `sig.recovery`.
- **Impact**: Ethereum/EVM signatures require the recovery identifier $v \in \{27, 28\}$ (or EIP-155 chain-specific $v$) to recover the signer's public key. Client applications could not broadcast valid transactions without guessing $v$.
- **Fix**: Added `recovery` (0 or 1) to signature responses.

### Bug 7: Naive XOR Fallback in Rust Loader
- **Issue**: `examples/rust-wallet-loader/src/lib.rs` implemented `reconstruct_private_key` by XORing the two byte slices: `shard_a.iter().zip(shard_b).map(|(a, b)| a ^ b)`.
- **Impact**: Shamir shares evaluated over $\mathbb{F}_p$ cannot be combined with XOR. The loader was completely dysfunctional.
- **Fix**: Implemented complete 256-bit Lagrange polynomial interpolation over $\mathbb{F}_p$ using `num-bigint` in Rust, verified against TypeScript test vectors.

### Bug 8: Leaked Host Paths in `tsconfig.json`
- **Issue**: Root `tsconfig.json` included hardcoded local paths:
  `"/Users/stanley/projects/Maren/node_modules/@types"`.
- **Impact**: Compiler diagnostics failed on clean Linux environments.
- **Fix**: Purged local paths, stripped DOM library dependencies, and enabled strict typechecking.

---

## 4. Architectural Recommendations for Future Versions (v0.2.0+)

The following issues were retained in v0.1.0 to prevent breaking changes for existing stored ciphertexts, but should be scheduled for deprecation in v0.2.0:

### 1. Insecure Fallback Server Secret & Static Salt
- **Current State**: In `ShardEncryption`:
  ```typescript
  const INSECURE_DEFAULT_SERVER_SECRET = 'open-mpc-vault-default-secret';
  const SERVER_KEY_SALT = 'open-mpc-vault-salt';
  ```
  If `MPC_SERVER_SECRET` is unset in the environment, the library silently encrypts Shard B with a hardcoded static key.
- **Recommendation**:
  1. Make `MPC_SERVER_SECRET` mandatory in production; fail closed with an explicit configuration error on startup.
  2. Transition to **Envelope Encryption** backed by a Hardware Security Module (HSM) or Cloud KMS (AWS KMS, Google Cloud KMS, HashiCorp Vault Transit). Generate a unique Data Encryption Key (DEK) per shard record rather than a global static server secret.

### 2. AES-256-GCM Nonce Length (16 bytes vs. 12 bytes)
- **Current State**: `IV_LENGTH` is set to 16 bytes.
- **Cryptographic Standard**: NIST SP 800-38D specifies that 96-bit (12-byte) IVs are the optimal format for AES-GCM. 16-byte IVs force the cipher to perform an extra GHASH evaluation over the IV to derive $J_0$, adding CPU overhead and slight edge-case risk.
- **Recommendation**: Introduce a v2 format prefix (e.g. `v2:<iv12>:<tag16>:<ciphertext>`) to migrate newly created shards to standard 12-byte nonces while continuing to decrypt legacy 16-byte ciphertexts.

### 3. Non-Standard Solana Derivation (BIP-32 vs. SLIP-0010)
- **Current State**: `HDWalletDerivation.deriveSolanaWallet` derives a 32-byte key using standard secp256k1 BIP-32 and passes those bytes into `Keypair.fromSeed(...)` for Ed25519.
- **Standard Behavior**: Standard Solana wallets (Phantom, Solflare, Backpack) implement **SLIP-0010**, which derives Ed25519 keys using HMAC-SHA512 with the key `ed25519 seed` and hardened derivation indices. As a result, the same mnemonic produces a different Solana address in this library than in Phantom.
- **Recommendation**: Add a dedicated `SLIP0010` derivation option so users can derive industry-standard Solana addresses.

### 4. Plaintext Exposure on Internal Service Endpoints
- **Current State**: `examples/express-prisma/controllers/internal.controller.ts` includes `/decrypt-shard-a`, `/shard-b/:id`, and `/reconstruct`.
- **Security Risk**: If an internal network is compromised, an attacker can query these endpoints to exfiltrate plaintext private keys.
- **Recommendation**: Implement **sign-in-place** internal endpoints (`/internal/sign`) where the execution service requests a signature rather than retrieving raw shards, keeping plaintext reconstruction isolated within a trusted enclave or secure compute environment.
