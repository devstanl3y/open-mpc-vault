# Reference Examples for open-mpc-vault

This directory contains reference implementations demonstrating how to integrate `open-mpc-vault` into production applications across backend, frontend, and systems services.

```
examples/
├── express-prisma/        # Production Express REST API with Prisma ORM
│   ├── controllers/       # Wallet creation, derivation, signing, recovery
│   ├── routes.ts          # Express routers (public and authenticated internal)
│   └── host.ts            # Host application dependency interface (@app/*)
├── react/                 # Frontend client integrations
│   └── useMpcWallet.ts    # React hook for vault lifecycle and signing
└── rust-wallet-loader/    # Systems/engine integration in Rust
    ├── Cargo.toml         # Manifest with ethers-rs and num-bigint
    └── src/lib.rs         # Shamir reconstruction over secp256k1 field
```

---

## 1. Express + Prisma Backend (`examples/express-prisma/`)

A complete reference API demonstrating non-custodial key provisioning, derivation, session keys, cloud backup sync, and recovery.

### Host Application Integration Contract (`host.ts`)

The controller code decouples host-specific database and middleware logic into `host.ts` under the placeholder alias `@app/*`. To incorporate these controllers into an existing service, map `@app/*` in your `tsconfig.json` `paths` or replace the re-exports with your concrete modules:

| Export in `host.ts` | Expected Contract / Type | Description |
|---|---|---|
| `prisma` | `@prisma/client` instance | Database client with `User`, `MpcWallet`, `ShardABackup`, and `UserCloudProvider` models. |
| `requireAuth` | `express.RequestHandler` | Authentication middleware populating `req.user.id`. |
| `logger` | Logging interface | Structured logger (e.g., Winston, Pino). |
| `cloudBackupService` | Cloud backup service | Handles uploading, fetching, and validating encrypted Shard A backups. |
| `SessionKeyManager` | Session key manager | Manages ephemeral signing sessions to sign transactions without prompting for PIN on every action. |
| `strictLimiter` | `express.RequestHandler` | Rate limiter applied to all PIN-checking endpoints to prevent brute-force attacks. |
| `PIN_PEPPER_SECRET` | `string` | High-entropy server secret concatenated with user PINs before bcrypt evaluation. |

### Minimum Prisma Schema

The example expects the following database schema:

```prisma
model User {
  id          Int          @id @default(autoincrement())
  pin_hash    String?      // bcrypt hash of (pin + PIN_PEPPER)
  mpc_enabled Boolean      @default(false)
  mpcWallets  MpcWallet[]
}

model MpcWallet {
  id             String          @id @default(uuid())
  userId         Int
  user           User            @relation(fields: [userId], references: [id])
  walletName     String
  publicAddress  String
  curveType      CurveType       // SECP256K1 | ED25519
  chainType      ChainType?      // ETHEREUM | SOLANA | BITCOIN
  derivationPath String?
  accountIndex   Int             @default(0)
  addressIndex   Int             @default(0)
  isImported     Boolean         @default(false)
  isSeedPhrase   Boolean         @default(true)
  shardBId       String          // Key pointer to ShardStorage
  status         ShardStatus     @default(ACTIVE)
  createdAt      DateTime        @default(now())
  lastUsedAt     DateTime?
  shardABackups  ShardABackup[]
}

model ShardABackup {
  id               String    @id @default(uuid())
  mpcWalletId      String
  mpcWallet        MpcWallet @relation(fields: [mpcWalletId], references: [id])
  driveFileId      String
  backupVersion    Int       @default(4)
  metadataChecksum String
  lastSyncedAt     DateTime  @default(now())
}
```

### Security Boundary: Internal Service Router

`createInternalRouter(serviceAuth)` exposes service-to-service endpoints for backend trading engines or background workers (such as the Rust loader). 

> **Important**: Endpoints such as `/decrypt-shard-a`, `/shard-b/:id`, and `/reconstruct` return or reconstruct plaintext key material. These endpoints **must never be mounted on a public gateway**. They must be restricted to a private VPC and protected by mutual TLS (mTLS) or high-entropy machine tokens.

---

## 2. React Client Hook (`examples/react/`)

`useMpcWallet.ts` provides a hook for React applications consuming the Express backend:

```tsx
import React, { useState } from 'react';
import { useMpcWallet } from './useMpcWallet';

export function VaultManager() {
  const { createVault, listWallets, sign, loading, error } = useMpcWallet('/api/v1/mpc');
  const [wallets, setWallets] = useState([]);

  const handleCreate = async () => {
    const result = await createVault('My Primary Vault', '123456');
    if (result) {
      // Shard A must be persisted securely on client storage (e.g. IndexedDB with WebCrypto)
      console.log('Vault created:', result.vaultId, result.wallets);
    }
  };

  return (
    <div>
      <button onClick={handleCreate} disabled={loading}>
        Create MPC Vault
      </button>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
```

---

## 3. Rust Wallet Loader (`examples/rust-wallet-loader/`)

The Rust crate demonstrates how backend execution engines can load a Shamir-split wallet directly into an `ethers::LocalWallet` for automated on-chain execution.

### Cryptographic Implementation
The Rust loader implements exact Lagrange polynomial interpolation over the secp256k1 base field:
$$p = 2^{256} - 2^{32} - 977$$

It accepts both current 34-byte extended shares (`[x, len, y_32]`) and legacy 33-byte shares (`[x, y_32]`), verifying field constraints, coordinate non-zeroness, and duplicate detection.

### Running Tests
```bash
cd examples/rust-wallet-loader
cargo test
```
