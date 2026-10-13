import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { keccak_256 } from '@noble/hashes/sha3';
import bs58 from 'bs58';
import { ShamirSecretSharing } from './shamir';
import { SeedPhraseUtils } from './seedPhrase';
import { HDWalletDerivation } from './hdWallet';
import { ChainType, CurveType, type MpcSeedShards } from '../types';

export type { MpcSeedShards };

export interface MpcDerivedWallet {
  privateKey: Buffer;
  publicKey: Buffer;
  address: string;
  chainType: ChainType;
  curveType: CurveType;
  derivationPath: string;
}

export interface WalletImportData {
  address: string;
  balance?: string;
  chainType: ChainType;
  derivationPath?: string;
}

/** Derivation path recorded for wallets imported from a raw private key. */
export const IMPORTED_KEY_DERIVATION_PATH = 'imported';

const LEGACY_SHARE_BYTES = 33;
const PRIVATE_KEY_HEX = /^[0-9a-fA-F]{64}$/;

export class MpcKeyGenerator {
  static createMpcSeed(wordCount: 12 | 24 = 12): MpcSeedShards {
    const mnemonic =
      wordCount === 12 ? SeedPhraseUtils.generate12Word() : SeedPhraseUtils.generate24Word();

    const entropy = SeedPhraseUtils.mnemonicToEntropy(mnemonic);
    const { shardA, shardB } = this.splitEntropyIntoShards(entropy);
    return { shardA, shardB, mnemonic, entropy };
  }

  static importMpcSeed(mnemonic: string): MpcSeedShards {
    const normalized = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');
    if (!SeedPhraseUtils.validate(normalized)) {
      throw new Error('Invalid mnemonic phrase');
    }

    const entropy = SeedPhraseUtils.mnemonicToEntropy(normalized);
    const { shardA, shardB } = this.splitEntropyIntoShards(entropy);
    return { shardA, shardB, mnemonic: normalized, entropy };
  }

  /** Split a raw 32-byte private key (hex, optional 0x prefix). */
  static importPrivateKey(privateKey: string): MpcSeedShards {
    const cleaned = privateKey.trim().replace(/^0x/i, '');
    if (!PRIVATE_KEY_HEX.test(cleaned)) {
      throw new Error('Invalid private key: expected 32 bytes of hex');
    }

    const entropy = Buffer.from(cleaned, 'hex');
    const { shardA, shardB } = this.splitEntropyIntoShards(entropy);
    return { shardA, shardB, mnemonic: '', entropy };
  }

  static splitEntropyIntoShards(entropy: Buffer): { shardA: Buffer; shardB: Buffer } {
    const [shardA, shardB] = ShamirSecretSharing.splitSecret(entropy, 2, 2);
    return { shardA, shardB };
  }

  static reconstructEntropy(shardA: Buffer, shardB: Buffer): Buffer {
    return ShamirSecretSharing.reconstructSecret([shardA, shardB]);
  }

  /**
   * Reconstruct the secret from both shards and derive the wallet for
   * `chainType`.
   *
   * For seed-phrase vaults created with the legacy 33-byte share format, a
   * 12-word seed may have been stored zero-padded to 32 bytes. When
   * `expectedAddress` is given, both interpretations are tried and the
   * matching one is returned.
   */
  static deriveWalletFromShards(
    shardA: Buffer,
    shardB: Buffer,
    chainType: ChainType,
    account = 0,
    index = 0,
    isSeedPhrase = true,
    expectedAddress?: string
  ): MpcDerivedWallet {
    const entropy = this.reconstructEntropy(shardA, shardB);

    if (!isSeedPhrase) {
      return this.deriveFromPrivateKey(entropy, chainType);
    }

    try {
      const candidates = this.getSeedEntropyCandidates(shardA, shardB, entropy);
      const derived = candidates.map((candidate) =>
        this.deriveFromSeedEntropy(candidate, chainType, account, index)
      );

      if (expectedAddress) {
        const expected = expectedAddress.toLowerCase();
        const match = derived.find((w) => w.address.toLowerCase() === expected);
        if (match) return match;
      }
      return derived[0];
    } finally {
      entropy.fill(0);
    }
  }

  /** Derive the first `count` receive addresses for the given secret. */
  static deriveAddresses(
    entropy: Buffer,
    chainType: ChainType,
    isSeedPhrase: boolean,
    count = 5
  ): WalletImportData[] {
    if (!isSeedPhrase) {
      const wallet = this.deriveFromPrivateKey(Buffer.from(entropy), chainType);
      wallet.privateKey.fill(0);
      return [
        { address: wallet.address, chainType, derivationPath: IMPORTED_KEY_DERIVATION_PATH },
      ];
    }

    const seed = this.entropyToSeed(entropy);
    try {
      const results: WalletImportData[] = [];
      for (let i = 0; i < count; i++) {
        // Solana uses the account level as the per-address counter.
        const wallet =
          chainType === ChainType.SOLANA
            ? HDWalletDerivation.deriveWallet(seed, chainType, i, 0)
            : HDWalletDerivation.deriveWallet(seed, chainType, 0, i);
        wallet.privateKey.fill(0);
        results.push({
          address: wallet.address,
          chainType: wallet.chainType,
          derivationPath: wallet.derivationPath,
        });
      }
      return results;
    } finally {
      seed.fill(0);
    }
  }

  /**
   * @deprecated Does not check on-chain usage; it returns the first
   * `min(5, gapLimit)` derived addresses. Use {@link deriveAddresses}.
   */
  static async scanUsedAddresses(
    entropy: Buffer,
    chainType: ChainType,
    isSeedPhrase: boolean,
    gapLimit = 20
  ): Promise<WalletImportData[]> {
    return this.deriveAddresses(entropy, chainType, isSeedPhrase, Math.min(5, gapLimit));
  }

  static verifyImport(
    entropy: Buffer,
    expectedAddress: string,
    chainType: ChainType,
    isSeedPhrase: boolean
  ): boolean {
    try {
      const wallet = isSeedPhrase
        ? this.deriveFromSeedEntropy(entropy, chainType, 0, 0)
        : this.deriveFromPrivateKey(Buffer.from(entropy), chainType);
      wallet.privateKey.fill(0);
      return wallet.address.toLowerCase() === expectedAddress.toLowerCase();
    } catch {
      return false;
    }
  }

  private static entropyToSeed(entropy: Buffer): Buffer {
    return SeedPhraseUtils.mnemonicToSeed(SeedPhraseUtils.entropyToMnemonic(entropy));
  }

  private static deriveFromSeedEntropy(
    entropy: Buffer,
    chainType: ChainType,
    account: number,
    index: number
  ): MpcDerivedWallet {
    const seed = this.entropyToSeed(entropy);
    try {
      return HDWalletDerivation.deriveWallet(seed, chainType, account, index);
    } finally {
      seed.fill(0);
    }
  }

  /** Takes ownership of `privateKey`; it is returned as the wallet's key. */
  private static deriveFromPrivateKey(privateKey: Buffer, chainType: ChainType): MpcDerivedWallet {
    switch (chainType) {
      case ChainType.ETHEREUM: {
        if (!secp256k1.utils.isValidPrivateKey(privateKey)) {
          throw new Error('Invalid secp256k1 private key');
        }
        const publicKey = secp256k1.getPublicKey(privateKey, false);
        const address =
          '0x' + Buffer.from(keccak_256(publicKey.subarray(1)).subarray(-20)).toString('hex');
        return {
          privateKey,
          publicKey: Buffer.from(publicKey),
          address,
          chainType,
          curveType: CurveType.SECP256K1,
          derivationPath: IMPORTED_KEY_DERIVATION_PATH,
        };
      }
      case ChainType.SOLANA: {
        const publicKey = ed25519.getPublicKey(privateKey);
        return {
          privateKey,
          publicKey: Buffer.from(publicKey),
          address: bs58.encode(publicKey),
          chainType,
          curveType: CurveType.ED25519,
          derivationPath: IMPORTED_KEY_DERIVATION_PATH,
        };
      }
      default:
        throw new Error(`Private key import is not supported for ${String(chainType)}`);
    }
  }

  private static getSeedEntropyCandidates(
    shardA: Buffer,
    shardB: Buffer,
    entropy: Buffer
  ): Buffer[] {
    const candidates = [entropy];

    const isLegacyShareFormat =
      shardA.length === LEGACY_SHARE_BYTES && shardB.length === LEGACY_SHARE_BYTES;
    const hasZeroPaddedPrefix =
      entropy.length === 32 && entropy.subarray(0, 16).every((byte) => byte === 0);

    if (isLegacyShareFormat && hasZeroPaddedPrefix) {
      candidates.push(entropy.subarray(16));
    }
    return candidates;
  }
}
