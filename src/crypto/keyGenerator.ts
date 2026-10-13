import { ShamirSecretSharing } from './shamir';
import { SeedPhraseUtils } from './seedPhrase';
import { HDWalletDerivation, ChainType, DerivedWallet } from './hdWallet';
import { CurveType } from '../types';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { ed25519 } from '@noble/curves/ed25519';
import bs58 from 'bs58';

export interface MpcSeedShards {
  shardA: Buffer;
  shardB: Buffer;
  mnemonic: string;
  entropy: Buffer;
}

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

export class MpcKeyGenerator {
  static reconstructPrivateKey(shardA: Buffer<ArrayBufferLike>, shardB: Buffer<ArrayBufferLike>) {
    throw new Error('Method not implemented.');
  }
  static createMpcSeed(wordCount: 12 | 24 = 12): MpcSeedShards {
    const mnemonic = wordCount === 12 
      ? SeedPhraseUtils.generate12Word() 
      : SeedPhraseUtils.generate24Word();
    
    const entropy = SeedPhraseUtils.mnemonicToEntropy(mnemonic);
    const { shardA, shardB } = this.splitEntropyIntoShards(entropy);

    return {
      shardA,
      shardB,
      mnemonic,
      entropy
    };
  }

  static importMpcSeed(mnemonic: string): MpcSeedShards {
    const normalized = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');
    
    if (!SeedPhraseUtils.validate(normalized)) {
      throw new Error('Invalid mnemonic phrase');
    }

    const entropy = SeedPhraseUtils.mnemonicToEntropy(normalized);
    const { shardA, shardB } = this.splitEntropyIntoShards(entropy);

    return {
      shardA,
      shardB,
      mnemonic: normalized,
      entropy
    };
  }

  static importPrivateKey(privateKey: string): MpcSeedShards {
    let privateKeyBuffer: Buffer;
    
    const cleaned = privateKey.trim();
    if (cleaned.startsWith('0x')) {
      privateKeyBuffer = Buffer.from(cleaned.slice(2), 'hex');
    } else {
      privateKeyBuffer = Buffer.from(cleaned, 'hex');
    }

    if (privateKeyBuffer.length !== 32) {
      throw new Error('Invalid private key length. Must be 32 bytes.');
    }

    const { shardA, shardB } = this.splitEntropyIntoShards(privateKeyBuffer);

    return {
      shardA,
      shardB,
      mnemonic: '',
      entropy: privateKeyBuffer
    };
  }

  static splitEntropyIntoShards(entropy: Buffer): { shardA: Buffer; shardB: Buffer } {
    const shards = ShamirSecretSharing.splitSecret(entropy, 2, 2);
    return {
      shardA: shards[0],
      shardB: shards[1]
    };
  }

  static reconstructEntropy(shardA: Buffer, shardB: Buffer): Buffer {
    return ShamirSecretSharing.reconstructSecret([shardA, shardB]);
  }

  static deriveWalletFromShards(
    shardA: Buffer,
    shardB: Buffer,
    chainType: ChainType,
    account: number = 0,
    index: number = 0,
    isSeedPhrase: boolean = true,
    expectedAddress?: string
  ): MpcDerivedWallet {
    const entropy = this.reconstructEntropy(shardA, shardB);

    if (!isSeedPhrase) {
      let address: string;
      let publicKey: Buffer;
      
      if (chainType === ChainType.ETHEREUM) {
        if (!secp256k1.utils.isValidPrivateKey(entropy)) {
          throw new Error('Invalid Ethereum private key');
        }

        const pubKey = secp256k1.getPublicKey(entropy, false);
        const publicKeyBytes = pubKey.slice(1);
        const hash = keccak_256(publicKeyBytes);
        address = '0x' + Buffer.from(hash.slice(-20)).toString('hex');
        publicKey = Buffer.from(pubKey);
      } else if (chainType === ChainType.SOLANA) {
        const pubKey = ed25519.getPublicKey(entropy);
        address = bs58.encode(Buffer.from(pubKey));
        publicKey = Buffer.from(pubKey);
      } else {
        throw new Error('Bitcoin import via private key not supported');
      }

      return {
        privateKey: entropy,
        publicKey,
        address,
        chainType,
        curveType: chainType === ChainType.ETHEREUM ? CurveType.SECP256K1 : CurveType.ED25519,
        derivationPath: 'imported'
      };
    }

    const candidates = this.getSeedEntropyCandidates(shardA, shardB, entropy);
    const derivedCandidates = candidates.map((candidate) =>
      this.deriveSeedWalletFromEntropy(candidate, chainType, account, index)
    );

    if (expectedAddress) {
      const matched = derivedCandidates.find(
        (candidate) => candidate.address.toLowerCase() === expectedAddress.toLowerCase()
      );
      if (matched) {
        return matched;
      }
    }

    return derivedCandidates[0];
  }

  static async scanUsedAddresses(
    entropy: Buffer,
    chainType: ChainType,
    isSeedPhrase: boolean,
    gapLimit: number = 20
  ): Promise<WalletImportData[]> {
    if (!isSeedPhrase) {
      const { shardA, shardB } = this.splitEntropyIntoShards(entropy);
      const wallet = this.deriveWalletFromShards(
        shardA,
        shardB,
        chainType,
        0,
        0,
        false
      );
      return [{
        address: wallet.address,
        chainType: wallet.chainType,
        derivationPath: 'imported'
      }];
    }

    const mnemonic = SeedPhraseUtils.entropyToMnemonic(entropy);
    const seed = SeedPhraseUtils.mnemonicToSeed(mnemonic);
    const usedWallets: WalletImportData[] = [];

    let consecutiveEmpty = 0;
    let index = 0;

    while (consecutiveEmpty < gapLimit && index < 100) {
      let derived: DerivedWallet;
      
      switch (chainType) {
        case ChainType.ETHEREUM:
          derived = HDWalletDerivation.deriveEthereumWallet(seed, 0, index);
          break;
        case ChainType.SOLANA:
          derived = HDWalletDerivation.deriveSolanaWallet(seed, index);
          break;
        case ChainType.BITCOIN:
          derived = HDWalletDerivation.deriveBitcoinWallet(seed, 0, index);
          break;
        default:
          throw new Error('Unsupported chain type');
      }

      usedWallets.push({
        address: derived.address,
        chainType: derived.chainType,
        derivationPath: derived.derivationPath
      });

      consecutiveEmpty++;
      index++;
    }

    return usedWallets.slice(0, Math.min(5, usedWallets.length));
  }

  static verifyImport(
    entropy: Buffer,
    expectedAddress: string,
    chainType: ChainType,
    isSeedPhrase: boolean
  ): boolean {
    try {
      const { shardA, shardB } = this.splitEntropyIntoShards(entropy);
      const wallet = this.deriveWalletFromShards(
        shardA,
        shardB,
        chainType,
        0,
        0,
        isSeedPhrase
      );
      return wallet.address.toLowerCase() === expectedAddress.toLowerCase();
    } catch {
      return false;
    }
  }

  private static deriveSeedWalletFromEntropy(
    entropy: Buffer,
    chainType: ChainType,
    account: number,
    index: number
  ): MpcDerivedWallet {
    const mnemonic = SeedPhraseUtils.entropyToMnemonic(entropy);
    const seed = SeedPhraseUtils.mnemonicToSeed(mnemonic);

    let derived: DerivedWallet;
    switch (chainType) {
      case ChainType.ETHEREUM:
        derived = HDWalletDerivation.deriveEthereumWallet(seed, account, index);
        break;
      case ChainType.SOLANA:
        derived = HDWalletDerivation.deriveSolanaWallet(seed, account);
        break;
      case ChainType.BITCOIN:
        derived = HDWalletDerivation.deriveBitcoinWallet(seed, account, index);
        break;
      default:
        throw new Error('Unsupported chain type');
    }

    return {
      ...derived,
      curveType: chainType === ChainType.SOLANA ? CurveType.ED25519 : CurveType.SECP256K1
    };
  }

  private static getSeedEntropyCandidates(
    shardA: Buffer,
    shardB: Buffer,
    entropy: Buffer
  ): Buffer[] {
    const candidates: Buffer[] = [entropy];

    const isLegacyShareFormat = shardA.length === 33 && shardB.length === 33;
    const hasZeroPaddedPrefix =
      entropy.length === 32 && entropy.subarray(0, 16).every((byte) => byte === 0);

    // Legacy 12-word imports were encoded as 32-byte values with a zero-padded prefix.
    if (isLegacyShareFormat && hasZeroPaddedPrefix) {
      candidates.push(entropy.subarray(16));
    }

    return candidates;
  }
}
