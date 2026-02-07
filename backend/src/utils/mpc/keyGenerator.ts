import { ShamirSecretSharing } from './shamir';
import { SeedPhraseUtils } from './seedPhrase';
import { HDWalletDerivation, ChainType, DerivedWallet } from './hdWallet';
import { CurveType } from '@prisma/client';

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
    isSeedPhrase: boolean = true
  ): MpcDerivedWallet {
    const entropy = this.reconstructEntropy(shardA, shardB);

    if (!isSeedPhrase) {
      let address: string;
      let publicKey: Buffer;
      
      if (chainType === ChainType.ETHEREUM) {
        const { secp256k1 } = require('@noble/curves/secp256k1');
        const pubKey = secp256k1.getPublicKey(entropy, false);
        const crypto = require('crypto');
        const publicKeyHash = crypto.createHash('sha256').update(Buffer.from(pubKey)).digest();
        const ripemd = crypto.createHash('ripemd160').update(publicKeyHash).digest();
        address = '0x' + ripemd.slice(-20).toString('hex');
        publicKey = Buffer.from(pubKey);
      } else if (chainType === ChainType.SOLANA) {
        const { ed25519 } = require('@noble/curves/ed25519');
        const pubKey = ed25519.getPublicKey(entropy);
        const bs58 = require('bs58');
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

  static async scanUsedAddresses(
    entropy: Buffer,
    chainType: ChainType,
    isSeedPhrase: boolean,
    gapLimit: number = 20
  ): Promise<WalletImportData[]> {
    if (!isSeedPhrase) {
      const wallet = this.deriveWalletFromShards(
        this.splitEntropyIntoShards(entropy).shardA,
        this.splitEntropyIntoShards(entropy).shardB,
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
}