import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { Keypair } from '@solana/web3.js';
import * as bitcoin from 'bitcoinjs-lib';
import { ChainType, CurveType, DerivedWallet } from '../types';

export { ChainType, CurveType, DerivedWallet };



export class HDWalletDerivation {
  private static readonly COIN_TYPES = {
    [ChainType.ETHEREUM]: 60,
    [ChainType.SOLANA]: 501,
    [ChainType.BITCOIN]: 0 
  };

  static buildPath(chain: ChainType, account: number = 0, index: number = 0): string {
    const coinType = this.COIN_TYPES[chain];
    
    if (chain === ChainType.SOLANA) {
      return `m/44'/${coinType}'/${account}'/0'`;
    }
    
    if (chain === ChainType.BITCOIN) {
      return `m/84'/${coinType}'/${account}'/0/${index}`; 
    }

    return `m/44'/${coinType}'/${account}'/0/${index}`;
  }

  static deriveFromSeed(seed: Buffer, derivationPath: string): HDKey {
    const masterKey = HDKey.fromMasterSeed(seed);
    return masterKey.derive(derivationPath);
  }

  static deriveEthereumWallet(seed: Buffer, account: number = 0, index: number = 0): DerivedWallet {
    const path = this.buildPath(ChainType.ETHEREUM, account, index);
    const derived = this.deriveFromSeed(seed, path);
    
    if (!derived.privateKey) {
      throw new Error('Failed to derive private key');
    }

    const publicKey = secp256k1.getPublicKey(derived.privateKey, false);
    const publicKeyBytes = publicKey.slice(1);
    const hash = keccak_256(publicKeyBytes);
    const addressBytes = hash.slice(-20);
    const address = '0x' + Buffer.from(addressBytes).toString('hex');

    return {
      privateKey: Buffer.from(derived.privateKey),
      publicKey: Buffer.from(publicKey),
      address,
      chainType: ChainType.ETHEREUM,
      derivationPath: path,
      curveType: CurveType.SECP256K1
    };
  }

  static deriveSolanaWallet(seed: Buffer, account: number = 0): DerivedWallet {
    const path = this.buildPath(ChainType.SOLANA, account);
    const derived = this.deriveFromSeed(seed, path);
    
    if (!derived.privateKey) {
      throw new Error('Failed to derive private key');
    }

    const keypair = Keypair.fromSeed(derived.privateKey.slice(0, 32));
    const address = keypair.publicKey.toBase58();

    return {
      privateKey: Buffer.from(keypair.secretKey.slice(0, 32)),
      publicKey: Buffer.from(keypair.publicKey.toBytes()),
      address,
      chainType: ChainType.SOLANA,
      derivationPath: path,
      curveType: CurveType.ED25519
    };
  }

  static deriveBitcoinWallet(
    seed: Buffer, 
    account: number = 0, 
    index: number = 0,
    network: bitcoin.Network = bitcoin.networks.bitcoin
  ): DerivedWallet {
    const path = `m/84'/0'/${account}'/0/${index}`;
    const derived = this.deriveFromSeed(seed, path);
    
    if (!derived.privateKey) {
      throw new Error('Failed to derive private key');
    }

    const publicKey = secp256k1.getPublicKey(derived.privateKey, true);
    
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: Buffer.from(publicKey),
      network
    });

    if (!address) {
      throw new Error('Failed to derive Bitcoin address');
    }

    return {
      privateKey: Buffer.from(derived.privateKey),
      publicKey: Buffer.from(publicKey),
      address,
      chainType: ChainType.BITCOIN,
      derivationPath: path,
      curveType: CurveType.SECP256K1
    };
  }
}