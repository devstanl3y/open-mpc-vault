import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { Keypair } from '@solana/web3.js';
import * as bitcoin from 'bitcoinjs-lib';
import { ChainType, CurveType, type DerivedWallet } from '../types';

export { ChainType, CurveType };
export type { DerivedWallet };

const MAX_HD_INDEX = 0x7fffffff;

function assertHdIndex(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > MAX_HD_INDEX) {
    throw new Error(`${name} must be an integer between 0 and ${MAX_HD_INDEX}`);
  }
}

export class HDWalletDerivation {
  private static readonly COIN_TYPES: Record<ChainType, number> = {
    [ChainType.ETHEREUM]: 60,
    [ChainType.SOLANA]: 501,
    [ChainType.BITCOIN]: 0,
  };

  /**
   * Build the derivation path for a chain.
   *
   * - Ethereum: BIP-44  m/44'/60'/{account}'/0/{index}
   * - Solana:   SLIP-10 m/44'/501'/{account}'/0'   (index is ignored)
   * - Bitcoin:  BIP-84  m/84'/0'/{account}'/0/{index}
   */
  static buildPath(chain: ChainType, account = 0, index = 0): string {
    assertHdIndex('account', account);
    assertHdIndex('index', index);

    const coinType = this.COIN_TYPES[chain];
    if (coinType === undefined) {
      throw new Error(`Unsupported chain type: ${String(chain)}`);
    }

    switch (chain) {
      case ChainType.SOLANA:
        return `m/44'/${coinType}'/${account}'/0'`;
      case ChainType.BITCOIN:
        return `m/84'/${coinType}'/${account}'/0/${index}`;
      default:
        return `m/44'/${coinType}'/${account}'/0/${index}`;
    }
  }

  static deriveFromSeed(seed: Buffer, derivationPath: string): HDKey {
    const master = HDKey.fromMasterSeed(seed);
    const node = master.derive(derivationPath);
    if (node !== master) {
      master.wipePrivateData();
    }
    return node;
  }

  /** Derive a wallet for any supported chain from a BIP-39 seed. */
  static deriveWallet(seed: Buffer, chain: ChainType, account = 0, index = 0): DerivedWallet {
    switch (chain) {
      case ChainType.ETHEREUM:
        return this.deriveEthereumWallet(seed, account, index);
      case ChainType.SOLANA:
        return this.deriveSolanaWallet(seed, account);
      case ChainType.BITCOIN:
        return this.deriveBitcoinWallet(seed, account, index);
      default:
        throw new Error(`Unsupported chain type: ${String(chain)}`);
    }
  }

  private static derivePrivateKey(seed: Buffer, path: string): Buffer {
    const node = this.deriveFromSeed(seed, path);
    try {
      if (!node.privateKey) {
        throw new Error('Failed to derive private key');
      }
      return Buffer.from(node.privateKey);
    } finally {
      node.wipePrivateData();
    }
  }

  static deriveEthereumWallet(seed: Buffer, account = 0, index = 0): DerivedWallet {
    const path = this.buildPath(ChainType.ETHEREUM, account, index);
    const privateKey = this.derivePrivateKey(seed, path);

    const publicKey = secp256k1.getPublicKey(privateKey, false);
    const address = '0x' + Buffer.from(keccak_256(publicKey.subarray(1)).subarray(-20)).toString('hex');

    return {
      privateKey,
      publicKey: Buffer.from(publicKey),
      address,
      chainType: ChainType.ETHEREUM,
      derivationPath: path,
      curveType: CurveType.SECP256K1,
    };
  }

  static deriveSolanaWallet(seed: Buffer, account = 0): DerivedWallet {
    const path = this.buildPath(ChainType.SOLANA, account);
    const derivedKey = this.derivePrivateKey(seed, path);

    try {
      const keypair = Keypair.fromSeed(derivedKey.subarray(0, 32));
      return {
        privateKey: Buffer.from(keypair.secretKey.subarray(0, 32)),
        publicKey: Buffer.from(keypair.publicKey.toBytes()),
        address: keypair.publicKey.toBase58(),
        chainType: ChainType.SOLANA,
        derivationPath: path,
        curveType: CurveType.ED25519,
      };
    } finally {
      derivedKey.fill(0);
    }
  }

  static deriveBitcoinWallet(
    seed: Buffer,
    account = 0,
    index = 0,
    network: bitcoin.Network = bitcoin.networks.bitcoin
  ): DerivedWallet {
    const path = this.buildPath(ChainType.BITCOIN, account, index);
    const privateKey = this.derivePrivateKey(seed, path);

    const publicKey = Buffer.from(secp256k1.getPublicKey(privateKey, true));
    const { address } = bitcoin.payments.p2wpkh({ pubkey: publicKey, network });
    if (!address) {
      privateKey.fill(0);
      throw new Error('Failed to derive Bitcoin address');
    }

    return {
      privateKey,
      publicKey,
      address,
      chainType: ChainType.BITCOIN,
      derivationPath: path,
      curveType: CurveType.SECP256K1,
    };
  }
}