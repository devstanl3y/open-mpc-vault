import { ChainType, CurveType } from '@prisma/client';
import { MpcKeyGenerator, type MpcDerivedWallet } from './keyGenerator';

export interface MpcWalletDerivationMeta {
  publicAddress: string;
  chainType?: ChainType | null;
  curveType?: CurveType | null;
  isSeedPhrase: boolean;
  accountIndex: number;
  addressIndex: number;
}

function resolveChainType(meta: MpcWalletDerivationMeta): ChainType {
  if (meta.chainType) {
    return meta.chainType;
  }

  if (meta.curveType === CurveType.ED25519) {
    return ChainType.SOLANA;
  }

  // SECP256K1 is compatible with EVM derivation fallback.
  return ChainType.ETHEREUM;
}

export function deriveWalletFromShardsForMpcWallet(params: {
  shardA: Buffer;
  shardB: Buffer;
  wallet: MpcWalletDerivationMeta;
}): MpcDerivedWallet {
  const chainType = resolveChainType(params.wallet);
  return MpcKeyGenerator.deriveWalletFromShards(
    params.shardA,
    params.shardB,
    chainType,
    params.wallet.accountIndex,
    params.wallet.addressIndex,
    params.wallet.isSeedPhrase,
    params.wallet.publicAddress
  );
}

export function addressesEqual(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}
