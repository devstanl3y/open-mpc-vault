import { ChainType, CurveType } from '../types';
import { MpcKeyGenerator, type MpcDerivedWallet } from './keyGenerator';

export interface MpcWalletDerivationMeta {
  publicAddress?: string;
  chainType?: ChainType | null;
  curveType?: CurveType | null;
  isSeedPhrase?: boolean;
  accountIndex?: number;
  addressIndex?: number;
}

function resolveChainType(meta: MpcWalletDerivationMeta): ChainType {
  if (meta.chainType) {
    return meta.chainType;
  }

  if (meta.curveType === CurveType.ED25519) {
    return ChainType.SOLANA;
  }

  return ChainType.ETHEREUM;
}

export function deriveWalletFromShards(params: {
  shardA: Buffer;
  shardB: Buffer;
  chainType?: ChainType;
  curveType?: CurveType;
  isSeedPhrase?: boolean;
  accountIndex?: number;
  addressIndex?: number;
  publicAddress?: string;
}): MpcDerivedWallet {
  const chainType = resolveChainType(params);
  return MpcKeyGenerator.deriveWalletFromShards(
    params.shardA,
    params.shardB,
    chainType,
    params.accountIndex ?? 0,
    params.addressIndex ?? 0,
    params.isSeedPhrase ?? true,
    params.publicAddress
  );
}

export function deriveWalletFromShardsForMpcWallet(params: {
  shardA: Buffer;
  shardB: Buffer;
  wallet: MpcWalletDerivationMeta;
}): MpcDerivedWallet {
  return deriveWalletFromShards({
    shardA: params.shardA,
    shardB: params.shardB,
    chainType: params.wallet.chainType ?? undefined,
    curveType: params.wallet.curveType ?? undefined,
    isSeedPhrase: params.wallet.isSeedPhrase,
    accountIndex: params.wallet.accountIndex,
    addressIndex: params.wallet.addressIndex,
    publicAddress: params.wallet.publicAddress,
  });
}

export function addressesEqual(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}
