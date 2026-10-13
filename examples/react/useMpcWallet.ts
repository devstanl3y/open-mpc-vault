import { useCallback, useState } from 'react';

/**
 * React client for the express-prisma example routes. Assumes the router is
 * mounted at `basePath` and authenticates via cookies.
 */

export type CurveType = 'SECP256K1' | 'ED25519';
export type ChainType = 'ETHEREUM' | 'SOLANA' | 'BITCOIN';

export interface EncryptedShardA {
  encrypted: string;
  iv: string;
  tag: string;
  salt?: string;
}

export interface MpcWallet {
  id: string;
  walletName: string;
  publicAddress: string;
  curveType: CurveType;
  chainType: ChainType | null;
  derivationPath: string | null;
  shardBId: string;
  createdAt: string;
  lastUsedAt?: string | null;
}

export interface CreatedWallet extends MpcWallet {
  /** Must be persisted client-side; the server does not keep shard A. */
  encryptedShardA: EncryptedShardA;
}

export interface CreateVaultResult {
  wallets: CreatedWallet[];
  vaultId: string;
}

export interface SignResult {
  signature: string;
  /** secp256k1 recovery id; Ethereum `v` = 27 + recovery (or yParity). */
  recovery?: number;
}

async function request<T>(url: string, init: RequestInit, fallbackError: string): Promise<T> {
  const response = await fetch(url, {
    ...init,
    credentials: 'include',
    headers: init.body ? { 'Content-Type': 'application/json' } : undefined,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(typeof body?.message === 'string' ? body.message : fallbackError);
  }
  return body as T;
}

export function useMpcWallet(basePath = '/api/v1/mpc') {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async <T,>(operation: () => Promise<T>): Promise<T | null> => {
    setLoading(true);
    setError(null);
    try {
      return await operation();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const createVault = useCallback(
    (walletName: string, pin: string) =>
      run(() =>
        request<CreateVaultResult>(
          `${basePath}/create`,
          { method: 'POST', body: JSON.stringify({ walletName, pin }) },
          'Failed to create vault'
        )
      ),
    [basePath, run]
  );

  const listWallets = useCallback(
    () =>
      run(() => request<MpcWallet[]>(`${basePath}/wallets`, { method: 'GET' }, 'Failed to fetch wallets')),
    [basePath, run]
  );

  const sign = useCallback(
    (walletId: string, messageHash: string, pin: string, shardA: EncryptedShardA) =>
      run(() =>
        request<SignResult>(
          `${basePath}/sign`,
          {
            method: 'POST',
            body: JSON.stringify({
              walletId,
              messageHash,
              pin,
              shardAEncrypted: shardA.encrypted,
              shardAIv: shardA.iv,
              shardATag: shardA.tag,
              shardASalt: shardA.salt,
            }),
          },
          'Failed to sign'
        )
      ),
    [basePath, run]
  );

  const deleteWallet = useCallback(
    async (walletId: string, pin: string) =>
      (await run(() =>
        request<unknown>(
          `${basePath}/wallets/${encodeURIComponent(walletId)}`,
          { method: 'DELETE', body: JSON.stringify({ pin }) },
          'Failed to delete wallet'
        )
      )) !== null,
    [basePath, run]
  );

  return { loading, error, createVault, listWallets, sign, deleteWallet };
}