import { useState, useCallback } from 'react';
import { ShardEncryption } from '../crypto/shardEncryption';

export interface MpcWallet {
  id: string;
  walletName: string;
  publicAddress: string;
  curveType: 'SECP256K1' | 'ED25519';
  createdAt: string;
  lastUsedAt?: string;
}

export function useMpcWallet() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const createMpcWallet = useCallback(
    async (
      walletName: string,
      curveType: 'SECP256K1' | 'ED25519',
      pin: string
    ): Promise<MpcWallet | null> => {
      setLoading(true);
      setError(null);

      try {
        const response = await fetch('/api/v1/mpc/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ walletName, curveType, pin }),
        });

        if (!response.ok) {
          const data = await response.json();
          throw new Error(data.message || 'Failed to create MPC wallet');
        }

        const wallet = await response.json();
        return wallet;
      } catch (err: any) {
        setError(err.message);
        return null;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  const getMpcWallets = useCallback(async (): Promise<MpcWallet[]> => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/mpc', {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch MPC wallets');
      }

      return await response.json();
    } catch (err: any) {
      setError(err.message);
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  const signWithMpcWallet = useCallback(
    async (
      walletId: string,
      messageHash: string,
      pin: string
    ): Promise<string | null> => {
      setLoading(true);
      setError(null);

      try {
        const response = await fetch('/api/v1/mpc/sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ walletId, messageHash, pin }),
        });

        if (!response.ok) {
          const data = await response.json();
          throw new Error(data.message || 'Failed to sign message');
        }

        const { signature } = await response.json();
        return signature;
      } catch (err: any) {
        setError(err.message);
        return null;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  const deleteMpcWallet = useCallback(
    async (walletId: string, pin: string): Promise<boolean> => {
      setLoading(true);
      setError(null);

      try {
        const response = await fetch(`/api/v1/mpc/${walletId}`, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ pin }),
        });

        if (!response.ok) {
          const data = await response.json();
          throw new Error(data.message || 'Failed to delete MPC wallet');
        }

        return true;
      } catch (err: any) {
        setError(err.message);
        return false;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return {
    loading,
    error,
    createMpcWallet,
    getMpcWallets,
    signWithMpcWallet,
    deleteMpcWallet,
  };
}