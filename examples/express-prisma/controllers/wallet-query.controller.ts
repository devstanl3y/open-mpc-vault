import { Response } from 'express';
import { ShardStatus } from '@prisma/client';
import { prisma, logger, type IUserRequest } from '../host';

export const getMpcWallets = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const wallets = await prisma.mpcWallet.findMany({
      where: {
        userId,
        status: ShardStatus.ACTIVE,
      },
      select: {
        id: true,
        walletName: true,
        publicAddress: true,
        curveType: true,
        chainType: true,
        derivationPath: true,
        accountIndex: true,
        addressIndex: true,
        isImported: true,
        isSeedPhrase: true,
        createdAt: true,
        shardBId: true,
        lastUsedAt: true,
        shardABackups: {
          select: {
            lastSyncedAt: true,
          },
          orderBy: {
            lastSyncedAt: 'desc',
          },
          take: 1,
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    const walletsWithBackupStatus = wallets.map((wallet) => ({
      id: wallet.id,
      walletName: wallet.walletName,
      publicAddress: wallet.publicAddress,
      curveType: wallet.curveType,
      chainType: wallet.chainType,
      derivationPath: wallet.derivationPath,
      accountIndex: wallet.accountIndex,
      addressIndex: wallet.addressIndex,
      isImported: wallet.isImported,
      isSeedPhrase: wallet.isSeedPhrase,
      shardBId: wallet.shardBId,
      createdAt: wallet.createdAt,
      lastUsedAt: wallet.lastUsedAt,
      cloudBackupEnabled: wallet.shardABackups.length > 0,
      lastBackupSync: wallet.shardABackups[0]?.lastSyncedAt || null,
    }));

    res.status(200).json(walletsWithBackupStatus);
  } catch (error) {
    logger.error('mpc.wallet_query.wallets_fetch_failed', { userId, err: error });
    res.status(500).json({ message: 'Failed to fetch MPC wallets' });
  }
};

export const getUserVaults = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const wallets = await prisma.mpcWallet.findMany({
      where: {
        userId,
        status: ShardStatus.ACTIVE,
      },
      select: {
        shardBId: true,
        createdAt: true,
        walletName: true,
      },
      distinct: ['shardBId'],
      orderBy: { createdAt: 'desc' },
    });

    const vaults = wallets.map((wallet) => ({
      shardBId: wallet.shardBId,
      createdAt: wallet.createdAt,
      vaultName: wallet.walletName.split(' (')[0],
    }));

    res.status(200).json(vaults);
  } catch (error) {
    logger.error('mpc.wallet_query.vaults_fetch_failed', { userId, err: error });
    res.status(500).json({ message: 'Failed to fetch vaults' });
  }
};
