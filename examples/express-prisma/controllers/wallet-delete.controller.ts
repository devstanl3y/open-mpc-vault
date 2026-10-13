import { Response } from 'express';
import { ShardStorage } from 'open-mpc-vault';
import { prisma, logger, cloudBackupService, SessionKeyManager, type IUserRequest } from '../host';
import { verifyUserPin } from './shared';

export const deleteMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletId } = req.params;
  const userId = Number(req.user?.id);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  if (typeof walletId !== 'string' || walletId.length === 0) {
    return res.status(400).json({ message: 'Invalid wallet ID format' });
  }

  try {
    const pinCheck = await verifyUserPin(userId, req.body?.pin);
    if (!pinCheck.ok) {
      return res.status(pinCheck.status).json({ message: pinCheck.message });
    }

    const wallet = await prisma.mpcWallet.findFirst({
      where: { id: walletId, userId },
      select: { id: true, shardBId: true },
    });
    if (!wallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    // Remove the database record first. If anything after this fails we leak
    // an orphaned shard or backup, which is recoverable, rather than leaving a
    // wallet row that points at a deleted shard.
    await prisma.mpcWallet.delete({ where: { id: walletId } });

    const remaining = await prisma.mpcWallet.count({
      where: { shardBId: wallet.shardBId },
    });
    if (remaining === 0) {
      await ShardStorage.deleteShardB(wallet.shardBId);
    }

    await SessionKeyManager.revokeAllUserSessions(userId);

    await cloudBackupService.deleteBackup(userId, walletId).catch((err: unknown) => {
      logger.warn('mpc.wallet_delete.backup_cleanup_failed', { userId, walletId, err });
    });

    return res.status(200).json({ message: 'MPC wallet deleted' });
  } catch (error) {
    logger.error('mpc.wallet_delete.failed', { userId, walletId, err: error });
    return res.status(500).json({ message: 'Failed to delete MPC wallet' });
  }
};
