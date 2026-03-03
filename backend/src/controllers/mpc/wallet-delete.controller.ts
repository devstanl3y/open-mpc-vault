import { Response } from 'express';
import bcrypt from 'bcrypt';
import type { IUserRequest } from '../../middleware/requireAuth';
import prisma from '../../utils/prisma';
import { cloudBackupService } from '../../utils/cloudBackup';
import { ShardStorage } from '../../utils/mpc/shardStorage';
import { SessionKeyManager } from '../../utils/sessionKey';
import { PIN_PEPPER } from './shared';

export const deleteMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletId } = req.params;
  const { pin } = req.body;
  const userId = Number(req.user?.id);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (typeof walletId !== 'string') {
    return res.status(400).json({ message: 'Invalid wallet ID format' });
  }

  if (!pin) {
    return res.status(400).json({ message: 'PIN is required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });

    if (!user || !user.pin_hash) {
      return res.status(401).json({ message: 'User PIN not set' });
    }
    const pinWithPepper = pin + PIN_PEPPER;
    const isPinValid = await bcrypt.compare(pinWithPepper, user.pin_hash);
    if (!isPinValid) {
      return res.status(401).json({ message: 'Invalid PIN' });
    }

    const mpcWallet = await prisma.mpcWallet.findFirst({
      where: {
        id: walletId,
        userId,
      },
    });

    if (!mpcWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    const walletsWithSameShardB = await prisma.mpcWallet.count({
      where: {
        shardBId: mpcWallet.shardBId,
        userId,
        id: { not: walletId },
      },
    });

    try {
      await cloudBackupService.deleteBackup(userId, walletId);
    } catch {
      // best-effort cleanup
    }

    await SessionKeyManager.revokeAllUserSessions(userId);

    if (walletsWithSameShardB === 0) {
      await ShardStorage.deleteShardB(mpcWallet.shardBId);
    }

    await prisma.mpcWallet.delete({
      where: { id: walletId },
    });

    res.status(200).json({ message: 'MPC wallet deleted successfully' });
  } catch (error) {
    console.error('Error deleting MPC wallet:', error);
    res.status(500).json({ message: 'Failed to delete MPC wallet' });
  }
};
