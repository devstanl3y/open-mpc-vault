import { Response } from 'express';
import bcrypt from 'bcrypt';
import { ShardStatus, UserSecurityEventType } from '@prisma/client';
import type { IUserRequest } from '../../middleware/requireAuth';
import prisma from '../../utils/prisma';
import { MpcKeyGenerator } from '../../utils/mpc/keyGenerator';
import { ShardEncryption } from '../../utils/mpc/shardEncryption';
import { ShardStorage } from '../../utils/mpc/shardStorage';
import { ChainType } from '../../utils/mpc/hdWallet';
import { logSecurityEvent } from '../../utils/securityLogger';
import { getRequestContext } from '../../utils/context';
import { cloudBackupService } from '../../utils/cloudBackup';
import { PolicyService } from '../../utils/policyService';
import { PIN_PEPPER, zeroizeBuffers } from './shared';

export const createMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletName, pin } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!walletName || !pin) {
    return res.status(400).json({
      message: 'walletName and pin are required',
    });
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

    const cloudProvider = await prisma.userCloudProvider.findUnique({
      where: { userId },
    });

    if (!cloudProvider || !cloudProvider.isConnected) {
      return res.status(400).json({
        message: 'Google Drive must be connected before creating a vault',
        requireCloudConnection: true,
      });
    }

    const mpcSeed = MpcKeyGenerator.createMpcSeed(12);
    const encryptedShardA = ShardEncryption.encryptShardA(mpcSeed.shardA, pinWithPepper);

    const sharedShardBId = await ShardStorage.storeShardB(mpcSeed.shardB, userId);

    const chainConfigs = [
      { chainType: ChainType.ETHEREUM, suffix: 'EVM', account: 0, index: 0 },
      { chainType: ChainType.SOLANA, suffix: 'Solana', account: 0, index: 0 },
      { chainType: ChainType.BITCOIN, suffix: 'Bitcoin', account: 0, index: 0 },
    ];

    const createdWallets = [];
    const createdWalletIds: string[] = [];

    try {
      for (const config of chainConfigs) {
        const derived = MpcKeyGenerator.deriveWalletFromShards(
          mpcSeed.shardA,
          mpcSeed.shardB,
          config.chainType,
          config.account,
          config.index,
          true,
        );

        const fullWalletName = `${walletName} (${config.suffix})`;

        const mpcWallet = await prisma.mpcWallet.create({
          data: {
            userId,
            walletName: fullWalletName,
            publicAddress: derived.address,
            curveType: derived.curveType,
            chainType: derived.chainType,
            derivationPath: derived.derivationPath,
            accountIndex: config.account,
            addressIndex: config.index,
            isImported: false,
            isSeedPhrase: true,
            shardBId: sharedShardBId,
            status: ShardStatus.ACTIVE,
          },
        });

        createdWalletIds.push(mpcWallet.id);

        await cloudBackupService.backupShardA(
          userId,
          mpcWallet.id,
          mpcWallet.publicAddress,
          encryptedShardA.encrypted,
          encryptedShardA.iv,
          encryptedShardA.tag,
          pinWithPepper,
          derived.chainType,
          sharedShardBId,
          derived.derivationPath,
          derived.curveType,
          config.account,
          config.index,
          encryptedShardA.salt,
        );

        createdWallets.push({
          id: mpcWallet.id,
          walletName: mpcWallet.walletName,
          publicAddress: mpcWallet.publicAddress,
          curveType: mpcWallet.curveType,
          chainType: mpcWallet.chainType,
          derivationPath: mpcWallet.derivationPath,
          shardBId: sharedShardBId,
          createdAt: mpcWallet.createdAt,
          encryptedShardA: {
            encrypted: encryptedShardA.encrypted,
            iv: encryptedShardA.iv,
            tag: encryptedShardA.tag,
            salt: encryptedShardA.salt,
          },
        });

        logSecurityEvent(userId, UserSecurityEventType.CLOUD_BACKUP_CREATED, context);
      }

      zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);

      await prisma.user.update({
        where: { id: userId },
        data: { mpc_enabled: true },
      });

      await PolicyService.getOrCreatePolicy(userId);

      logSecurityEvent(userId, UserSecurityEventType.MPC_WALLET_CREATED, context);

      res.status(201).json({
        wallets: createdWallets,
        vaultId: sharedShardBId,
        cloudBackupEnabled: true,
        message: 'Vault created successfully. Your keys are secured with MPC and backed up to cloud.',
      });
    } catch (error) {
      console.error('Failed to create wallets:', error);

      for (const walletId of createdWalletIds) {
        await prisma.mpcWallet.delete({ where: { id: walletId } }).catch(() => {});
      }

      await ShardStorage.deleteShardB(sharedShardBId).catch(() => {});

      throw error;
    }
  } catch (error) {
    console.error('MPC wallet creation error:', error);
    res.status(500).json({ message: 'Failed to create MPC wallets' });
  }
};
