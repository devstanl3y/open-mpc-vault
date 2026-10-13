import { Response } from 'express';
import { ShardStatus, UserSecurityEventType } from '@prisma/client';
import { ChainType, MpcKeyGenerator, ShardEncryption, ShardStorage } from 'open-mpc-vault';
import {
  prisma,
  logger,
  cloudBackupService,
  logSecurityEvent,
  getRequestContext,
  PolicyService,
  type IUserRequest,
} from '../host';
import { chainLabel, verifyUserPin, zeroizeBuffers } from './shared';

const DEFAULT_CHAINS = [ChainType.ETHEREUM, ChainType.SOLANA, ChainType.BITCOIN] as const;

export const createMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletName, pin } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  if (typeof walletName !== 'string' || walletName.trim().length === 0) {
    return res.status(400).json({ message: 'walletName is required' });
  }

  let mpcSeed: ReturnType<typeof MpcKeyGenerator.createMpcSeed> | undefined;

  try {
    const pinCheck = await verifyUserPin(userId, pin);
    if (!pinCheck.ok) {
      return res.status(pinCheck.status).json({ message: pinCheck.message });
    }
    const { pinWithPepper } = pinCheck;

    const cloudProvider = await prisma.userCloudProvider.findUnique({ where: { userId } });
    if (!cloudProvider?.isConnected) {
      return res.status(400).json({
        message: 'A cloud backup provider must be connected before creating a vault',
        requireCloudConnection: true,
      });
    }

    mpcSeed = MpcKeyGenerator.createMpcSeed(12);
    const encryptedShardA = ShardEncryption.encryptShardA(mpcSeed.shardA, pinWithPepper);
    const shardBId = await ShardStorage.storeShardB(mpcSeed.shardB, userId);

    const createdWalletIds: string[] = [];
    const createdWallets = [];

    try {
      for (const chainType of DEFAULT_CHAINS) {
        const derived = MpcKeyGenerator.deriveWalletFromShards(
          mpcSeed.shardA,
          mpcSeed.shardB,
          chainType,
          0,
          0,
          true
        );
        derived.privateKey.fill(0);

        const mpcWallet = await prisma.mpcWallet.create({
          data: {
            userId,
            walletName: `${walletName.trim()} (${chainLabel(chainType)})`,
            publicAddress: derived.address,
            curveType: derived.curveType,
            chainType: derived.chainType,
            derivationPath: derived.derivationPath,
            accountIndex: 0,
            addressIndex: 0,
            isImported: false,
            isSeedPhrase: true,
            shardBId,
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
          shardBId,
          derived.derivationPath,
          derived.curveType,
          0,
          0,
          encryptedShardA.salt
        );
        logSecurityEvent(userId, UserSecurityEventType.CLOUD_BACKUP_CREATED, context);

        createdWallets.push({
          id: mpcWallet.id,
          walletName: mpcWallet.walletName,
          publicAddress: mpcWallet.publicAddress,
          curveType: mpcWallet.curveType,
          chainType: mpcWallet.chainType,
          derivationPath: mpcWallet.derivationPath,
          shardBId,
          createdAt: mpcWallet.createdAt,
          encryptedShardA,
        });
      }
    } catch (error) {
      logger.error('mpc.wallet_create.rollback', { userId, err: error });
      await prisma.mpcWallet
        .deleteMany({ where: { id: { in: createdWalletIds } } })
        .catch(() => undefined);
      await ShardStorage.deleteShardB(shardBId).catch(() => undefined);
      throw error;
    }

    await prisma.user.update({ where: { id: userId }, data: { mpc_enabled: true } });
    await PolicyService.getOrCreatePolicy(userId);
    logSecurityEvent(userId, UserSecurityEventType.MPC_WALLET_CREATED, context);

    return res.status(201).json({
      wallets: createdWallets,
      vaultId: shardBId,
      cloudBackupEnabled: true,
    });
  } catch (error) {
    logger.error('mpc.wallet_create.failed', { userId, err: error });
    return res.status(500).json({ message: 'Failed to create MPC wallets' });
  } finally {
    if (mpcSeed) zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);
  }
};
