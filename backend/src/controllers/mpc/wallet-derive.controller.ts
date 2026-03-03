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
import { PIN_PEPPER, zeroizeBuffers } from './shared';

export const deriveAdditionalWallet = async (req: IUserRequest, res: Response) => {
  const {
    walletId,
    pin,
    chainType,
    accountIndex,
    addressIndex = 0,
    shardAEncrypted,
    shardAIv,
    shardATag,
    shardASalt,
  } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!walletId || !pin || !chainType || accountIndex === undefined || !shardAEncrypted || !shardAIv || !shardATag) {
    return res.status(400).json({
      message: 'walletId, pin, chainType, accountIndex, and encrypted shard A data are required',
    });
  }

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;

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

    const existingWallet = await prisma.mpcWallet.findFirst({
      where: {
        id: walletId,
        userId,
        status: ShardStatus.ACTIVE,
      },
    });

    if (!existingWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    if (!existingWallet.isSeedPhrase) {
      return res.status(400).json({
        message: 'Cannot derive additional wallets from imported private keys',
      });
    }

    shardA = ShardEncryption.decryptShardA(
      shardAEncrypted,
      shardAIv,
      shardATag,
      pinWithPepper,
      shardASalt,
    );

    shardB = await ShardStorage.retrieveShardBForUser(existingWallet.shardBId, userId);
    if (!shardB) {
      return res.status(500).json({ message: 'Shard B not found' });
    }

    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardA,
      shardB,
      chainType as ChainType,
      accountIndex,
      addressIndex,
      true,
    );

    const existingAddress = await prisma.mpcWallet.findFirst({
      where: {
        publicAddress: derived.address,
        userId,
      },
    });

    if (existingAddress) {
      return res.status(400).json({
        message: 'This wallet address already exists in your account',
      });
    }

    const chainSuffix =
      chainType === ChainType.ETHEREUM
        ? 'EVM'
        : chainType === ChainType.SOLANA
          ? 'Solana'
          : 'Bitcoin';
    const walletName = `Wallet ${accountIndex + 1} (${chainSuffix})`;

    const encryptedShardA = ShardEncryption.encryptShardA(shardA, pinWithPepper);

    const newWallet = await prisma.mpcWallet.create({
      data: {
        userId,
        walletName,
        publicAddress: derived.address,
        curveType: derived.curveType,
        chainType: derived.chainType,
        derivationPath: derived.derivationPath,
        accountIndex,
        addressIndex,
        isImported: false,
        isSeedPhrase: true,
        shardBId: existingWallet.shardBId,
        status: ShardStatus.ACTIVE,
      },
    });

    await cloudBackupService.backupShardA(
      userId,
      newWallet.id,
      newWallet.publicAddress,
      encryptedShardA.encrypted,
      encryptedShardA.iv,
      encryptedShardA.tag,
      pinWithPepper,
      derived.chainType,
      existingWallet.shardBId,
      derived.derivationPath,
      derived.curveType,
      accountIndex,
      addressIndex,
      encryptedShardA.salt,
    );

    logSecurityEvent(userId, UserSecurityEventType.MPC_WALLET_CREATED, context);

    res.status(201).json({
      id: newWallet.id,
      walletName: newWallet.walletName,
      publicAddress: newWallet.publicAddress,
      curveType: newWallet.curveType,
      chainType: newWallet.chainType,
      derivationPath: newWallet.derivationPath,
      createdAt: newWallet.createdAt,
    });
  } catch (error) {
    console.error('Wallet derivation error:', error);
    res.status(500).json({ message: 'Failed to derive additional wallet' });
  } finally {
    zeroizeBuffers(shardA, shardB);
  }
};
