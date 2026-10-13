import { Response } from 'express';
import { ShardStatus, UserSecurityEventType } from '@prisma/client';
import { MpcKeyGenerator, ShardEncryption, ShardStorage } from 'open-mpc-vault';
import {
  prisma,
  logger,
  cloudBackupService,
  logSecurityEvent,
  getRequestContext,
  type IUserRequest,
} from '../host';
import { chainLabel, parseChainType, parseHdIndex, verifyUserPin, zeroizeBuffers } from './shared';

export const deriveAdditionalWallet = async (req: IUserRequest, res: Response) => {
  const { walletId, shardAEncrypted, shardAIv, shardATag, shardASalt } = req.body;
  const chainType = parseChainType(req.body.chainType);
  const accountIndex = parseHdIndex(req.body.accountIndex);
  const addressIndex = parseHdIndex(req.body.addressIndex ?? 0);
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  if (
    typeof walletId !== 'string' ||
    !chainType ||
    accountIndex === null ||
    addressIndex === null ||
    !shardAEncrypted ||
    !shardAIv ||
    !shardATag
  ) {
    return res.status(400).json({
      message:
        'walletId, chainType, integer accountIndex/addressIndex, and encrypted shard A data are required',
    });
  }

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;

  try {
    const pinCheck = await verifyUserPin(userId, req.body.pin);
    if (!pinCheck.ok) {
      return res.status(pinCheck.status).json({ message: pinCheck.message });
    }
    const { pinWithPepper } = pinCheck;

    const existingWallet = await prisma.mpcWallet.findFirst({
      where: { id: walletId, userId, status: ShardStatus.ACTIVE },
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
      shardASalt
    );

    shardB = await ShardStorage.retrieveShardBForUser(existingWallet.shardBId, userId);
    if (!shardB) {
      logger.error('mpc.wallet_derive.shard_b_missing', { userId, walletId });
      return res.status(500).json({ message: 'Server shard unavailable' });
    }

    // Confirm the client-supplied shard belongs to this vault before deriving
    // a new wallet from it.
    const reference = MpcKeyGenerator.deriveWalletFromShards(
      shardA,
      shardB,
      existingWallet.chainType ?? chainType,
      existingWallet.accountIndex,
      existingWallet.addressIndex,
      true,
      existingWallet.publicAddress
    );
    reference.privateKey.fill(0);
    if (reference.address.toLowerCase() !== existingWallet.publicAddress.toLowerCase()) {
      return res.status(403).json({ message: 'Shard payload does not match selected wallet' });
    }

    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardA,
      shardB,
      chainType,
      accountIndex,
      addressIndex,
      true
    );
    derived.privateKey.fill(0);

    const duplicate = await prisma.mpcWallet.findFirst({
      where: { publicAddress: derived.address, userId },
      select: { id: true },
    });
    if (duplicate) {
      return res.status(409).json({ message: 'This wallet address already exists in your account' });
    }

    const encryptedShardA = ShardEncryption.encryptShardA(shardA, pinWithPepper);

    const newWallet = await prisma.mpcWallet.create({
      data: {
        userId,
        walletName: `Wallet ${accountIndex + 1} (${chainLabel(chainType)})`,
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
      encryptedShardA.salt
    );

    logSecurityEvent(userId, UserSecurityEventType.MPC_WALLET_CREATED, context);

    return res.status(201).json({
      id: newWallet.id,
      walletName: newWallet.walletName,
      publicAddress: newWallet.publicAddress,
      curveType: newWallet.curveType,
      chainType: newWallet.chainType,
      derivationPath: newWallet.derivationPath,
      createdAt: newWallet.createdAt,
      encryptedShardA,
    });
  } catch (error) {
    logger.error('mpc.wallet_derive.failed', {
      userId,
      walletId,
      chainType,
      accountIndex,
      addressIndex,
      err: error,
    });
    return res.status(500).json({ message: 'Failed to derive additional wallet' });
  } finally {
    zeroizeBuffers(shardA, shardB);
  }
};
