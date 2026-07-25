import { Response } from 'express';
import bcrypt from 'bcrypt';
import { CurveType, ShardStatus, UserSecurityEventType } from '@prisma/client';
import type { IUserRequest } from '../../middleware/requireAuth';
import prisma from '../../utils/prisma';
import { ShardEncryption } from '../../utils/mpc/shardEncryption';
import { ShardStorage } from '../../utils/mpc/shardStorage';
import { SessionKeyManager } from '../../utils/sessionKey';
import { logSecurityEvent } from '../../utils/securityLogger';
import { getRequestContext } from '../../utils/context';
import { addressesEqual, deriveWalletFromShardsForMpcWallet } from '../../utils/mpc/walletDerivation';
import { getSessionShardFromRequestBody } from '../../utils/sessionShard';
import { PIN_PEPPER, zeroizeBuffers } from './shared';
import { logger } from '../../utils/logger';

export const signWithMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletId, messageHash, pin, shardAEncrypted, shardAIv, shardATag, shardASalt } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;
  let privateKey: Buffer | undefined;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!walletId || !messageHash || !pin || !shardAEncrypted || !shardAIv || !shardATag) {
    return res.status(400).json({
      message: 'walletId, messageHash, pin, and encrypted shard A data are required',
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

    const mpcWallet = await prisma.mpcWallet.findFirst({
      where: {
        id: walletId,
        userId,
        status: ShardStatus.ACTIVE,
      },
    });

    if (!mpcWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    shardA = ShardEncryption.decryptShardA(
      shardAEncrypted,
      shardAIv,
      shardATag,
      pinWithPepper,
      shardASalt,
    );

    shardB = await ShardStorage.retrieveShardBForUser(mpcWallet.shardBId, userId);
    if (!shardB) {
      return res.status(500).json({ message: 'Shard B not found' });
    }

    const derivedWallet = deriveWalletFromShardsForMpcWallet({
      shardA,
      shardB,
      wallet: {
        publicAddress: mpcWallet.publicAddress,
        chainType: mpcWallet.chainType,
        curveType: mpcWallet.curveType,
        isSeedPhrase: mpcWallet.isSeedPhrase,
        accountIndex: mpcWallet.accountIndex,
        addressIndex: mpcWallet.addressIndex,
      },
    });

    if (!addressesEqual(derivedWallet.address, mpcWallet.publicAddress)) {
      return res.status(403).json({ message: 'Shard payload does not match selected wallet' });
    }

    privateKey = Buffer.from(derivedWallet.privateKey);

    let signature: string;
    const messageBuffer = Buffer.from(messageHash.replace('0x', ''), 'hex');

    if (mpcWallet.curveType === CurveType.SECP256K1) {
      const { secp256k1 } = await import('@noble/curves/secp256k1');
      const sig = secp256k1.sign(messageBuffer, privateKey);
      signature = '0x' + sig.toCompactHex();
    } else {
      const { ed25519 } = await import('@noble/curves/ed25519');
      const sig = ed25519.sign(messageBuffer, privateKey);
      signature = Buffer.from(sig).toString('hex');
    }

    await prisma.mpcWallet.update({
      where: { id: walletId },
      data: { lastUsedAt: new Date() },
    });

    logSecurityEvent(userId, UserSecurityEventType.MPC_SIGNATURE_GENERATED, context);

    res.status(200).json({ signature });
  } catch (error) {
    logger.error('mpc.signing.failed', {
      userId,
      walletId,
      err: error,
    });
    res.status(500).json({ message: 'Failed to sign with MPC wallet' });
  } finally {
    zeroizeBuffers(shardA, shardB, privateKey);
  }
};

export const signWithSession = async (req: IUserRequest, res: Response) => {
  const { messageHash, sessionToken } = req.body;
  const sessionShard = getSessionShardFromRequestBody(req.body);

  const walletId = req.body.walletId || req.body.mpcWalletId;

  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;
  let privateKey: Buffer | undefined;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!walletId || !messageHash || !sessionToken || !sessionShard) {
    return res.status(400).json({
      message: 'walletId, messageHash, sessionToken, and sessionShard are required',
    });
  }

  try {
    const session = await SessionKeyManager.validateSession(sessionToken);

    if (!session) {
      return res.status(401).json({
        message: 'Invalid or expired session',
        code: 'SESSION_INVALID',
      });
    }

    if (session.userId !== userId || session.mpcWalletId !== walletId) {
      return res.status(403).json({
        message: 'Session does not match wallet or user',
        code: 'SESSION_MISMATCH',
      });
    }

    const mpcWallet = await prisma.mpcWallet.findFirst({
      where: {
        id: walletId,
        userId,
        status: ShardStatus.ACTIVE,
      },
    });

    if (!mpcWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    shardA = await SessionKeyManager.decryptSessionShard({
      sessionToken,
      sessionShard,
    });

    shardB = await ShardStorage.retrieveShardBForUser(mpcWallet.shardBId, userId);
    if (!shardB) {
      return res.status(500).json({ message: 'Shard B not found' });
    }

    const derivedWallet = deriveWalletFromShardsForMpcWallet({
      shardA,
      shardB,
      wallet: {
        publicAddress: mpcWallet.publicAddress,
        chainType: mpcWallet.chainType,
        curveType: mpcWallet.curveType,
        isSeedPhrase: mpcWallet.isSeedPhrase,
        accountIndex: mpcWallet.accountIndex,
        addressIndex: mpcWallet.addressIndex,
      },
    });

    if (!addressesEqual(derivedWallet.address, mpcWallet.publicAddress)) {
      return res.status(403).json({ message: 'Session shard does not match selected wallet' });
    }

    privateKey = Buffer.from(derivedWallet.privateKey);

    let signature: string;
    const messageBuffer = Buffer.from(messageHash.replace('0x', ''), 'hex');

    if (mpcWallet.curveType === CurveType.SECP256K1) {
      const { secp256k1 } = await import('@noble/curves/secp256k1');
      const sig = secp256k1.sign(messageBuffer, privateKey);
      signature = '0x' + sig.toCompactHex();
    } else {
      const { ed25519 } = await import('@noble/curves/ed25519');
      const sig = ed25519.sign(messageBuffer, privateKey);
      signature = Buffer.from(sig).toString('hex');
    }

    await prisma.mpcWallet.update({
      where: { id: walletId },
      data: { lastUsedAt: new Date() },
    });

    await SessionKeyManager.refreshSession(sessionToken);

    logSecurityEvent(userId, UserSecurityEventType.MPC_SIGNATURE_GENERATED, context);
    logSecurityEvent(userId, UserSecurityEventType.SIGNING_SESSION_USED, context);

    res.status(200).json({ signature });
  } catch (error) {
    logger.error('mpc.signing.session_failed', {
      userId,
      walletId,
      err: error,
    });
    res.status(500).json({ message: 'Failed to sign with session' });
  } finally {
    zeroizeBuffers(shardA, shardB, privateKey);
  }
};
