import { Response } from 'express';
import { ShardStatus, UserSecurityEventType } from '@prisma/client';
import { ShardEncryption, ShardStorage, addressesEqual, deriveWalletFromShardsForMpcWallet } from 'open-mpc-vault';
import {
  prisma,
  logger,
  SessionKeyManager,
  logSecurityEvent,
  getRequestContext,
  getSessionShardFromRequestBody,
  type IUserRequest,
} from '../host';
import { decodeHex, signMessage, verifyUserPin, zeroizeBuffers, type DigestSignature } from './shared';

type MpcWalletRecord = NonNullable<Awaited<ReturnType<typeof prisma.mpcWallet.findFirst>>>;

class SigningError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

/**
 * Reconstruct the wallet key from both shards, check it matches the stored
 * address, and sign. `shardA` is zeroized by the caller; shard B and the
 * private key are zeroized here.
 */
async function signWithShards(
  wallet: MpcWalletRecord,
  userId: number,
  shardA: Buffer,
  message: Buffer
): Promise<DigestSignature> {
  let shardB: Buffer | undefined;
  let privateKey: Buffer | undefined;

  try {
    shardB = await ShardStorage.retrieveShardBForUser(wallet.shardBId, userId);
    if (!shardB) {
      logger.error('mpc.signing.shard_b_missing', { userId, walletId: wallet.id });
      throw new SigningError(500, 'Server shard unavailable');
    }

    const derived = deriveWalletFromShardsForMpcWallet({
      shardA,
      shardB,
      wallet: {
        publicAddress: wallet.publicAddress,
        chainType: wallet.chainType,
        curveType: wallet.curveType,
        isSeedPhrase: wallet.isSeedPhrase,
        accountIndex: wallet.accountIndex,
        addressIndex: wallet.addressIndex,
      },
    });
    const walletKey = derived.privateKey;
    privateKey = walletKey;

    if (!addressesEqual(derived.address, wallet.publicAddress)) {
      throw new SigningError(403, 'Shard payload does not match selected wallet');
    }

    try {
      return signMessage(wallet.curveType, message, walletKey);
    } catch (error) {
      if (error instanceof RangeError) throw new SigningError(400, error.message);
      throw error;
    }
  } finally {
    zeroizeBuffers(shardB, privateKey);
  }
}

async function findActiveWallet(walletId: string, userId: number) {
  return prisma.mpcWallet.findFirst({
    where: { id: walletId, userId, status: ShardStatus.ACTIVE },
  });
}

export const signWithMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletId, shardAEncrypted, shardAIv, shardATag, shardASalt } = req.body;
  const message = decodeHex(req.body.messageHash);
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  if (typeof walletId !== 'string' || !message || !shardAEncrypted || !shardAIv || !shardATag) {
    return res.status(400).json({
      message: 'walletId, hex messageHash, pin, and encrypted shard A data are required',
    });
  }

  let shardA: Buffer | undefined;

  try {
    const pinCheck = await verifyUserPin(userId, req.body.pin);
    if (!pinCheck.ok) {
      return res.status(pinCheck.status).json({ message: pinCheck.message });
    }

    const wallet = await findActiveWallet(walletId, userId);
    if (!wallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    const decryptedShardA = ShardEncryption.decryptShardA(
      shardAEncrypted,
      shardAIv,
      shardATag,
      pinCheck.pinWithPepper,
      shardASalt
    );
    shardA = decryptedShardA;

    const result = await signWithShards(wallet, userId, decryptedShardA, message);

    await prisma.mpcWallet.update({ where: { id: walletId }, data: { lastUsedAt: new Date() } });
    logSecurityEvent(userId, UserSecurityEventType.MPC_SIGNATURE_GENERATED, context);

    return res.status(200).json(result);
  } catch (error) {
    if (error instanceof SigningError) {
      return res.status(error.status).json({ message: error.message });
    }
    logger.error('mpc.signing.failed', { userId, walletId, err: error });
    return res.status(500).json({ message: 'Failed to sign with MPC wallet' });
  } finally {
    zeroizeBuffers(shardA);
  }
};

export const signWithSession = async (req: IUserRequest, res: Response) => {
  const { sessionToken } = req.body;
  const message = decodeHex(req.body.messageHash);
  const sessionShard = getSessionShardFromRequestBody(req.body);
  const walletId: unknown = req.body.walletId ?? req.body.mpcWalletId;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  if (typeof walletId !== 'string' || !message || !sessionToken || !sessionShard) {
    return res.status(400).json({
      message: 'walletId, hex messageHash, sessionToken, and sessionShard are required',
    });
  }

  let shardA: Buffer | undefined;

  try {
    const session = await SessionKeyManager.validateSession(sessionToken);
    if (!session) {
      return res.status(401).json({ message: 'Invalid or expired session', code: 'SESSION_INVALID' });
    }
    if (session.userId !== userId || session.mpcWalletId !== walletId) {
      return res.status(403).json({
        message: 'Session does not match wallet or user',
        code: 'SESSION_MISMATCH',
      });
    }

    const wallet = await findActiveWallet(walletId, userId);
    if (!wallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    const sessionShardA: Buffer = await SessionKeyManager.decryptSessionShard({
      sessionToken,
      sessionShard,
    });
    shardA = sessionShardA;
    const result = await signWithShards(wallet, userId, sessionShardA, message);

    await prisma.mpcWallet.update({ where: { id: walletId }, data: { lastUsedAt: new Date() } });
    await SessionKeyManager.refreshSession(sessionToken);

    logSecurityEvent(userId, UserSecurityEventType.MPC_SIGNATURE_GENERATED, context);
    logSecurityEvent(userId, UserSecurityEventType.SIGNING_SESSION_USED, context);

    return res.status(200).json(result);
  } catch (error) {
    if (error instanceof SigningError) {
      return res.status(error.status).json({ message: error.message });
    }
    logger.error('mpc.signing.session_failed', { userId, walletId, err: error });
    return res.status(500).json({ message: 'Failed to sign with session' });
  } finally {
    zeroizeBuffers(shardA);
  }
};
