/**
 * Service-to-service endpoints used by the Rust wallet loader.
 *
 * WARNING: several of these handlers return plaintext key material (decrypted
 * shard A, decrypted shard B, reconstructed entropy). Anyone who can reach
 * them can reconstruct any wallet. Mount them only on a private network
 * behind mutual service authentication, never on the public router. See
 * REVIEW.md for the recommended replacement (sign-in-place instead of
 * exporting secrets).
 */
import { Request, Response } from 'express';
import { MpcKeyGenerator, ShardEncryption, ShardStorage } from 'open-mpc-vault';
import { prisma, logger } from '../host';
import { PIN_PEPPER, decodeHex, parseChainType, parseHdIndex, zeroizeBuffers } from './shared';

const WALLET_PUBLIC_FIELDS = {
  id: true,
  userId: true,
  walletName: true,
  publicAddress: true,
  curveType: true,
  chainType: true,
  derivationPath: true,
  accountIndex: true,
  addressIndex: true,
  isImported: true,
  isSeedPhrase: true,
  shardBId: true,
  status: true,
  createdAt: true,
  lastUsedAt: true,
} as const;

function shardScopeRequired(): boolean {
  return (process.env.REQUIRE_ENGINE_USER_SCOPE_FOR_SHARD_B ?? 'true').toLowerCase() !== 'false';
}

export const getMpcWalletInternal = async (req: Request, res: Response) => {
  const { walletId } = req.params;
  if (typeof walletId !== 'string') {
    return res.status(400).json({ message: 'Invalid wallet ID format' });
  }

  try {
    const wallet = await prisma.mpcWallet.findUnique({
      where: { id: walletId },
      select: WALLET_PUBLIC_FIELDS,
    });
    if (!wallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }
    return res.status(200).json(wallet);
  } catch (error) {
    logger.error('mpc_internal.wallet.fetch_failed', { walletId, err: error });
    return res.status(500).json({ message: 'Failed to fetch MPC wallet' });
  }
};

export const getWalletShardDataInternal = async (req: Request, res: Response) => {
  const { walletId } = req.params;
  if (typeof walletId !== 'string') {
    return res.status(400).json({ message: 'Invalid wallet ID format' });
  }

  try {
    const backup = await prisma.shardABackup.findFirst({
      where: { mpcWalletId: walletId },
      orderBy: { lastSyncedAt: 'desc' },
      select: { driveFileId: true, backupVersion: true, metadataChecksum: true, lastSyncedAt: true },
    });
    if (!backup) {
      return res.status(404).json({ message: 'No backup found for this wallet' });
    }
    return res.status(200).json(backup);
  } catch (error) {
    logger.error('mpc_internal.wallet_shard_data.fetch_failed', { walletId, err: error });
    return res.status(500).json({ message: 'Failed to fetch shard data' });
  }
};

/** Returns plaintext shard A. See file header. */
export const decryptShardAInternal = async (req: Request, res: Response) => {
  const { encrypted, iv, tag, pin, salt } = req.body;
  if (!encrypted || !iv || !tag || typeof pin !== 'string' || !pin || !salt) {
    return res.status(400).json({ message: 'encrypted, iv, tag, salt, and pin are required' });
  }

  let toZeroize: Buffer | undefined;
  try {
    const shard = ShardEncryption.decryptShardA(encrypted, iv, tag, pin + PIN_PEPPER, salt);
    toZeroize = shard;
    return res.status(200).json({ shard: shard.toString('hex'), length: shard.length });
  } catch (error) {
    logger.warn('mpc_internal.shard_a.decrypt_failed', { err: error });
    return res.status(400).json({ message: 'Failed to decrypt shard A' });
  } finally {
    zeroizeBuffers(toZeroize);
  }
};

export const encryptShardAInternal = async (req: Request, res: Response) => {
  const shard = decodeHex(req.body?.shard);
  const pin = req.body?.pin;
  if (!shard || typeof pin !== 'string' || !pin) {
    return res.status(400).json({ message: 'hex shard and pin are required' });
  }

  try {
    return res.status(200).json(ShardEncryption.encryptShardA(shard, pin + PIN_PEPPER));
  } catch (error) {
    logger.error('mpc_internal.shard_a.encrypt_failed', { err: error });
    return res.status(500).json({ message: 'Failed to encrypt shard A' });
  } finally {
    zeroizeBuffers(shard);
  }
};

/** Returns plaintext shard B. See file header. */
export const getShardBInternal = async (req: Request, res: Response) => {
  const { shardBId } = req.params;
  if (typeof shardBId !== 'string') {
    return res.status(400).json({ message: 'Invalid shard B ID format' });
  }

  let shardB: Buffer | undefined;
  try {
    const { userId, walletId } = req.query;
    let scopedUserId: number | undefined;

    if (typeof userId === 'string' && /^[1-9]\d*$/.test(userId)) {
      scopedUserId = Number(userId);
    } else if (typeof walletId === 'string' && walletId.trim().length > 0) {
      const wallet = await prisma.mpcWallet.findUnique({
        where: { id: walletId },
        select: { userId: true, shardBId: true },
      });
      if (!wallet) {
        return res.status(404).json({ message: 'Wallet not found for provided walletId scope' });
      }
      if (wallet.shardBId !== shardBId) {
        return res.status(400).json({ message: 'walletId scope does not match requested shardBId' });
      }
      scopedUserId = wallet.userId;
    }

    if (scopedUserId === undefined && shardScopeRequired()) {
      return res.status(400).json({ message: 'userId or walletId scope is required' });
    }

    if (scopedUserId !== undefined) {
      // ShardStorage does not record ownership; verify it against the DB.
      const owned = await prisma.mpcWallet.count({ where: { shardBId, userId: scopedUserId } });
      if (owned === 0) {
        return res.status(404).json({ message: 'Shard B not found' });
      }
    }

    shardB = await ShardStorage.retrieveShardB(shardBId);
    if (!shardB) {
      return res.status(404).json({ message: 'Shard B not found' });
    }
    return res.status(200).json({ shard: shardB.toString('hex'), length: shardB.length });
  } catch (error) {
    logger.error('mpc_internal.shard_b.fetch_failed', { shardBId, err: error });
    return res.status(500).json({ message: 'Failed to fetch shard B' });
  } finally {
    zeroizeBuffers(shardB);
  }
};

/** Returns reconstructed plaintext entropy. See file header. */
export const reconstructKeyInternal = async (req: Request, res: Response) => {
  const shardA = decodeHex(req.body?.shardA);
  const shardB = decodeHex(req.body?.shardB);
  if (!shardA || !shardB) {
    return res.status(400).json({ message: 'hex shardA and shardB are required' });
  }

  let toZeroize: Buffer | undefined;
  try {
    const entropy = MpcKeyGenerator.reconstructEntropy(shardA, shardB);
    toZeroize = entropy;
    return res.status(200).json({ entropy: entropy.toString('hex'), length: entropy.length });
  } catch (error) {
    logger.warn('mpc_internal.entropy.reconstruct_failed', { err: error });
    return res.status(400).json({ message: 'Failed to reconstruct entropy' });
  } finally {
    zeroizeBuffers(shardA, shardB, toZeroize);
  }
};

export const deriveAddressInternal = async (req: Request, res: Response) => {
  const shardA = decodeHex(req.body?.shardA);
  const shardB = decodeHex(req.body?.shardB);
  const chainType = parseChainType(req.body?.chainType);
  const accountIndex = parseHdIndex(req.body?.accountIndex ?? 0);
  const addressIndex = parseHdIndex(req.body?.addressIndex ?? 0);

  if (!shardA || !shardB || !chainType || accountIndex === null || addressIndex === null) {
    zeroizeBuffers(shardA ?? undefined, shardB ?? undefined);
    return res.status(400).json({
      message: 'hex shardA, shardB, a valid chainType, and integer indices are required',
    });
  }

  try {
    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardA,
      shardB,
      chainType,
      accountIndex,
      addressIndex,
      req.body.isSeedPhrase !== false
    );
    derived.privateKey.fill(0);

    return res.status(200).json({
      address: derived.address,
      publicKey: derived.publicKey.toString('hex'),
      chainType: derived.chainType,
      curveType: derived.curveType,
      derivationPath: derived.derivationPath,
    });
  } catch (error) {
    logger.error('mpc_internal.address.derive_failed', {
      chainType,
      accountIndex,
      addressIndex,
      err: error,
    });
    return res.status(500).json({ message: 'Failed to derive address' });
  } finally {
    zeroizeBuffers(shardA, shardB);
  }
};

/** Check that a plaintext shard A reconstructs the wallet's recorded address. */
export const validateShardInternal = async (req: Request, res: Response) => {
  const { walletId } = req.body ?? {};
  const shardA = decodeHex(req.body?.shardA);
  if (typeof walletId !== 'string' || !shardA) {
    return res.status(400).json({ message: 'walletId and hex shardA are required' });
  }

  let shardB: Buffer | undefined;
  try {
    const wallet = await prisma.mpcWallet.findUnique({
      where: { id: walletId },
      select: {
        shardBId: true,
        chainType: true,
        accountIndex: true,
        addressIndex: true,
        isSeedPhrase: true,
        publicAddress: true,
      },
    });
    const chainType = parseChainType(wallet?.chainType);
    if (!wallet || !chainType) {
      return res.status(404).json({ message: 'Wallet not found' });
    }

    shardB = await ShardStorage.retrieveShardB(wallet.shardBId);
    if (!shardB) {
      return res.status(404).json({ message: 'Shard B not found' });
    }

    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardA,
      shardB,
      chainType,
      wallet.accountIndex,
      wallet.addressIndex,
      wallet.isSeedPhrase,
      wallet.publicAddress
    );
    derived.privateKey.fill(0);

    return res.status(200).json({
      valid: derived.address.toLowerCase() === wallet.publicAddress.toLowerCase(),
    });
  } catch (error) {
    logger.error('mpc_internal.shard.validate_failed', { walletId, err: error });
    return res.status(500).json({ message: 'Failed to validate shard' });
  } finally {
    zeroizeBuffers(shardA, shardB);
  }
};

export const healthCheckInternal = async (_req: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;

    const probe = Buffer.from('health-check');
    const roundTrip = ShardEncryption.decryptShardB(ShardEncryption.encryptShardB(probe));
    const encryptionOk = roundTrip.equals(probe);

    return res.status(encryptionOk ? 200 : 503).json({
      status: encryptionOk ? 'healthy' : 'degraded',
      database: 'connected',
      encryption: encryptionOk ? 'working' : 'failed',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('mpc_internal.health_check.failed', { err: error });
    return res.status(503).json({ status: 'unhealthy', timestamp: new Date().toISOString() });
  }
};
