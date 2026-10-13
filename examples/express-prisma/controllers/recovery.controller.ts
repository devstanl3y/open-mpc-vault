import { Response } from 'express';
import { AdminKillSwitchFeature, ShardStatus, UserSecurityEventType } from '@prisma/client';
import {
  IMPORTED_KEY_DERIVATION_PATH,
  ShardEncryption,
  ShardStorage,
  addressesEqual,
  deriveWalletFromShardsForMpcWallet,
  type ChainType,
} from 'open-mpc-vault';
import {
  prisma,
  logger,
  cloudBackupService,
  logSecurityEvent,
  getRequestContext,
  getKillSwitchMatch,
  type BackupPayloadV4,
  type IUserRequest,
} from '../host';
import {
  getCloudRecoveryErrorStatus,
  getRecoveryIdentityMismatch,
  verifyUserPin,
  zeroizeBuffers,
} from './shared';

class RecoveryError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

/** Returns a 503 response body if cloud backup is paused, otherwise null. */
async function cloudBackupPausedResponse() {
  const match = await getKillSwitchMatch({ feature: AdminKillSwitchFeature.CLOUD_BACKUP });
  if (!match.active || !match.killSwitch) return null;
  return {
    message: 'Cloud backup is temporarily paused.',
    code: 'FEATURE_PAUSED',
    feature: AdminKillSwitchFeature.CLOUD_BACKUP,
    reason: match.killSwitch.reason,
    blastRadiusLabel: match.killSwitch.blastRadiusLabel,
  };
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined;
}

/**
 * Backups do not record whether the vault holds a seed or a raw key; raw-key
 * imports are identified by their sentinel derivation path.
 */
function backupIsSeedPhrase(backup: BackupPayloadV4): boolean {
  return backup.derivationPath !== IMPORTED_KEY_DERIVATION_PATH;
}

function encryptedShardAOf(backup: BackupPayloadV4) {
  return { encrypted: backup.encryptedShardA, iv: backup.iv, tag: backup.tag, salt: backup.salt };
}

/**
 * Decrypt the backed-up shard A, prove it reconstructs the recorded address
 * with `shardB`, and upsert the wallet row. Throws RecoveryError on identity
 * mismatches.
 */
async function restoreWalletFromBackup(
  userId: number,
  backup: BackupPayloadV4,
  shardB: Buffer,
  pinWithPepper: string
) {
  let shardA: Buffer | undefined;
  let privateKey: Buffer | undefined;
  const isSeedPhrase = backupIsSeedPhrase(backup);

  try {
    const decryptedShardA = ShardEncryption.decryptShardA(
      backup.encryptedShardA,
      backup.iv,
      backup.tag,
      pinWithPepper,
      backup.salt
    );
    shardA = decryptedShardA;

    const derived = deriveWalletFromShardsForMpcWallet({
      shardA: decryptedShardA,
      shardB,
      wallet: {
        publicAddress: backup.publicAddress,
        chainType: backup.chainType,
        curveType: backup.curveType,
        isSeedPhrase,
        accountIndex: backup.accountIndex,
        addressIndex: backup.addressIndex,
      },
    });
    privateKey = derived.privateKey;

    if (!addressesEqual(derived.address, backup.publicAddress)) {
      throw new RecoveryError(400, 'backup identity mismatch');
    }

    const existing = await prisma.mpcWallet.findUnique({
      where: { id: backup.walletId },
      select: {
        id: true,
        userId: true,
        publicAddress: true,
        chainType: true,
        curveType: true,
        derivationPath: true,
        accountIndex: true,
        addressIndex: true,
        shardBId: true,
      },
    });
    if (existing) {
      const mismatch = getRecoveryIdentityMismatch(existing, backup, userId);
      if (mismatch) {
        logger.warn('mpc.recovery.identity_mismatch', {
          userId,
          walletId: backup.walletId,
          mismatch,
        });
        throw new RecoveryError(409, `existing wallet mismatch (${mismatch})`);
      }
    }

    return prisma.mpcWallet.upsert({
      where: { id: backup.walletId },
      update: { status: ShardStatus.ACTIVE },
      create: {
        id: backup.walletId,
        userId,
        walletName: `Recovered ${backup.chainType} Wallet`,
        publicAddress: backup.publicAddress,
        curveType: backup.curveType,
        chainType: backup.chainType,
        derivationPath: backup.derivationPath,
        accountIndex: backup.accountIndex,
        addressIndex: backup.addressIndex,
        isImported: !isSeedPhrase,
        isSeedPhrase,
        shardBId: backup.shardBId,
        status: ShardStatus.ACTIVE,
      },
    });
  } finally {
    zeroizeBuffers(shardA, privateKey);
  }
}

export const recoverFromCloud = async (req: IUserRequest, res: Response) => {
  const pin = req.body?.pin;
  const requestedFileId = nonEmptyString(req.body?.fileId);
  const requestedWalletId = nonEmptyString(req.body?.mpcWalletId) ?? nonEmptyString(req.body?.walletId);
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });
  if (!requestedFileId && !requestedWalletId) {
    return res.status(400).json({ message: 'fileId or walletId is required' });
  }

  let shardB: Buffer | undefined;

  try {
    const paused = await cloudBackupPausedResponse();
    if (paused) return res.status(503).json(paused);

    const pinCheck = await verifyUserPin(userId, pin);
    if (!pinCheck.ok) {
      return res.status(pinCheck.status).json({ message: pinCheck.message });
    }
    const { pinWithPepper } = pinCheck;

    const fileId =
      requestedFileId ??
      (await cloudBackupService.resolveBackupFileIdForWallet(userId, requestedWalletId!));
    if (!fileId) {
      return res.status(404).json({ message: 'No backup file found for recovery' });
    }

    const backup = await cloudBackupService.validateRecoveryBackup(userId, fileId, pinWithPepper);

    shardB = await ShardStorage.retrieveShardBForUser(backup.shardBId, userId);
    if (!shardB) {
      throw new RecoveryError(400, 'Server shard for this vault is missing; recovery is not possible');
    }

    const wallet = await restoreWalletFromBackup(userId, backup, shardB, pinWithPepper);

    await prisma.user.update({ where: { id: userId }, data: { mpc_enabled: true } });
    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_SUCCESS, context);

    return res.status(200).json({
      recovered: true,
      walletId: wallet.id,
      publicAddress: wallet.publicAddress,
      chainType: wallet.chainType,
      wallet,
      encryptedShardA: encryptedShardAOf(backup),
    });
  } catch (error) {
    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);

    if (error instanceof RecoveryError) {
      return res.status(error.status).json({ message: `Recovery failed: ${error.message}` });
    }

    logger.error('mpc.recovery.failed', { userId, err: error });
    const message = error instanceof Error ? error.message : '';
    const status = getCloudRecoveryErrorStatus(message);
    if (status !== 500) {
      return res.status(status).json({ message: `Recovery failed: ${message}` });
    }
    return res.status(500).json({ message: 'Failed to recover from cloud' });
  } finally {
    zeroizeBuffers(shardB);
  }
};

export const recoverAllWalletsFromCloud = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const paused = await cloudBackupPausedResponse();
    if (paused) return res.status(503).json(paused);

    const pinCheck = await verifyUserPin(userId, req.body?.pin);
    if (!pinCheck.ok) {
      return res.status(pinCheck.status).json({ message: pinCheck.message });
    }
    const { pinWithPepper } = pinCheck;

    const allBackups = await cloudBackupService.listBackups(userId);
    if (!allBackups?.length) {
      return res.status(404).json({ message: 'No backups found in cloud' });
    }

    const backupsByVault = new Map<string, BackupPayloadV4[]>();
    const errors: Array<Record<string, string>> = [];

    for (const file of allBackups) {
      if (!file.id) continue;
      try {
        const backup = await cloudBackupService.validateRecoveryBackup(userId, file.id, pinWithPepper);
        const group = backupsByVault.get(backup.shardBId) ?? [];
        group.push(backup);
        backupsByVault.set(backup.shardBId, group);
      } catch (error) {
        errors.push({
          fileId: file.id,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    if (backupsByVault.size === 0) {
      return res.status(404).json({
        message: 'No valid backups found',
        errors: errors.length > 0 ? errors : undefined,
      });
    }

    const recovered = [];

    for (const [shardBId, backups] of backupsByVault) {
      let shardB: Buffer | undefined;
      try {
        shardB = await ShardStorage.retrieveShardBForUser(shardBId, userId);
        if (!shardB) {
          errors.push({ vaultId: shardBId, error: 'Server shard missing' });
          continue;
        }

        for (const backup of backups) {
          try {
            const wallet = await restoreWalletFromBackup(userId, backup, shardB, pinWithPepper);
            recovered.push({
              id: wallet.id,
              walletName: wallet.walletName,
              publicAddress: wallet.publicAddress,
              chainType: wallet.chainType,
              shardBId: wallet.shardBId,
              encryptedShardA: encryptedShardAOf(backup),
            });
          } catch (error) {
            if (!(error instanceof RecoveryError)) {
              logger.error('mpc.recovery.wallet_failed', {
                userId,
                walletId: backup.walletId,
                err: error,
              });
            }
            errors.push({
              chainType: backup.chainType,
              walletId: backup.walletId,
              error: error instanceof Error ? error.message : 'Unknown error',
            });
          }
        }
      } finally {
        zeroizeBuffers(shardB);
      }
    }

    if (recovered.length === 0) {
      logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
      return res.status(422).json({ message: 'No wallets could be recovered', errors });
    }

    await prisma.user.update({ where: { id: userId }, data: { mpc_enabled: true } });
    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_SUCCESS, context);

    return res.status(200).json({
      wallets: recovered,
      totalVaults: backupsByVault.size,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (error) {
    logger.error('mpc.recovery.all_failed', { userId, err: error });
    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
    return res.status(500).json({ message: 'Failed to recover from cloud' });
  }
};

export const listRecoverableVaults = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const allBackups = await cloudBackupService.listBackups(userId);
    if (!allBackups?.length) {
      return res.status(200).json({ vaults: [] });
    }

    const vaults = new Map<string, { chains: ChainType[]; createdAt: Date }>();
    let skippedLegacy = 0;

    for (const file of allBackups) {
      if (!file?.id) continue;

      let parsed: BackupPayloadV4;
      try {
        parsed = cloudBackupService.parseBackupPayload(
          await cloudBackupService.fetchBackup(userId, file.id)
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : '';
        if (/Unsupported backup version/i.test(message)) {
          skippedLegacy += 1;
        } else {
          logger.error('mpc.recovery.list_vaults.parse_failed', {
            userId,
            fileId: file.id,
            err: error,
          });
        }
        continue;
      }

      const vault = vaults.get(parsed.shardBId) ?? {
        chains: [],
        createdAt: new Date(parsed.timestamp || file.createdTime || Date.now()),
      };
      vault.chains.push(parsed.chainType);
      vaults.set(parsed.shardBId, vault);
    }

    if (skippedLegacy > 0) {
      logger.info('mpc.recovery.list_vaults.legacy_skipped', { userId, skippedCount: skippedLegacy });
    }

    return res.status(200).json({
      vaults: [...vaults].map(([shardBId, v]) => ({
        shardBId,
        walletsCount: v.chains.length,
        chains: v.chains,
        createdAt: v.createdAt,
      })),
    });
  } catch (error) {
    logger.error('mpc.recovery.list_vaults.failed', { userId, err: error });
    return res.status(500).json({ message: 'Failed to list recoverable vaults' });
  }
};
