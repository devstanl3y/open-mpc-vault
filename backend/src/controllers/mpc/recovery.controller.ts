import { Response } from 'express';
import bcrypt from 'bcrypt';
import { ShardStatus, UserSecurityEventType } from '@prisma/client';
import type { IUserRequest } from '../../middleware/requireAuth';
import prisma from '../../utils/prisma';
import { ShardEncryption } from '../../utils/mpc/shardEncryption';
import { ShardStorage } from '../../utils/mpc/shardStorage';
import { getRequestContext } from '../../utils/context';
import { cloudBackupService, type BackupPayloadV4 } from '../../utils/cloudBackup';
import { logSecurityEvent } from '../../utils/securityLogger';
import { addressesEqual, deriveWalletFromShardsForMpcWallet } from '../../utils/mpc/walletDerivation';
import { ChainType } from '../../utils/mpc/hdWallet';
import {
  PIN_PEPPER,
  getCloudRecoveryErrorStatus,
  getRecoveryIdentityMismatch,
  zeroizeBuffers,
} from './shared';

export const recoverFromCloud = async (req: IUserRequest, res: Response) => {
  const pin = typeof req.body?.pin === 'string' ? req.body.pin : '';
  const requestedFileId =
    typeof req.body?.fileId === 'string' && req.body.fileId.trim().length > 0
      ? req.body.fileId
      : undefined;
  const requestedWalletId =
    typeof req.body?.mpcWalletId === 'string' && req.body.mpcWalletId.trim().length > 0
      ? req.body.mpcWalletId
      : typeof req.body?.walletId === 'string' && req.body.walletId.trim().length > 0
        ? req.body.walletId
        : undefined;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });
  if (!pin || (!requestedFileId && !requestedWalletId)) {
    return res.status(400).json({ message: 'Missing fileId/walletId (or mpcWalletId) or PIN' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.pin_hash) return res.status(401).json({ message: 'User PIN not set' });

    const pinWithPepper = pin + PIN_PEPPER;
    if (!(await bcrypt.compare(pinWithPepper, user.pin_hash))) {
      return res.status(401).json({ message: 'Invalid PIN' });
    }

    const fileId =
      requestedFileId ||
      (requestedWalletId
        ? await cloudBackupService.resolveBackupFileIdForWallet(userId, requestedWalletId)
        : undefined);

    if (!fileId) {
      return res.status(404).json({ message: 'No backup file found for recovery' });
    }

    const backupData = await cloudBackupService.validateRecoveryBackup(userId, fileId, pinWithPepper);

    shardB = await ShardStorage.retrieveShardBForUser(backupData.shardBId, userId);
    if (!shardB) {
      return res.status(400).json({
        message: 'Critical: The server-side key for this wallet is missing. Recovery impossible.',
      });
    }

    shardA = ShardEncryption.decryptShardA(
      backupData.encryptedShardA,
      backupData.iv,
      backupData.tag,
      pinWithPepper,
      backupData.salt,
    );

    const derived = deriveWalletFromShardsForMpcWallet({
      shardA,
      shardB,
      wallet: {
        publicAddress: backupData.publicAddress,
        chainType: backupData.chainType,
        curveType: backupData.curveType,
        isSeedPhrase: true,
        accountIndex: backupData.accountIndex,
        addressIndex: backupData.addressIndex,
      },
    });

    if (!addressesEqual(derived.address, backupData.publicAddress)) {
      logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
      return res.status(400).json({
        message: 'Recovery failed: Backup identity mismatch',
      });
    }

    const existingWallet = await prisma.mpcWallet.findUnique({
      where: { id: backupData.walletId },
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

    if (existingWallet) {
      const mismatch = getRecoveryIdentityMismatch(existingWallet, backupData, userId);
      if (mismatch) {
        console.error('Recovery identity mismatch:', {
          walletId: backupData.walletId,
          mismatch,
        });
        logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
        return res.status(409).json({
          message: 'Recovery rejected: Existing wallet identity does not match backup',
        });
      }
    }

    const mpcWallet = await prisma.mpcWallet.upsert({
      where: { id: backupData.walletId },
      update: {
        status: ShardStatus.ACTIVE,
      },
      create: {
        id: backupData.walletId,
        userId,
        walletName: `Recovered ${backupData.chainType} Wallet`,
        publicAddress: backupData.publicAddress,
        curveType: backupData.curveType,
        chainType: backupData.chainType,
        derivationPath: backupData.derivationPath,
        accountIndex: backupData.accountIndex,
        addressIndex: backupData.addressIndex,
        isImported: true,
        isSeedPhrase: true,
        shardBId: backupData.shardBId,
        status: ShardStatus.ACTIVE,
      },
    });

    await prisma.user.update({
      where: { id: userId },
      data: { mpc_enabled: true },
    });

    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_SUCCESS, context);

    return res.status(200).json({
      message: 'Wallet recovered successfully',
      recovered: true,
      walletId: mpcWallet.id,
      publicAddress: mpcWallet.publicAddress,
      chainType: mpcWallet.chainType,
      wallet: mpcWallet,
      encryptedShardA: {
        encrypted: backupData.encryptedShardA,
        iv: backupData.iv,
        tag: backupData.tag,
        salt: backupData.salt,
      },
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    const status = getCloudRecoveryErrorStatus(errorMessage);

    console.error('Recovery error:', error);
    if (status === 400 || status === 404) {
      logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
      return res.status(status).json({
        message: `Recovery failed: ${errorMessage}`,
      });
    }
    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
    res.status(500).json({ message: 'Failed to recover from cloud' });
  } finally {
    zeroizeBuffers(shardA, shardB);
  }
};

export const recoverAllWalletsFromCloud = async (req: IUserRequest, res: Response) => {
  const { pin } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });
  if (!pin) return res.status(400).json({ message: 'PIN is required' });

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.pin_hash) return res.status(401).json({ message: 'User PIN not set' });

    const pinWithPepper = pin + PIN_PEPPER;
    if (!(await bcrypt.compare(pinWithPepper, user.pin_hash))) {
      return res.status(401).json({ message: 'Invalid PIN' });
    }

    const allBackups = await cloudBackupService.listBackups(userId);

    if (!allBackups || allBackups.length === 0) {
      return res.status(404).json({ message: 'No backups found in cloud' });
    }

    const backupsByVault = new Map<string, Array<BackupPayloadV4 & { fileId: string }>>();
    const allErrors: Array<Record<string, string>> = [];

    for (const backup of allBackups) {
      try {
        if (!backup.id) continue;
        const backupData = await cloudBackupService.validateRecoveryBackup(userId, backup.id, pinWithPepper);

        if (!backupsByVault.has(backupData.shardBId)) {
          backupsByVault.set(backupData.shardBId, []);
        }

        backupsByVault.get(backupData.shardBId)!.push({
          fileId: backup.id,
          ...backupData,
        });
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        allErrors.push({
          fileId: backup.id || 'unknown',
          error: errorMessage,
        });
      }
    }

    if (backupsByVault.size === 0) {
      return res.status(404).json({
        message: 'No valid backups found. Ensure backups use the latest format.',
        errors: allErrors.length > 0 ? allErrors : undefined,
      });
    }

    const allRecoveredWallets = [];

    for (const [shardBId, vaultBackups] of backupsByVault.entries()) {
      let shardA: Buffer | undefined;
      let shardB: Buffer | undefined;

      try {
        shardB = await ShardStorage.retrieveShardBForUser(shardBId, userId);

        if (!shardB) {
          allErrors.push({
            vaultId: shardBId,
            error: 'Server-side key missing',
          });
          continue;
        }

        for (const backupData of vaultBackups) {
          try {
            shardA = ShardEncryption.decryptShardA(
              backupData.encryptedShardA,
              backupData.iv,
              backupData.tag,
              pinWithPepper,
              backupData.salt,
            );

            const derived = deriveWalletFromShardsForMpcWallet({
              shardA,
              shardB,
              wallet: {
                publicAddress: backupData.publicAddress,
                chainType: backupData.chainType,
                curveType: backupData.curveType,
                isSeedPhrase: true,
                accountIndex: backupData.accountIndex,
                addressIndex: backupData.addressIndex,
              },
            });

            if (!addressesEqual(derived.address, backupData.publicAddress)) {
              allErrors.push({
                chainType: backupData.chainType,
                walletId: backupData.walletId,
                error: 'backup identity mismatch',
              });
              continue;
            }

            const existingWallet = await prisma.mpcWallet.findUnique({
              where: { id: backupData.walletId },
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

            if (existingWallet) {
              const mismatch = getRecoveryIdentityMismatch(existingWallet, backupData, userId);
              if (mismatch) {
                allErrors.push({
                  chainType: backupData.chainType,
                  walletId: backupData.walletId,
                  error: `existing wallet mismatch (${mismatch})`,
                });
                continue;
              }
            }

            const mpcWallet = await prisma.mpcWallet.upsert({
              where: { id: backupData.walletId },
              update: { status: ShardStatus.ACTIVE },
              create: {
                id: backupData.walletId,
                userId,
                walletName: `Recovered ${backupData.chainType} Wallet`,
                publicAddress: backupData.publicAddress,
                curveType: backupData.curveType,
                chainType: backupData.chainType,
                derivationPath: backupData.derivationPath,
                accountIndex: backupData.accountIndex,
                addressIndex: backupData.addressIndex,
                isImported: true,
                isSeedPhrase: true,
                shardBId: backupData.shardBId,
                status: ShardStatus.ACTIVE,
              },
            });

            allRecoveredWallets.push({
              id: mpcWallet.id,
              walletName: mpcWallet.walletName,
              publicAddress: mpcWallet.publicAddress,
              chainType: mpcWallet.chainType,
              shardBId: mpcWallet.shardBId,
              encryptedShardA: {
                encrypted: backupData.encryptedShardA,
                iv: backupData.iv,
                tag: backupData.tag,
                salt: backupData.salt,
              },
            });

            zeroizeBuffers(shardA);
          } catch (walletError) {
            console.error('Failed to recover wallet:', walletError);
            allErrors.push({
              chainType: backupData.chainType,
              walletId: backupData.walletId,
              error: walletError instanceof Error ? walletError.message : 'Unknown error',
            });
          }
        }
      } catch (vaultError) {
        console.error(`Failed to process vault ${shardBId}:`, vaultError);
        allErrors.push({
          vaultId: shardBId,
          error: vaultError instanceof Error ? vaultError.message : 'Unknown error',
        });
      } finally {
        zeroizeBuffers(shardA, shardB);
      }
    }

    if (allRecoveredWallets.length === 0) {
      logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
      return res.status(500).json({
        message: 'Failed to recover any wallets',
        errors: allErrors,
      });
    }

    await prisma.user.update({
      where: { id: userId },
      data: { mpc_enabled: true },
    });

    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_SUCCESS, context);

    return res.status(200).json({
      message: `Successfully recovered ${allRecoveredWallets.length} wallet(s)`,
      wallets: allRecoveredWallets,
      totalVaults: backupsByVault.size,
      errors: allErrors.length > 0 ? allErrors : undefined,
    });
  } catch (error) {
    console.error('Recovery error:', error);
    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
    res.status(500).json({ message: 'Failed to recover from cloud' });
  }
};

export const listRecoverableVaults = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  try {
    let allBackups;
    let skippedLegacyBackupCount = 0;

    try {
      allBackups = await cloudBackupService.listBackups(userId);
    } catch (backupError) {
      console.error('[listRecoverableVaults] ERROR fetching backups:', backupError);
      return res.status(200).json({ vaults: [] });
    }

    if (!allBackups || allBackups.length === 0) {
      return res.status(200).json({ vaults: [] });
    }

    const vaultMap = new Map<
      string,
      {
        shardBId: string;
        wallets: Array<{ chainType: ChainType; walletId: string; fileId: string }>;
        createdAt: Date;
      }
    >();

    for (const backup of allBackups) {
      try {
        if (!backup || !backup.id) continue;

        let parsed: BackupPayloadV4;
        try {
          const backupData = await cloudBackupService.fetchBackup(userId, backup.id);
          parsed = cloudBackupService.parseBackupPayload(backupData);
        } catch (fetchError) {
          const errorMessage =
            fetchError instanceof Error ? fetchError.message : 'Unknown parse error';
          if (/Unsupported backup version/i.test(errorMessage)) {
            skippedLegacyBackupCount += 1;
            continue;
          }
          console.error(`[listRecoverableVaults] Failed to fetch/parse backup ${backup.id}:`, fetchError);
          continue;
        }

        const shardBId = parsed.shardBId;

        if (!vaultMap.has(shardBId)) {
          vaultMap.set(shardBId, {
            shardBId,
            wallets: [],
            createdAt: new Date(parsed.timestamp || backup.createdTime || Date.now()),
          });
        }

        const vault = vaultMap.get(shardBId)!;
        vault.wallets.push({
          chainType: parsed.chainType,
          walletId: parsed.walletId,
          fileId: backup.id,
        });
      } catch (error) {
        console.error('[listRecoverableVaults] ERROR processing backup:', error);
      }
    }

    if (skippedLegacyBackupCount > 0) {
      console.info(
        `[listRecoverableVaults] Skipped ${skippedLegacyBackupCount} legacy backup file(s) (unsupported version).`,
      );
    }

    const vaults = Array.from(vaultMap.entries()).map(([shardBId, data]) => ({
      shardBId,
      walletsCount: data.wallets.length,
      chains: data.wallets.map((w) => w.chainType),
      createdAt: data.createdAt,
    }));

    return res.status(200).json({ vaults });
  } catch (error) {
    console.error('[listRecoverableVaults] CRITICAL ERROR:', error);
    return res.status(500).json({
      message: 'Failed to list recoverable vaults',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
};
