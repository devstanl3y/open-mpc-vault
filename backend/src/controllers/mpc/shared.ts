import { CurveType } from '@prisma/client';
import { ChainType } from '../../utils/mpc/hdWallet';
import type { BackupPayloadV4 } from '../../utils/cloudBackup';
import { addressesEqual } from '../../utils/mpc/walletDerivation';

export const PIN_PEPPER = process.env.PIN_PEPPER_SECRET || '';

export function zeroizeBuffers(...buffers: Array<Buffer | undefined>): void {
  buffers.forEach((buffer) => {
    if (buffer && Buffer.isBuffer(buffer)) {
      buffer.fill(0);
    }
  });
}

type RecoveryIdentityWallet = {
  id: string;
  userId: number;
  publicAddress: string;
  chainType: ChainType | null;
  curveType: CurveType;
  derivationPath: string | null;
  accountIndex: number;
  addressIndex: number;
  shardBId: string;
};

export function getRecoveryIdentityMismatch(
  existingWallet: RecoveryIdentityWallet,
  backupData: BackupPayloadV4,
  userId: number,
): string | null {
  if (existingWallet.userId !== userId) return 'wallet ownership mismatch';
  if (!addressesEqual(existingWallet.publicAddress, backupData.publicAddress)) {
    return 'publicAddress mismatch';
  }
  if (existingWallet.chainType !== backupData.chainType) return 'chainType mismatch';
  if (existingWallet.curveType !== backupData.curveType) return 'curveType mismatch';
  if ((existingWallet.derivationPath || '') !== backupData.derivationPath) {
    return 'derivationPath mismatch';
  }
  if (existingWallet.accountIndex !== backupData.accountIndex) return 'accountIndex mismatch';
  if (existingWallet.addressIndex !== backupData.addressIndex) return 'addressIndex mismatch';
  if (existingWallet.shardBId !== backupData.shardBId) return 'shardBId mismatch';
  return null;
}

export function getCloudRecoveryErrorStatus(message: string): number {
  if (/not found|no cloud backup/i.test(message)) {
    return 404;
  }

  if (/integrity|checksum|metadata|unsupported|invalid|mismatch|ownership|backup/i.test(message)) {
    return 400;
  }

  return 500;
}
