import assert from 'node:assert/strict';
import test from 'node:test';
import bcrypt from 'bcrypt';
import type { IUserRequest } from '../middleware/requireAuth';
import { ChainType } from '@prisma/client';
import prisma from '../utils/prisma';
import { cloudBackupService, type BackupPayloadV4 } from '../utils/cloudBackup';
import { ShardStorage } from '../utils/mpc/shardStorage';
import { ShardEncryption } from '../utils/mpc/shardEncryption';
import { MpcKeyGenerator } from '../utils/mpc/keyGenerator';
import * as securityLogger from '../utils/securityLogger';
import { recoverFromCloud } from './mpc.controller';

type MockResponse = {
  statusCode: number;
  body: unknown;
  status: (code: number) => MockResponse;
  json: (payload: unknown) => MockResponse;
};

const createResponse = (): MockResponse => {
  const response: MockResponse = {
    statusCode: 200,
    body: null,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return response;
};

test('recoverFromCloud returns 400 when wallet/file identifier is missing', async () => {
  const req = {
    user: { id: 11 },
    body: { pin: '123456' },
    headers: {},
  } as unknown as IUserRequest;
  const res = createResponse();

  await recoverFromCloud(req, res as never);

  assert.equal(res.statusCode, 400);
  assert.deepEqual(res.body, {
    message: 'Missing fileId/walletId (or mpcWalletId) or PIN',
  });
});

test('recoverFromCloud returns 401 when PIN validation fails', async () => {
  const originalFindUser = prisma.user.findUnique;
  const originalCompare = bcrypt.compare;

  (prisma.user as any).findUnique = async () => ({ id: 11, pin_hash: 'hash' });
  (bcrypt as any).compare = async () => false;

  try {
    const req = {
      user: { id: 11 },
      body: { mpcWalletId: 'wallet_1', pin: '123456' },
      headers: {},
    } as unknown as IUserRequest;
    const res = createResponse();

    await recoverFromCloud(req, res as never);

    assert.equal(res.statusCode, 401);
    assert.deepEqual(res.body, { message: 'Invalid PIN' });
  } finally {
    (prisma.user as any).findUnique = originalFindUser;
    (bcrypt as any).compare = originalCompare;
  }
});

test('recoverFromCloud supports walletId alias and recovers wallet', async () => {
  const seed = MpcKeyGenerator.createMpcSeed(12);
  const derived = MpcKeyGenerator.deriveWalletFromShards(
    seed.shardA,
    seed.shardB,
    ChainType.ETHEREUM,
    0,
    0,
    true,
  );

  const backupData: BackupPayloadV4 = {
    version: 4,
    walletId: 'wallet_1',
    publicAddress: derived.address,
    chainType: ChainType.ETHEREUM,
    curveType: derived.curveType,
    derivationPath: derived.derivationPath,
    accountIndex: 0,
    addressIndex: 0,
    shardBId: 'shard_b_1',
    encryptedShardA: 'enc',
    iv: 'iv',
    tag: 'tag',
    salt: 'salt',
    timestamp: new Date().toISOString(),
    metadataMac: 'a'.repeat(64),
  };

  const originalCompare = bcrypt.compare;
  const originalFindUser = prisma.user.findUnique;
  const originalFindWallet = prisma.mpcWallet.findUnique;
  const originalUpsertWallet = prisma.mpcWallet.upsert;
  const originalUserUpdate = prisma.user.update;
  const originalResolveFile = cloudBackupService.resolveBackupFileIdForWallet;
  const originalValidateBackup = cloudBackupService.validateRecoveryBackup;
  const originalRetrieveShardB = ShardStorage.retrieveShardBForUser;
  const originalDecryptShardA = ShardEncryption.decryptShardA;
  const originalLogEvent = securityLogger.logSecurityEvent;

  (bcrypt as any).compare = async () => true;
  (prisma.user as any).findUnique = async () => ({ id: 11, pin_hash: 'hash' });
  (prisma.mpcWallet as any).findUnique = async () => null;
  (prisma.mpcWallet as any).upsert = async () =>
    ({
      id: backupData.walletId,
      userId: 11,
      walletName: 'Recovered ETHEREUM Wallet',
      publicAddress: backupData.publicAddress,
      curveType: backupData.curveType,
      chainType: backupData.chainType,
      derivationPath: backupData.derivationPath,
      accountIndex: backupData.accountIndex,
      addressIndex: backupData.addressIndex,
      isImported: true,
      isSeedPhrase: true,
      shardBId: backupData.shardBId,
      status: 'ACTIVE',
    });
  (prisma.user as any).update = async () => ({ id: 11 });
  (cloudBackupService as any).resolveBackupFileIdForWallet = async () => 'file_1';
  (cloudBackupService as any).validateRecoveryBackup = async () => backupData;
  (ShardStorage as any).retrieveShardBForUser = async () => Buffer.from(seed.shardB);
  (ShardEncryption as any).decryptShardA = () => Buffer.from(seed.shardA);
  (securityLogger as any).logSecurityEvent = async () => undefined;

  try {
    const req = {
      user: { id: 11 },
      body: { walletId: backupData.walletId, pin: '123456' },
      headers: {},
    } as unknown as IUserRequest;
    const res = createResponse();

    await recoverFromCloud(req, res as never);

    assert.equal(res.statusCode, 200);
    assert.equal((res.body as { recovered: boolean }).recovered, true);
    assert.equal((res.body as { walletId: string }).walletId, backupData.walletId);
    assert.equal(
      (res.body as { publicAddress: string }).publicAddress.toLowerCase(),
      backupData.publicAddress.toLowerCase(),
    );
  } finally {
    (bcrypt as any).compare = originalCompare;
    (prisma.user as any).findUnique = originalFindUser;
    (prisma.mpcWallet as any).findUnique = originalFindWallet;
    (prisma.mpcWallet as any).upsert = originalUpsertWallet;
    (prisma.user as any).update = originalUserUpdate;
    (cloudBackupService as any).resolveBackupFileIdForWallet = originalResolveFile;
    (cloudBackupService as any).validateRecoveryBackup = originalValidateBackup;
    (ShardStorage as any).retrieveShardBForUser = originalRetrieveShardB;
    (ShardEncryption as any).decryptShardA = originalDecryptShardA;
    (securityLogger as any).logSecurityEvent = originalLogEvent;
  }
});
