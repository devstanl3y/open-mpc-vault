import { Response } from 'express';
import { ShardStatus, UserSecurityEventType } from '@prisma/client';
import {
  ChainType,
  HDWalletDerivation,
  MpcKeyGenerator,
  SeedPhraseUtils,
  ShardEncryption,
  ShardStorage,
  type MpcSeedShards,
  type DerivedWallet,
} from 'open-mpc-vault';
import {
  prisma,
  logger,
  cloudBackupService,
  logSecurityEvent,
  getRequestContext,
  PolicyService,
  type IUserRequest,
} from '../host';
import { chainLabel, parseChainType, parseHdIndex, verifyUserPin, zeroizeBuffers } from './shared';

const MAX_IMPORT_INDICES = 20;
const PREVIEW_ADDRESS_COUNT = 5;

type ImportType = 'seed_phrase' | 'private_key';

function parseImportSecret(importType: ImportType, importData: string): MpcSeedShards {
  return importType === 'private_key'
    ? MpcKeyGenerator.importPrivateKey(importData)
    : MpcKeyGenerator.importMpcSeed(importData);
}

/** Validate and de-duplicate requested indices. Returns null if invalid. */
function parseIndices(value: unknown): number[] | null {
  if (value === undefined) return [0];
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_IMPORT_INDICES) {
    return null;
  }
  const parsed = value.map(parseHdIndex);
  if (parsed.some((i) => i === null)) return null;
  return [...new Set(parsed as number[])];
}

/** Solana uses the account level as its per-address counter. */
function indexToAccountAndAddress(chain: ChainType, index: number) {
  return chain === ChainType.SOLANA
    ? { accountIndex: index, addressIndex: 0 }
    : { accountIndex: 0, addressIndex: index };
}

function validateImportRequest(body: Record<string, unknown>) {
  const { importType, importData } = body;
  const chainType = parseChainType(body.chainType);
  if (importType !== 'seed_phrase' && importType !== 'private_key') return null;
  if (typeof importData !== 'string' || importData.trim().length === 0) return null;
  if (!chainType) return null;
  return { importType: importType as ImportType, importData, chainType };
}

export const importMpcWallet = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  const request = validateImportRequest(req.body ?? {});
  const indices = parseIndices(req.body?.indices);
  const walletName = typeof req.body?.walletName === 'string' ? req.body.walletName.trim() : '';
  if (!request || !indices || !walletName) {
    return res.status(400).json({
      message: `walletName, importType, importData, chainType are required; indices must be up to ${MAX_IMPORT_INDICES} non-negative integers`,
    });
  }
  const { importType, importData, chainType } = request;
  const isSeedPhrase = importType === 'seed_phrase';

  if (!isSeedPhrase && indices.length > 1) {
    return res.status(400).json({ message: 'Cannot import multiple indices from a private key' });
  }

  let mpcSeed: MpcSeedShards | undefined;
  let seed: Buffer | undefined;

  try {
    const pinCheck = await verifyUserPin(userId, req.body.pin);
    if (!pinCheck.ok) {
      return res.status(pinCheck.status).json({ message: pinCheck.message });
    }
    const { pinWithPepper } = pinCheck;

    try {
      mpcSeed = parseImportSecret(importType, importData);
    } catch (error) {
      return res.status(400).json({ message: (error as Error).message });
    }

    const encryptedShardA = ShardEncryption.encryptShardA(mpcSeed.shardA, pinWithPepper);
    const shardBId = await ShardStorage.storeShardB(mpcSeed.shardB, userId);
    if (isSeedPhrase) {
      seed = SeedPhraseUtils.mnemonicToSeed(mpcSeed.mnemonic);
    }

    const createdWalletIds: string[] = [];
    const createdWallets = [];

    try {
      for (const index of indices) {
        const { accountIndex, addressIndex } = indexToAccountAndAddress(chainType, index);
        const derived: DerivedWallet = seed
          ? HDWalletDerivation.deriveWallet(seed, chainType, accountIndex, addressIndex)
          : MpcKeyGenerator.deriveWalletFromShards(
              mpcSeed.shardA,
              mpcSeed.shardB,
              chainType,
              0,
              0,
              false
            );
        derived.privateKey.fill(0);

        const indexLabel = indices.length > 1 ? ` ${index + 1}` : '';
        const mpcWallet = await prisma.mpcWallet.create({
          data: {
            userId,
            walletName: `${walletName}${indexLabel} (${chainLabel(chainType)})`,
            publicAddress: derived.address,
            curveType: derived.curveType,
            chainType: derived.chainType,
            derivationPath: derived.derivationPath,
            accountIndex: seed ? accountIndex : 0,
            addressIndex: seed ? addressIndex : 0,
            isImported: true,
            isSeedPhrase,
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
          mpcWallet.accountIndex,
          mpcWallet.addressIndex,
          encryptedShardA.salt
        );

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
      logger.error('mpc.wallet_import.rollback', { userId, importType, chainType, err: error });
      await prisma.mpcWallet
        .deleteMany({ where: { id: { in: createdWalletIds } } })
        .catch(() => undefined);
      await ShardStorage.deleteShardB(shardBId).catch(() => undefined);
      throw error;
    }

    await prisma.user.update({ where: { id: userId }, data: { mpc_enabled: true } });
    await PolicyService.getOrCreatePolicy(userId);
    logSecurityEvent(userId, UserSecurityEventType.MPC_WALLET_CREATED, context);

    return res.status(201).json({ wallets: createdWallets, vaultId: shardBId });
  } catch (error) {
    logger.error('mpc.wallet_import.failed', { userId, importType, chainType, err: error });
    return res.status(500).json({ message: 'Failed to import wallet' });
  } finally {
    zeroizeBuffers(seed);
    if (mpcSeed) zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);
  }
};

/** Preview the addresses an import would produce, without persisting anything. */
export const verifyImportAddress = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);
  if (!userId) return res.status(401).json({ message: 'Unauthorized' });

  const request = validateImportRequest(req.body ?? {});
  if (!request) {
    return res.status(400).json({ message: 'importType, importData, and chainType are required' });
  }
  const { importType, importData, chainType } = request;
  const isSeedPhrase = importType === 'seed_phrase';

  let mpcSeed: MpcSeedShards | undefined;
  try {
    try {
      mpcSeed = parseImportSecret(importType, importData);
    } catch (error) {
      return res.status(400).json({ message: (error as Error).message });
    }

    const derived = MpcKeyGenerator.deriveAddresses(
      mpcSeed.entropy,
      chainType,
      isSeedPhrase,
      isSeedPhrase ? PREVIEW_ADDRESS_COUNT : 1
    );

    const addresses = derived.map((wallet, index) => ({
      chainType,
      address: wallet.address,
      derivationPath: wallet.derivationPath,
      index,
      label: isSeedPhrase ? `Account ${index + 1}` : 'Imported Account',
    }));

    return res.status(200).json({ addresses, isSeedPhrase });
  } catch (error) {
    logger.error('mpc.wallet_import.verify_failed', { userId, importType, chainType, err: error });
    return res.status(500).json({ message: 'Failed to verify import' });
  } finally {
    if (mpcSeed) zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);
  }
};
