import { Response } from 'express';
import bcrypt from 'bcrypt';
import { CurveType, ShardStatus, UserSecurityEventType } from '@prisma/client';
import type { IUserRequest } from '../../middleware/requireAuth';
import prisma from '../../utils/prisma';
import { MpcKeyGenerator } from '../../utils/mpc/keyGenerator';
import { ShardEncryption } from '../../utils/mpc/shardEncryption';
import { ShardStorage } from '../../utils/mpc/shardStorage';
import { ChainType, HDWalletDerivation } from '../../utils/mpc/hdWallet';
import { SeedPhraseUtils } from '../../utils/mpc/seedPhrase';
import { logSecurityEvent } from '../../utils/securityLogger';
import { getRequestContext } from '../../utils/context';
import { cloudBackupService } from '../../utils/cloudBackup';
import { PolicyService } from '../../utils/policyService';
import { PIN_PEPPER, zeroizeBuffers } from './shared';
import { logger } from '../../utils/logger';

export const importMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletName, pin, importType, importData, chainType, indices } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });
  if (!walletName || !pin || !importType || !importData || !chainType) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  const indicesToImport = Array.isArray(indices) && indices.length > 0 ? indices : [0];

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.pin_hash) return res.status(401).json({ message: 'User PIN not set' });

    const pinWithPepper = pin + PIN_PEPPER;
    if (!(await bcrypt.compare(pinWithPepper, user.pin_hash))) {
      return res.status(401).json({ message: 'Invalid PIN' });
    }

    const selectedChain = chainType as ChainType;
    let mpcSeed;
    let isSeedPhrase = true;

    if (importType === 'private_key') {
      mpcSeed = MpcKeyGenerator.importPrivateKey(importData);
      isSeedPhrase = false;
      if (indicesToImport.length > 1) {
        return res.status(400).json({ message: 'Cannot import multiple indices from a private key' });
      }
    } else {
      mpcSeed = MpcKeyGenerator.importMpcSeed(importData);
      isSeedPhrase = true;
    }

    const encryptedShardA = ShardEncryption.encryptShardA(mpcSeed.shardA, pinWithPepper);
    const sharedShardBId = await ShardStorage.storeShardB(mpcSeed.shardB, userId);

    const createdWallets = [];
    const createdWalletIds: string[] = [];

    try {
      for (const index of indicesToImport) {
        let derived;
        if (isSeedPhrase) {
          const mnemonic = SeedPhraseUtils.entropyToMnemonic(mpcSeed.entropy);
          const seed = SeedPhraseUtils.mnemonicToSeed(mnemonic);

          if (selectedChain === ChainType.ETHEREUM) {
            derived = HDWalletDerivation.deriveEthereumWallet(seed, 0, index);
          } else if (selectedChain === ChainType.SOLANA) {
            derived = HDWalletDerivation.deriveSolanaWallet(seed, index);
          } else {
            derived = HDWalletDerivation.deriveBitcoinWallet(seed, 0, index);
          }
        } else {
          derived = MpcKeyGenerator.deriveWalletFromShards(
            mpcSeed.shardA,
            mpcSeed.shardB,
            selectedChain,
            0,
            0,
            false,
          );
        }

        const chainSuffix =
          selectedChain === ChainType.ETHEREUM
            ? 'EVM'
            : selectedChain === ChainType.SOLANA
              ? 'Solana'
              : 'Bitcoin';

        const indexLabel = indicesToImport.length > 1 ? ` ${index + 1}` : '';
        const fullWalletName = `${walletName}${indexLabel} (${chainSuffix})`;

        const mpcWallet = await prisma.mpcWallet.create({
          data: {
            userId,
            walletName: fullWalletName,
            publicAddress: derived.address,
            curveType: selectedChain === ChainType.SOLANA ? CurveType.ED25519 : CurveType.SECP256K1,
            chainType: derived.chainType,
            derivationPath: derived.derivationPath,
            accountIndex: selectedChain === ChainType.SOLANA ? index : 0,
            addressIndex: selectedChain === ChainType.SOLANA ? 0 : index,
            isImported: true,
            isSeedPhrase,
            shardBId: sharedShardBId,
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
          sharedShardBId,
          derived.derivationPath,
          derived.curveType,
          selectedChain === ChainType.SOLANA ? index : 0,
          selectedChain === ChainType.SOLANA ? 0 : index,
          encryptedShardA.salt,
        );

        createdWallets.push({
          id: mpcWallet.id,
          walletName: mpcWallet.walletName,
          publicAddress: mpcWallet.publicAddress,
          curveType: mpcWallet.curveType,
          chainType: mpcWallet.chainType,
          derivationPath: mpcWallet.derivationPath,
          shardBId: sharedShardBId,
          createdAt: mpcWallet.createdAt,
          encryptedShardA: {
            encrypted: encryptedShardA.encrypted,
            iv: encryptedShardA.iv,
            tag: encryptedShardA.tag,
            salt: encryptedShardA.salt,
          },
        });
      }

      zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);

      await prisma.user.update({ where: { id: userId }, data: { mpc_enabled: true } });
      await PolicyService.getOrCreatePolicy(userId);
      logSecurityEvent(userId, UserSecurityEventType.MPC_WALLET_CREATED, context);

      res.status(201).json({
        wallets: createdWallets,
        vaultId: sharedShardBId,
        message: 'Wallets imported successfully.',
      });
    } catch (innerError) {
      logger.error('mpc.wallet_import.wallet_creation_failed', {
        userId,
        importType,
        chainType,
        err: innerError,
      });

      for (const walletId of createdWalletIds) {
        await prisma.mpcWallet.delete({ where: { id: walletId } }).catch(() => {});
      }

      await ShardStorage.deleteShardB(sharedShardBId).catch(() => {});

      throw innerError;
    }
  } catch (error) {
    logger.error('mpc.wallet_import.failed', {
      userId,
      importType,
      chainType,
      hasPin: Boolean(pin),
      err: error,
    });
    res.status(500).json({ message: 'Failed to import wallet' });
  }
};

export const verifyImportAddress = async (req: IUserRequest, res: Response) => {
  const { importType, importData, chainType } = req.body;
  const userId = Number(req.user?.id);

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });
  if (!importType || !importData || !chainType) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    let mpcSeed;
    let isSeedPhrase = true;

    if (importType === 'private_key') {
      mpcSeed = MpcKeyGenerator.importPrivateKey(importData);
      isSeedPhrase = false;
    } else {
      mpcSeed = MpcKeyGenerator.importMpcSeed(importData);
      isSeedPhrase = true;
    }

    const selectedChain = chainType as ChainType;
    const addresses = [];

    if (isSeedPhrase) {
      const mnemonic = SeedPhraseUtils.entropyToMnemonic(mpcSeed.entropy);
      const seed = SeedPhraseUtils.mnemonicToSeed(mnemonic);

      const accountsToScan = 5;

      for (let i = 0; i < accountsToScan; i++) {
        let derived;
        let label;

        if (selectedChain === ChainType.ETHEREUM) {
          derived = HDWalletDerivation.deriveEthereumWallet(seed, 0, i);
          label = `Account ${i + 1}`;
        } else if (selectedChain === ChainType.SOLANA) {
          derived = HDWalletDerivation.deriveSolanaWallet(seed, i);
          label = `Account ${i + 1}`;
        } else {
          derived = HDWalletDerivation.deriveBitcoinWallet(seed, 0, i);
          label = `Account ${i + 1}`;
        }

        addresses.push({
          chainType: selectedChain,
          address: derived.address,
          derivationPath: derived.derivationPath,
          index: i,
          label,
        });
      }
    } else {
      const derived = MpcKeyGenerator.deriveWalletFromShards(
        mpcSeed.shardA,
        mpcSeed.shardB,
        selectedChain,
        0,
        0,
        false,
      );
      addresses.push({
        chainType: selectedChain,
        address: derived.address,
        derivationPath: derived.derivationPath,
        index: 0,
        label: 'Imported Account',
      });
    }

    zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);

    res.status(200).json({
      addresses,
      isSeedPhrase,
      message: 'Verified successfully.',
    });
  } catch (error) {
    logger.error('mpc.wallet_import.verify_address_failed', {
      userId,
      importType,
      chainType,
      err: error,
    });
    res.status(500).json({ message: 'Failed to verify import' });
  }
};
