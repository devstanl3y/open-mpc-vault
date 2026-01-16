import { Response } from 'express';
import { IUserRequest } from '../middleware/requireAuth';
import prisma from '../utils/prisma';
import { MpcKeyGenerator } from '../utils/mpc/keyGenerator';
import { ShardEncryption } from '../utils/mpc/shardEncryption';
import { ShardStorage } from '../utils/mpc/shardStorage';
import { SessionKeyManager } from '../utils/sessionKey';
import { CurveType, ShardStatus, PolicyLogStatus } from '@prisma/client';
import { ChainType, HDWalletDerivation } from '../utils/mpc/hdWallet';
import { SeedPhraseUtils } from '../utils/mpc/seedPhrase';
import bcrypt from 'bcrypt';
import { logSecurityEvent } from '../utils/securityLogger';
import { UserSecurityEventType } from '@prisma/client';
import { getRequestContext } from '../utils/context';
import { cloudBackupService } from '../utils/cloudBackup';
import { PolicyService } from '../utils/policyService';

const PIN_PEPPER = process.env.PIN_PEPPER_SECRET || '';

function zeroizeBuffers(...buffers: (Buffer | undefined)[]) {
  buffers.forEach(buffer => {
    if (buffer && Buffer.isBuffer(buffer)) {
      buffer.fill(0);
    }
  });
}

export const createMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletName, pin } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!walletName || !pin) {
    return res.status(400).json({ 
      message: 'walletName and pin are required' 
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

    const cloudProvider = await prisma.userCloudProvider.findUnique({
      where: { userId }
    });

    if (!cloudProvider || !cloudProvider.isConnected) {
      return res.status(400).json({ 
        message: 'Google Drive must be connected before creating a vault',
        requireCloudConnection: true
      });
    }

    const mpcSeed = MpcKeyGenerator.createMpcSeed(12);
    const encryptedShardA = ShardEncryption.encryptShardA(mpcSeed.shardA, pinWithPepper);
    const sharedShardBId = await ShardStorage.storeShardB(mpcSeed.shardB, userId);

    const chainConfigs = [
      { chainType: ChainType.ETHEREUM, suffix: 'EVM', account: 0, index: 0 },
      { chainType: ChainType.SOLANA, suffix: 'Solana', account: 0, index: 0 },
      { chainType: ChainType.BITCOIN, suffix: 'Bitcoin', account: 0, index: 0 }
    ];

    const createdWallets = [];
    const createdWalletIds: string[] = [];

    try {
      for (const config of chainConfigs) {
        const derived = MpcKeyGenerator.deriveWalletFromShards(
          mpcSeed.shardA,
          mpcSeed.shardB,
          config.chainType,
          config.account,
          config.index,
          true
        );

        const fullWalletName = `${walletName} (${config.suffix})`;

        const mpcWallet = await prisma.mpcWallet.create({
          data: {
            userId,
            walletName: fullWalletName,
            publicAddress: derived.address,
            curveType: derived.curveType,
            chainType: derived.chainType,
            derivationPath: derived.derivationPath,
            accountIndex: config.account,
            addressIndex: config.index,
            isImported: false,
            isSeedPhrase: true,
            shardBId: sharedShardBId,
            status: ShardStatus.ACTIVE
          }
        });

        createdWalletIds.push(mpcWallet.id);

        await cloudBackupService.backupShardA(
          userId,
          mpcWallet.id,
          encryptedShardA.encrypted,
          encryptedShardA.iv,
          encryptedShardA.tag,
          pinWithPepper,
          derived.chainType,
          sharedShardBId,
          derived.derivationPath,
          derived.curveType,
          config.account,
          config.index,
          encryptedShardA.salt
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
            salt: encryptedShardA.salt
          }
        });

        logSecurityEvent(
          userId,
          UserSecurityEventType.CLOUD_BACKUP_CREATED,
          context
        );
      }

      zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);

      await prisma.user.update({
        where: { id: userId },
        data: { mpc_enabled: true }
      });

      await PolicyService.getOrCreatePolicy(userId);

      logSecurityEvent(
        userId,
        UserSecurityEventType.MPC_WALLET_CREATED,
        context
      );

      res.status(201).json({
        wallets: createdWallets,
        vaultId: sharedShardBId,
        cloudBackupEnabled: true,
        message: 'Vault created successfully. Your keys are secured with MPC and backed up to cloud.'
      });

    } catch (error) {
      console.error('Failed to create wallets:', error);
      
      for (const walletId of createdWalletIds) {
        await prisma.mpcWallet.delete({ where: { id: walletId } }).catch(() => {});
      }
      
      await ShardStorage.deleteShardB(sharedShardBId).catch(() => {});
      
      throw error;
    }

  } catch (error) {
    console.error('MPC wallet creation error:', error);
    res.status(500).json({ message: 'Failed to create MPC wallets' });
  }
};

export const importMpcWallet = async (req: IUserRequest, res: Response) => {
  const { 
    walletName, 
    pin, 
    importType, 
    importData, 
    chainType, 
    indices 
  } = req.body;
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
    if (!await bcrypt.compare(pinWithPepper, user.pin_hash)) return res.status(401).json({ message: 'Invalid PIN' });

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
            mpcSeed.shardA, mpcSeed.shardB, selectedChain, 0, 0, false
          );
        }

        const chainSuffix = selectedChain === ChainType.ETHEREUM ? 'EVM' : 
                           selectedChain === ChainType.SOLANA ? 'Solana' : 'Bitcoin';
        
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
            status: ShardStatus.ACTIVE
          }
        });

        createdWalletIds.push(mpcWallet.id);

        await cloudBackupService.backupShardA(
          userId,
          mpcWallet.id,
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
          encryptedShardA.salt
        );

        createdWallets.push(mpcWallet);
      }

      zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);

      await prisma.user.update({ where: { id: userId }, data: { mpc_enabled: true } });
      await PolicyService.getOrCreatePolicy(userId);
      logSecurityEvent(userId, UserSecurityEventType.MPC_WALLET_CREATED, context);

      res.status(201).json({
        wallets: createdWallets,
        vaultId: sharedShardBId,
        message: 'Wallets imported successfully.'
      });

    } catch (innerError) {
      console.error('Import error during wallet creation:', innerError);
      
      for (const walletId of createdWalletIds) {
        await prisma.mpcWallet.delete({ where: { id: walletId } }).catch(() => {});
      }
      
      await ShardStorage.deleteShardB(sharedShardBId).catch(() => {});
      
      throw innerError;
    }

  } catch (error) {
    console.error('Import error:', error);
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
          label
        });
      }
    } else {
      const derived = MpcKeyGenerator.deriveWalletFromShards(
        mpcSeed.shardA, mpcSeed.shardB, selectedChain, 0, 0, false
      );
      addresses.push({
        chainType: selectedChain,
        address: derived.address,
        derivationPath: derived.derivationPath,
        index: 0,
        label: 'Imported Account'
      });
    }

    zeroizeBuffers(mpcSeed.shardA, mpcSeed.shardB, mpcSeed.entropy);

    res.status(200).json({
      addresses,
      isSeedPhrase,
      message: 'Verified successfully.'
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ message: 'Failed to verify import' });
  }
};

export const deriveAdditionalWallet = async (req: IUserRequest, res: Response) => {
  const { walletId, pin, chainType, accountIndex, addressIndex = 0, shardAEncrypted, shardAIv, shardATag, shardASalt } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!walletId || !pin || !chainType || accountIndex === undefined || !shardAEncrypted || !shardAIv || !shardATag) {
    return res.status(400).json({ 
      message: 'walletId, pin, chainType, accountIndex, and encrypted shard A data are required' 
    });
  }

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;

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

    const existingWallet = await prisma.mpcWallet.findFirst({
      where: {
        id: walletId,
        userId,
        status: ShardStatus.ACTIVE
      }
    });

    if (!existingWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    if (!existingWallet.isSeedPhrase) {
      return res.status(400).json({ 
        message: 'Cannot derive additional wallets from imported private keys' 
      });
    }

    shardA = ShardEncryption.decryptShardA(
      shardAEncrypted,
      shardAIv,
      shardATag,
      pinWithPepper,
      shardASalt
    );

    shardB = await ShardStorage.retrieveShardB(existingWallet.shardBId);
    if (!shardB) {
      return res.status(500).json({ message: 'Shard B not found' });
    }

    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardA,
      shardB,
      chainType as ChainType,
      accountIndex,
      addressIndex,
      true
    );

    const existingAddress = await prisma.mpcWallet.findFirst({
      where: {
        publicAddress: derived.address,
        userId
      }
    });

    if (existingAddress) {
      return res.status(400).json({ 
        message: 'This wallet address already exists in your account' 
      });
    }

    const chainSuffix = chainType === ChainType.ETHEREUM ? 'EVM' : 
                        chainType === ChainType.SOLANA ? 'Solana' : 'Bitcoin';
    const walletName = `Wallet ${accountIndex + 1} (${chainSuffix})`;

    const encryptedShardA = ShardEncryption.encryptShardA(shardA, pinWithPepper);

    const newWallet = await prisma.mpcWallet.create({
      data: {
        userId,
        walletName,
        publicAddress: derived.address,
        curveType: derived.curveType,
        chainType: derived.chainType,
        derivationPath: derived.derivationPath,
        accountIndex,
        addressIndex,
        isImported: false,
        isSeedPhrase: true,
        shardBId: existingWallet.shardBId,
        status: ShardStatus.ACTIVE
      }
    });

    await cloudBackupService.backupShardA(
      userId,
      newWallet.id,
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

    logSecurityEvent(
      userId,
      UserSecurityEventType.MPC_WALLET_CREATED,
      context
    );

    res.status(201).json({
      id: newWallet.id,
      walletName: newWallet.walletName,
      publicAddress: newWallet.publicAddress,
      curveType: newWallet.curveType,
      chainType: newWallet.chainType,
      derivationPath: newWallet.derivationPath,
      createdAt: newWallet.createdAt
    });
  } catch (error) {
    console.error('Wallet derivation error:', error);
    res.status(500).json({ message: 'Failed to derive additional wallet' });
  } finally {
    zeroizeBuffers(shardA, shardB);
  }
};

export const recoverFromCloud = async (req: IUserRequest, res: Response) => {
  const { fileId, pin } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;

  if (!userId) return res.status(401).json({ message: 'Unauthorized' });
  if (!fileId || !pin) return res.status(400).json({ message: 'Missing fileId or PIN' });

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.pin_hash) return res.status(401).json({ message: 'User PIN not set' });
    
    const pinWithPepper = pin + PIN_PEPPER;
    if (!await bcrypt.compare(pinWithPepper, user.pin_hash)) return res.status(401).json({ message: 'Invalid PIN' });

    const backupData = await cloudBackupService.fetchBackup(userId, fileId);
    
    if (backupData.version === 2) {
      return res.status(400).json({ 
        message: 'This backup uses an old format. Please create a new vault and transfer your assets.' 
      });
    }
    
    if (backupData.version !== 3) {
      return res.status(400).json({ message: 'Unsupported backup version' });
    }

    if (!backupData.salt) {
      return res.status(400).json({ 
        message: 'Invalid backup format: missing salt. Please contact support.' 
      });
    }

    shardA = ShardEncryption.decryptShardA(
      backupData.encryptedShardA,
      backupData.iv,
      backupData.tag,
      pinWithPepper,
      backupData.salt
    );

    if (!backupData.shardBId) {
      return res.status(400).json({ message: 'Legacy backup format not supported.' });
    }

    shardB = await ShardStorage.retrieveShardB(backupData.shardBId);
    
    if (!shardB) {
      return res.status(400).json({ 
        message: 'Critical: The server-side key for this wallet is missing. Recovery impossible.' 
      });
    }

    const accountIndex = backupData.accountIndex || 0;
    const addressIndex = backupData.addressIndex || 0;

    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardA,
      shardB,
      backupData.chainType,
      accountIndex,
      addressIndex,
      true
    );

    const existingWallet = await prisma.mpcWallet.findUnique({
      where: { id: backupData.walletId }
    });

    if (existingWallet && existingWallet.publicAddress !== derived.address) {
      console.error('Address mismatch during recovery:', {
        expected: existingWallet.publicAddress,
        derived: derived.address,
        accountIndex,
        addressIndex
      });
      
      logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
      
      return res.status(400).json({ 
        message: 'Recovery failed: Address mismatch. Please contact support.' 
      });
    }

    const mpcWallet = await prisma.mpcWallet.upsert({
      where: { id: backupData.walletId },
      update: { 
        status: ShardStatus.ACTIVE
      },
      create: {
        id: backupData.walletId, 
        userId,
        walletName: `Recovered ${backupData.chainType} Wallet`,
        publicAddress: derived.address,
        curveType: backupData.curveType,
        chainType: backupData.chainType,
        derivationPath: backupData.derivationPath,
        accountIndex: accountIndex,
        addressIndex: addressIndex,
        isImported: true,
        isSeedPhrase: true,
        shardBId: backupData.shardBId,
        status: ShardStatus.ACTIVE
      }
    });

    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_SUCCESS, context);

    return res.status(200).json({ 
      message: 'Wallet recovered successfully', 
      wallet: mpcWallet,
      encryptedShardA: {
        encrypted: backupData.encryptedShardA,
        iv: backupData.iv,
        tag: backupData.tag,
        salt: backupData.salt
      }
    });

  } catch (error) {
    console.error('Recovery error:', error);
    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
    res.status(500).json({ message: 'Failed to recover from cloud' });
  } finally {
    zeroizeBuffers(shardA, shardB);
  }
};

export const getMpcWallets = async (req: IUserRequest, res: Response) => {
  const userId = Number(req.user?.id);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const wallets = await prisma.mpcWallet.findMany({
      where: { 
        userId,
        status: ShardStatus.ACTIVE
      },
      select: {
        id: true,
        walletName: true,
        publicAddress: true,
        curveType: true,
        chainType: true,
        derivationPath: true,
        accountIndex: true,
        addressIndex: true,
        isImported: true,
        isSeedPhrase: true,
        createdAt: true,
        shardBId: true,
        lastUsedAt: true,
        shardABackups: {
          select: {
            lastSyncedAt: true
          },
          orderBy: {
            lastSyncedAt: 'desc'
          },
          take: 1
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    const walletsWithBackupStatus = wallets.map(wallet => ({
      id: wallet.id,
      walletName: wallet.walletName,
      publicAddress: wallet.publicAddress,
      curveType: wallet.curveType,
      chainType: wallet.chainType,
      derivationPath: wallet.derivationPath,
      accountIndex: wallet.accountIndex,
      addressIndex: wallet.addressIndex,
      isImported: wallet.isImported,
      isSeedPhrase: wallet.isSeedPhrase,
      shardBId: wallet.shardBId,
      createdAt: wallet.createdAt,
      lastUsedAt: wallet.lastUsedAt,
      cloudBackupEnabled: wallet.shardABackups.length > 0,
      lastBackupSync: wallet.shardABackups[0]?.lastSyncedAt || null
    }));

    res.status(200).json(walletsWithBackupStatus);
  } catch (error) {
    console.error('Error fetching MPC wallets:', error);
    res.status(500).json({ message: 'Failed to fetch MPC wallets' });
  }
};

export const signWithMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletId, messageHash, pin, amountUsd, tokenSymbol, chain, toAddress, contractAddress, shardAEncrypted, shardAIv, shardATag, shardASalt } = req.body;
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
      message: 'walletId, messageHash, pin, and encrypted shard A data are required' 
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
        status: ShardStatus.ACTIVE
      }
    });

    if (!mpcWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    let spendingLog;
    if (amountUsd && tokenSymbol && chain && toAddress) {
      spendingLog = await PolicyService.logTransaction(userId, {
        amount: amountUsd,
        amountUsd: parseFloat(amountUsd),
        tokenSymbol,
        chain,
        toAddress,
        contractAddress,
        status: PolicyLogStatus.APPROVED
      });
    }

    shardA = ShardEncryption.decryptShardA(
      shardAEncrypted,
      shardAIv,
      shardATag,
      pinWithPepper,
      shardASalt 
    );

    shardB = await ShardStorage.retrieveShardB(mpcWallet.shardBId);
    if (!shardB) {
      return res.status(500).json({ message: 'Shard B not found' });
    }

    if (mpcWallet.isSeedPhrase && mpcWallet.chainType) {
      const derived = MpcKeyGenerator.deriveWalletFromShards(
        shardA,
        shardB,
        mpcWallet.chainType as ChainType,
        mpcWallet.accountIndex,
        mpcWallet.addressIndex,
        true
      );
      privateKey = derived.privateKey;
    } else {
      privateKey = MpcKeyGenerator.reconstructEntropy(shardA, shardB);
    }

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
      data: { lastUsedAt: new Date() }
    });

    logSecurityEvent(
      userId,
      UserSecurityEventType.MPC_SIGNATURE_GENERATED,
      context
    );

    res.status(200).json({ 
      signature,
      spendingLogId: spendingLog?.id
    });
  } catch (error) {
    console.error('MPC signing error:', error);
    res.status(500).json({ message: 'Failed to sign with MPC wallet' });
  } finally {
    zeroizeBuffers(shardA, shardB, privateKey);
  }
};

export const signWithSession = async (req: IUserRequest, res: Response) => {
  const { walletId, messageHash, sessionToken, amountUsd, tokenSymbol, chain, toAddress, contractAddress } = req.body;
  const userId = Number(req.user?.id);
  const context = getRequestContext(req);

  let shardA: Buffer | undefined;
  let shardB: Buffer | undefined;
  let privateKey: Buffer | undefined;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!walletId || !messageHash || !sessionToken) {
    return res.status(400).json({ 
      message: 'walletId, messageHash, and sessionToken are required' 
    });
  }

  try {
    const session = await SessionKeyManager.validateSession(sessionToken);
    
    if (!session) {
      return res.status(401).json({
        message: 'Invalid or expired session',
        code: 'SESSION_INVALID'
      });
    }

    if (session.userId !== userId || session.mpcWalletId !== walletId) {
      return res.status(403).json({
        message: 'Session does not match wallet or user',
        code: 'SESSION_MISMATCH'
      });
    }

    const mpcWallet = await prisma.mpcWallet.findFirst({
      where: {
        id: walletId,
        userId,
        status: ShardStatus.ACTIVE
      }
    });

    if (!mpcWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    let spendingLog;
    if (amountUsd && tokenSymbol && chain && toAddress) {
      spendingLog = await PolicyService.logTransaction(userId, {
        amount: amountUsd,
        amountUsd: parseFloat(amountUsd),
        tokenSymbol,
        chain,
        toAddress,
        contractAddress,
        status: PolicyLogStatus.APPROVED
      });
    }

    if (!session.encryptedShardA || !session.shardAIv || !session.shardATag) {
      return res.status(500).json({ message: 'Session does not contain encrypted shard data' });
    }

    shardA = ShardEncryption.decryptShardA(
      session.encryptedShardA,
      session.shardAIv,
      session.shardATag,
      session.sessionKey,
      session.shardASalt 
    );

    shardB = await ShardStorage.retrieveShardB(mpcWallet.shardBId);
    if (!shardB) {
      return res.status(500).json({ message: 'Shard B not found' });
    }

    if (mpcWallet.isSeedPhrase && mpcWallet.chainType) {
      const derived = MpcKeyGenerator.deriveWalletFromShards(
        shardA,
        shardB,
        mpcWallet.chainType as ChainType,
        mpcWallet.accountIndex,
        mpcWallet.addressIndex,
        true
      );
      privateKey = derived.privateKey;
    } else {
      privateKey = MpcKeyGenerator.reconstructEntropy(shardA, shardB);
    }

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
      data: { lastUsedAt: new Date() }
    });

    await SessionKeyManager.refreshSession(sessionToken);

    logSecurityEvent(
      userId,
      UserSecurityEventType.MPC_SIGNATURE_GENERATED,
      context
    );

    logSecurityEvent(
      userId,
      UserSecurityEventType.BIOMETRIC_SESSION_USED,
      context
    );

    res.status(200).json({ 
      signature,
      spendingLogId: spendingLog?.id
    });
  } catch (error) {
    console.error('Session-based MPC signing error:', error);
    res.status(500).json({ message: 'Failed to sign with session' });
  } finally {
    zeroizeBuffers(shardA, shardB, privateKey);
  }
};

export const deleteMpcWallet = async (req: IUserRequest, res: Response) => {
  const { walletId } = req.params;
  const { pin } = req.body;
  const userId = Number(req.user?.id);

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!pin) {
    return res.status(400).json({ message: 'PIN is required' });
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
        userId
      }
    });


    if (!mpcWallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    const walletsWithSameShardB = await prisma.mpcWallet.count({
      where: {
        shardBId: mpcWallet.shardBId,
        userId,
        id: { not: walletId }
      }
    });

    try {
      await cloudBackupService.deleteBackup(userId, walletId);
    } catch (backupError) {
      
    }

    await SessionKeyManager.revokeAllUserSessions(userId);

    if (walletsWithSameShardB === 0) {
      await ShardStorage.deleteShardB(mpcWallet.shardBId);
    }

    await prisma.mpcWallet.delete({
      where: { id: walletId }
    });

    res.status(200).json({ message: 'MPC wallet deleted successfully' });
  } catch (error) {
    console.error('Error deleting MPC wallet:', error);
    res.status(500).json({ message: 'Failed to delete MPC wallet' });
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
    if (!await bcrypt.compare(pinWithPepper, user.pin_hash)) {
      return res.status(401).json({ message: 'Invalid PIN' });
    }

    const allBackups = await cloudBackupService.listBackups(userId);
    
    if (!allBackups || allBackups.length === 0) {
      return res.status(404).json({ message: 'No backups found in cloud' });
    }

    const backupsByVault = new Map<string, any[]>();
    
    for (const backup of allBackups) {
      try {
        const backupData = await cloudBackupService.fetchBackup(userId, backup.id!);
        
        if (backupData.version !== 3 || !backupData.shardBId) continue;

        if (!backupsByVault.has(backupData.shardBId)) {
          backupsByVault.set(backupData.shardBId, []);
        }
        
        backupsByVault.get(backupData.shardBId)!.push({
          fileId: backup.id,
          ...backupData
        });
      } catch (error) {
        console.error(`Failed to fetch backup ${backup.id}:`, error);
      }
    }

    if (backupsByVault.size === 0) {
      return res.status(404).json({ 
        message: 'No valid backups found. Please create a new vault.' 
      });
    }

    const allRecoveredWallets = [];
    const allErrors = [];

    for (const [shardBId, vaultBackups] of backupsByVault.entries()) {
      let shardA: Buffer | undefined;
      let shardB: Buffer | undefined;

      try {
        shardB = await ShardStorage.retrieveShardB(shardBId);
        
        if (!shardB) {
          allErrors.push({
            vaultId: shardBId,
            error: 'Server-side key missing'
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
              backupData.salt
            );

            const accountIndex = backupData.accountIndex || 0;
            const addressIndex = backupData.addressIndex || 0;

            const derived = MpcKeyGenerator.deriveWalletFromShards(
              shardA,
              shardB!,
              backupData.chainType,
              accountIndex,
              addressIndex,
              true
            );

            const existingWallet = await prisma.mpcWallet.findUnique({
              where: { id: backupData.walletId }
            });

            if (existingWallet && existingWallet.publicAddress !== derived.address) {
              allErrors.push({
                chainType: backupData.chainType,
                walletId: backupData.walletId,
                error: 'Address mismatch'
              });
              continue;
            }

            const mpcWallet = await prisma.mpcWallet.upsert({
              where: { id: backupData.walletId },
              update: { status: ShardStatus.ACTIVE },
              create: {
                id: backupData.walletId, 
                userId,
                walletName: `Recovered ${backupData.chainType} Wallet`,
                publicAddress: derived.address,
                curveType: backupData.curveType,
                chainType: backupData.chainType,
                derivationPath: backupData.derivationPath,
                accountIndex: accountIndex,
                addressIndex: addressIndex,
                isImported: true,
                isSeedPhrase: true,
                shardBId: backupData.shardBId,
                status: ShardStatus.ACTIVE
              }
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
                salt: backupData.salt
              }
            });

            if (shardA && Buffer.isBuffer(shardA)) {
              shardA.fill(0);
            }

          } catch (walletError) {
            console.error(`Failed to recover wallet:`, walletError);
            allErrors.push({
              chainType: backupData.chainType,
              walletId: backupData.walletId,
              error: walletError instanceof Error ? walletError.message : 'Unknown error'
            });
          }
        }

        if (shardB && Buffer.isBuffer(shardB)) {
          shardB.fill(0);
        }

      } catch (vaultError) {
        console.error(`Failed to process vault ${shardBId}:`, vaultError);
        allErrors.push({
          vaultId: shardBId,
          error: vaultError instanceof Error ? vaultError.message : 'Unknown error'
        });
      }
    }

    if (allRecoveredWallets.length === 0) {
      logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_FAILED, context);
      return res.status(500).json({ 
        message: 'Failed to recover any wallets',
        errors: allErrors 
      });
    }

    await prisma.user.update({
      where: { id: userId },
      data: { mpc_enabled: true }
    });

    logSecurityEvent(userId, UserSecurityEventType.CLOUD_RECOVERY_SUCCESS, context);

    return res.status(200).json({ 
      message: `Successfully recovered ${allRecoveredWallets.length} wallet(s)`,
      wallets: allRecoveredWallets,
      totalVaults: backupsByVault.size,
      errors: allErrors.length > 0 ? allErrors : undefined
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
    
    try {
      allBackups = await cloudBackupService.listBackups(userId);
    } catch (backupError) {
      console.error('[listRecoverableVaults] ERROR fetching backups:', backupError);
      return res.status(200).json({ vaults: [] });
    }
    
    if (!allBackups || allBackups.length === 0) {
      return res.status(200).json({ vaults: [] });
    }

    const vaultMap = new Map<string, {
      shardBId: string;
      wallets: any[];
      createdAt: Date;
    }>();

    for (const backup of allBackups) {
      try {
        if (!backup || !backup.id) continue;

        let backupData;
        try {
          backupData = await cloudBackupService.fetchBackup(userId, backup.id);
        } catch (fetchError) {
          console.error(`[listRecoverableVaults] Failed to fetch backup ${backup.id}:`, fetchError);
          continue;
        }

        // Skip if no data or missing critical fields
        if (!backupData || typeof backupData !== 'object') continue;
        
        const version = backupData.version || (backupData.shardBId ? 2 : undefined);
        const shardBId = backupData.shardBId;
        
        // Only process version 3 backups (new format with salt)
        if (version !== 3 || !shardBId) continue;

        if (!vaultMap.has(shardBId)) {
          vaultMap.set(shardBId, {
            shardBId: shardBId,
            wallets: [],
            createdAt: new Date(backupData.timestamp || backup.createdTime || Date.now())
          });
        }

        const vault = vaultMap.get(shardBId)!;
        vault.wallets.push({
          chainType: backupData.chainType,
          walletId: backupData.walletId,
          fileId: backup.id
        });

      } catch (error) {
        console.error(`[listRecoverableVaults] ERROR processing backup:`, error);
      }
    }

    const vaults = Array.from(vaultMap.entries()).map(([shardBId, data]) => ({
      shardBId,
      walletsCount: data.wallets.length,
      chains: data.wallets.map(w => w.chainType),
      createdAt: data.createdAt
    }));

    return res.status(200).json({ vaults });

  } catch (error) {
    console.error('[listRecoverableVaults] CRITICAL ERROR:', error);
    return res.status(500).json({ 
      message: 'Failed to list recoverable vaults',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
};