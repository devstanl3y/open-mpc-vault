import { Response, Request } from 'express';
import prisma from '../utils/prisma';
import { ShardEncryption } from '../utils/mpc/shardEncryption';
import { ShardStorage } from '../utils/mpc/shardStorage';
import { MpcKeyGenerator } from '../utils/mpc/keyGenerator';
import { ChainType } from '@prisma/client';

const PIN_PEPPER = process.env.PIN_PEPPER_SECRET;

if (!PIN_PEPPER) {
  throw new Error('FATAL: PIN_PEPPER_SECRET must be set in environment variables');
}

export const getMpcWalletInternal = async (req: Request, res: Response) => {
  const { walletId } = req.params;

  if (typeof walletId !== 'string') {
    return res.status(400).json({ message: 'Invalid wallet ID format' });
  }

  try {
    const wallet = await prisma.mpcWallet.findUnique({
      where: { id: walletId },
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
        shardBId: true,
        status: true,
        createdAt: true,
        lastUsedAt: true
      }
    });

    if (!wallet) {
      return res.status(404).json({ message: 'MPC wallet not found' });
    }

    res.status(200).json(wallet);
  } catch (error) {
    console.error('Error fetching MPC wallet:', error);
    res.status(500).json({ message: 'Failed to fetch MPC wallet' });
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
      select: {
        driveFileId: true,
        backupIv: true,
        backupTag: true,
        lastSyncedAt: true
      }
    });

    if (!backup) {
      return res.status(404).json({ message: 'No backup found for this wallet' });
    }

    res.status(200).json(backup);
  } catch (error) {
    console.error('Error fetching wallet shard data:', error);
    res.status(500).json({ message: 'Failed to fetch shard data' });
  }
};

export const decryptShardAInternal = async (req: Request, res: Response) => {
  const { encrypted, iv, tag, pin, salt } = req.body;

  if (!encrypted || !iv || !tag || !pin) {
    return res.status(400).json({ 
      message: 'encrypted, iv, tag, and pin are required' 
    });
  }

  if (!salt) {
    return res.status(400).json({ 
      message: 'salt is required for current shard format' 
    });
  }

  try {
    const pinWithPepper = pin + PIN_PEPPER;
    
    const decryptedShard = ShardEncryption.decryptShardA(
      encrypted,
      iv,
      tag,
      pinWithPepper,
      salt
    );

    res.status(200).json({ 
      shard: decryptedShard.toString('hex'),
      length: decryptedShard.length
    });
  } catch (error) {
    console.error('Error decrypting shard A:', error);
    res.status(500).json({ message: 'Failed to decrypt shard A' });
  }
};

export const encryptShardAInternal = async (req: Request, res: Response) => {
  const { shard, pin } = req.body;

  if (!shard || !pin) {
    return res.status(400).json({ 
      message: 'shard and pin are required' 
    });
  }

  try {
    const pinWithPepper = pin + PIN_PEPPER;
    const shardBuffer = Buffer.from(shard, 'hex');
    
    const encrypted = ShardEncryption.encryptShardA(shardBuffer, pinWithPepper);

    res.status(200).json(encrypted);
  } catch (error) {
    console.error('Error encrypting shard A:', error);
    res.status(500).json({ message: 'Failed to encrypt shard A' });
  }
};

export const getShardBInternal = async (req: Request, res: Response) => {
  const { shardBId } = req.params;

  if (typeof shardBId !== 'string') {
    return res.status(400).json({ message: 'Invalid shard B ID format' });
  }

  try {
    const shardB = await ShardStorage.retrieveShardB(shardBId);

    if (!shardB) {
      return res.status(404).json({ message: 'Shard B not found' });
    }

    res.status(200).json({ 
      shard: shardB.toString('hex'),
      length: shardB.length
    });
  } catch (error) {
    console.error('Error fetching shard B:', error);
    res.status(500).json({ message: 'Failed to fetch shard B' });
  }
};

export const reconstructKeyInternal = async (req: Request, res: Response) => {
  const { shardA, shardB } = req.body;

  if (!shardA || !shardB) {
    return res.status(400).json({ 
      message: 'shardA and shardB are required' 
    });
  }

  try {
    const shardABuffer = Buffer.from(shardA, 'hex');
    const shardBBuffer = Buffer.from(shardB, 'hex');
    
    const entropy = MpcKeyGenerator.reconstructEntropy(shardABuffer, shardBBuffer);

    res.status(200).json({ 
      entropy: entropy.toString('hex'),
      length: entropy.length
    });
  } catch (error) {
    console.error('Error reconstructing entropy:', error);
    res.status(500).json({ message: 'Failed to reconstruct entropy' });
  }
};

export const deriveAddressInternal = async (req: Request, res: Response) => {
  const { shardA, shardB, chainType, accountIndex, addressIndex, isSeedPhrase } = req.body;

  if (!shardA || !shardB || !chainType) {
    return res.status(400).json({ 
      message: 'shardA, shardB, and chainType are required' 
    });
  }

  try {
    const shardABuffer = Buffer.from(shardA, 'hex');
    const shardBBuffer = Buffer.from(shardB, 'hex');
    
    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardABuffer,
      shardBBuffer,
      chainType as ChainType,
      accountIndex || 0,
      addressIndex || 0,
      isSeedPhrase !== false
    );

    res.status(200).json({
      address: derived.address,
      publicKey: derived.publicKey.toString('hex'),
      chainType: derived.chainType,
      curveType: derived.curveType,
      derivationPath: derived.derivationPath
    });
  } catch (error) {
    console.error('Error deriving address:', error);
    res.status(500).json({ message: 'Failed to derive address' });
  }
};

export const validateShardInternal = async (req: Request, res: Response) => {
  const { walletId, shardA, pin } = req.body;

  if (!walletId || !shardA || !pin) {
    return res.status(400).json({ 
      message: 'walletId, shardA, and pin are required' 
    });
  }

  try {
    const wallet = await prisma.mpcWallet.findUnique({
      where: { id: walletId },
      select: {
        shardBId: true,
        chainType: true,
        accountIndex: true,
        addressIndex: true,
        isSeedPhrase: true,
        publicAddress: true
      }
    });

    if (!wallet) {
      return res.status(404).json({ message: 'Wallet not found' });
    }

    const shardABuffer = Buffer.from(shardA, 'hex');
    const shardB = await ShardStorage.retrieveShardB(wallet.shardBId);

    if (!shardB) {
      return res.status(404).json({ message: 'Shard B not found' });
    }

    const derived = MpcKeyGenerator.deriveWalletFromShards(
      shardABuffer,
      shardB,
      wallet.chainType as ChainType,
      wallet.accountIndex,
      wallet.addressIndex,
      wallet.isSeedPhrase
    );

    const isValid = derived.address.toLowerCase() === wallet.publicAddress.toLowerCase();

    res.status(200).json({
      valid: isValid,
      expectedAddress: wallet.publicAddress,
      derivedAddress: derived.address
    });
  } catch (error) {
    console.error('Error validating shard:', error);
    res.status(500).json({ message: 'Failed to validate shard' });
  }
};

export const healthCheckInternal = async (req: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    
    const testShardBId = 'health-check-test';
    const testShard = Buffer.from('test', 'utf8');
    
    const encrypted = ShardEncryption.encryptShardB(testShard);
    const decrypted = ShardEncryption.decryptShardB(encrypted);
    
    const encryptionWorks = decrypted.toString('utf8') === 'test';

    res.status(200).json({
      status: 'healthy',
      database: 'connected',
      encryption: encryptionWorks ? 'working' : 'failed',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    });
  }
};