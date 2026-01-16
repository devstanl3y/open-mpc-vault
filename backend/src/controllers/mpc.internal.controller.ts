import { Response, Request } from 'express';
import prisma from '../utils/prisma';
import { ShardEncryption } from '../utils/mpc/shardEncryption';
import { ShardStorage } from '../utils/mpc/shardStorage';

export const getMpcWalletInternal = async (req: Request, res: Response) => {
  const { walletId } = req.params;

  try {
    const wallet = await prisma.mpcWallet.findUnique({
      where: { id: walletId },
      select: {
        id: true,
        shardAEncrypted: true,
        shardAIv: true,
        shardATag: true,
        shardBId: true,
        curveType: true,
        publicAddress: true
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

export const decryptShardAInternal = async (req: Request, res: Response) => {
  const { encrypted, iv, tag, pin } = req.body;

  if (!encrypted || !iv || !tag || !pin) {
    return res.status(400).json({ 
      message: 'encrypted, iv, tag, and pin are required' 
    });
  }

  try {
    const decryptedShard = ShardEncryption.decryptShardA(
      encrypted,
      iv,
      tag,
      pin
    );

    res.status(200).json({ 
      shard: decryptedShard.toString('hex') 
    });
  } catch (error) {
    console.error('Error decrypting shard A:', error);
    res.status(500).json({ message: 'Failed to decrypt shard A' });
  }
};

export const getShardBInternal = async (req: Request, res: Response) => {
  const { shardBId } = req.params;

  try {
    const shardB = await ShardStorage.retrieveShardB(shardBId);

    if (!shardB) {
      return res.status(404).json({ message: 'Shard B not found' });
    }

    res.status(200).json({ 
      shard: shardB.toString('hex') 
    });
  } catch (error) {
    console.error('Error fetching shard B:', error);
    res.status(500).json({ message: 'Failed to fetch shard B' });
  }
};