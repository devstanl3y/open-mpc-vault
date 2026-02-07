import { redisPublisher } from '../redis';
import { ShardEncryption } from './shardEncryption';
import prisma from '../prisma';
import crypto from 'crypto';

const REDIS_PREFIX = 'mpc:shard_b:';
const REDIS_TTL = 24 * 60 * 60;

export class ShardStorage {
  static async storeShardB(shard: Buffer, userId: number): Promise<string> {
    const shardId = crypto.randomUUID();
    const encrypted = ShardEncryption.encryptShardB(shard);
    
    await prisma.mpcShardB.create({
      data: {
        id: shardId,
        encryptedShard: encrypted,
        userId
      }
    });
    
    await redisPublisher.set(`${REDIS_PREFIX}${shardId}`, encrypted, {
      EX: REDIS_TTL
    });

    return shardId;
  }

  static async retrieveShardB(shardId: string): Promise<Buffer | undefined> {
    const redisKey = `${REDIS_PREFIX}${shardId}`;
    let encrypted = await redisPublisher.get(redisKey);
    
    if (!encrypted) {
      const record = await prisma.mpcShardB.findUnique({
        where: { id: shardId }
      });
      
      if (!record) {
        return undefined;
      }
      
      encrypted = record.encryptedShard;
      
      await redisPublisher.set(redisKey, encrypted, {
        EX: REDIS_TTL
      });
    }

    return ShardEncryption.decryptShardB(encrypted);
  }

  static async deleteShardB(shardId: string): Promise<void> {
    await prisma.mpcShardB.delete({
      where: { id: shardId }
    }).catch(() => {});
    
    await redisPublisher.del(`${REDIS_PREFIX}${shardId}`);
  }

  static async rotateShardB(
    oldShardId: string,
    newShard: Buffer,
    userId: number
  ): Promise<string> {
    await this.deleteShardB(oldShardId);
    return this.storeShardB(newShard, userId);
  }
}