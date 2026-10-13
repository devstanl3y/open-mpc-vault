import crypto from 'crypto';
import { ShardEncryption } from './shardEncryption';

export interface ShardStorageAdapter {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
}

export class InMemoryShardStorageAdapter implements ShardStorageAdapter {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | undefined> {
    return this.store.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
  }
}

export class ShardStorage {
  private static adapter: ShardStorageAdapter = new InMemoryShardStorageAdapter();
  private static readonly KEY_PREFIX = 'mpc:shard_b:';
  private static readonly DEFAULT_TTL = 24 * 60 * 60;

  static setAdapter(adapter: ShardStorageAdapter): void {
    this.adapter = adapter;
  }

  static async storeShardB(shard: Buffer, userId?: string | number): Promise<string> {
    const shardId = crypto.randomUUID();
    const encrypted = ShardEncryption.encryptShardB(shard);
    const key = `${this.KEY_PREFIX}${shardId}`;

    await this.adapter.set(key, encrypted, this.DEFAULT_TTL);
    return shardId;
  }

  static async retrieveShardB(shardId: string): Promise<Buffer | undefined> {
    const key = `${this.KEY_PREFIX}${shardId}`;
    const encrypted = await this.adapter.get(key);
    if (!encrypted) {
      return undefined;
    }

    return ShardEncryption.decryptShardB(encrypted);
  }

  static async retrieveShardBForUser(shardId: string, _userId: string | number): Promise<Buffer | undefined> {
    return this.retrieveShardB(shardId);
  }

  static async deleteShardB(shardId: string): Promise<void> {
    const key = `${this.KEY_PREFIX}${shardId}`;
    await this.adapter.del(key);
  }

  static async rotateShardB(
    oldShardId: string,
    newShard: Buffer,
    userId?: string | number
  ): Promise<string> {
    await this.deleteShardB(oldShardId);
    return this.storeShardB(newShard, userId);
  }
}
