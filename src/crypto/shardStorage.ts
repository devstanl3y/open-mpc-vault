import crypto from 'crypto';
import { ShardEncryption } from './shardEncryption';

/**
 * Persistence backend for encrypted Shard B records. Values are opaque
 * ciphertext strings. `ttlSeconds` is optional; when omitted, the record must
 * not expire.
 */
export interface ShardStorageAdapter {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
}

/** Process-local adapter for tests and local development. Ignores TTL. */
export class InMemoryShardStorageAdapter implements ShardStorageAdapter {
  private readonly store = new Map<string, string>();

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

  static setAdapter(adapter: ShardStorageAdapter): void {
    this.adapter = adapter;
  }

  private static keyFor(shardId: string): string {
    return `${this.KEY_PREFIX}${shardId}`;
  }

  /**
   * Encrypt and persist Shard B. Returns the generated shard ID.
   *
   * Records are stored without a TTL: losing Shard B makes the vault
   * unrecoverable.
   *
   * `_userId` is accepted for API compatibility but not persisted.
   * Ownership must be enforced by the caller (see {@link retrieveShardBForUser}).
   */
  static async storeShardB(shard: Buffer, _userId?: string | number): Promise<string> {
    const shardId = crypto.randomUUID();
    await this.adapter.set(this.keyFor(shardId), ShardEncryption.encryptShardB(shard));
    return shardId;
  }

  static async retrieveShardB(shardId: string): Promise<Buffer | undefined> {
    const encrypted = await this.adapter.get(this.keyFor(shardId));
    return encrypted ? ShardEncryption.decryptShardB(encrypted) : undefined;
  }

  /**
   * Same as {@link retrieveShardB}. Ownership is NOT verified here because
   * the storage record does not carry a user ID; callers must check that
   * `shardId` belongs to `_userId` before calling.
   */
  static async retrieveShardBForUser(
    shardId: string,
    _userId: string | number
  ): Promise<Buffer | undefined> {
    return this.retrieveShardB(shardId);
  }

  static async deleteShardB(shardId: string): Promise<void> {
    await this.adapter.del(this.keyFor(shardId));
  }

  /**
   * Replace a Shard B record. The new record is written before the old one is
   * deleted so a failed write cannot leave the vault without a server shard.
   */
  static async rotateShardB(
    oldShardId: string,
    newShard: Buffer,
    userId?: string | number
  ): Promise<string> {
    const newShardId = await this.storeShardB(newShard, userId);
    await this.deleteShardB(oldShardId);
    return newShardId;
  }
}
