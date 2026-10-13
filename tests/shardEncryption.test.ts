import { test, describe } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { ShardEncryption } from '../src/crypto/shardEncryption';

describe('ShardEncryption', () => {
  const pin = '482910';
  const shard = crypto.randomBytes(34);

  test('round-trips Shard A with the correct PIN', () => {
    const encrypted = ShardEncryption.encryptShardA(shard, pin);
    assert.ok(encrypted.salt);

    const decrypted = ShardEncryption.decryptShardA(
      encrypted.encrypted,
      encrypted.iv,
      encrypted.tag,
      pin,
      encrypted.salt
    );
    assert.deepStrictEqual(decrypted, shard);
  });

  test('decrypts the legacy salt:ciphertext Shard A format', () => {
    const encrypted = ShardEncryption.encryptShardA(shard, pin);
    const legacy = `${encrypted.salt}:${encrypted.encrypted}`;
    const decrypted = ShardEncryption.decryptShardA(legacy, encrypted.iv, encrypted.tag, pin);
    assert.deepStrictEqual(decrypted, shard);
  });

  test('rejects Shard A with a wrong PIN', () => {
    const e = ShardEncryption.encryptShardA(shard, pin);
    assert.throws(() =>
      ShardEncryption.decryptShardA(e.encrypted, e.iv, e.tag, 'wrong-pin', e.salt)
    );
  });

  test('rejects a truncated authentication tag', () => {
    const e = ShardEncryption.encryptShardA(shard, pin);
    assert.throws(
      () => ShardEncryption.decryptShardA(e.encrypted, e.iv, e.tag.slice(0, 8), pin, e.salt),
      /tag length/
    );
  });

  test('round-trips Shard B and rejects tampered ciphertext', () => {
    const encrypted = ShardEncryption.encryptShardB(shard);
    assert.deepStrictEqual(ShardEncryption.decryptShardB(encrypted), shard);

    const lastByte = parseInt(encrypted.slice(-2), 16) ^ 0x01;
    const tampered = encrypted.slice(0, -2) + lastByte.toString(16).padStart(2, '0');
    assert.throws(() => ShardEncryption.decryptShardB(tampered));
  });
});
