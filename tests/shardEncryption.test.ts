import { test, describe } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { ShardEncryption } from '../src/crypto/shardEncryption';

describe('ShardEncryption', () => {
  const pin = '482910';
  const shard = crypto.randomBytes(34);

  test('encrypts and decrypts Shard A with valid PIN', () => {
    const encrypted = ShardEncryption.encryptShardA(shard, pin);
    assert.ok(encrypted.encrypted);
    assert.ok(encrypted.iv);
    assert.ok(encrypted.tag);
    assert.ok(encrypted.salt);

    const decrypted = ShardEncryption.decryptShardA(
      encrypted.encrypted,
      encrypted.iv,
      encrypted.tag,
      pin,
      encrypted.salt
    );

    assert.strictEqual(decrypted.toString('hex'), shard.toString('hex'));
  });

  test('fails decryption with invalid PIN', () => {
    const encrypted = ShardEncryption.encryptShardA(shard, pin);

    assert.throws(() => {
      ShardEncryption.decryptShardA(
        encrypted.encrypted,
        encrypted.iv,
        encrypted.tag,
        'wrong-pin',
        encrypted.salt
      );
    });
  });

  test('encrypts and decrypts Shard B with server secret', () => {
    const encryptedB = ShardEncryption.encryptShardB(shard);
    assert.ok(typeof encryptedB === 'string');

    const decryptedB = ShardEncryption.decryptShardB(encryptedB);
    assert.strictEqual(decryptedB.toString('hex'), shard.toString('hex'));
  });
});
