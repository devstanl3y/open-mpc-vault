import { test, describe } from 'node:test';
import assert from 'node:assert';
import { MpcKeyGenerator } from '../src/crypto/keyGenerator';
import { ShardEncryption } from '../src/crypto/shardEncryption';
import {
  ShardStorage,
  InMemoryShardStorageAdapter,
  type ShardStorageAdapter,
} from '../src/crypto/shardStorage';
import { deriveWalletFromShards } from '../src/crypto/walletDerivation';
import { ChainType } from '../src/types';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('vault lifecycle', () => {
  const pin = '918273';

  test('create, encrypt, store, retrieve, and derive', async () => {
    ShardStorage.setAdapter(new InMemoryShardStorageAdapter());

    const seed = MpcKeyGenerator.createMpcSeed(12);
    assert.strictEqual(seed.shardA.length, 34);
    assert.strictEqual(seed.shardB.length, 34);

    const encryptedA = ShardEncryption.encryptShardA(seed.shardA, pin);
    const shardBId = await ShardStorage.storeShardB(seed.shardB);

    const shardA = ShardEncryption.decryptShardA(
      encryptedA.encrypted,
      encryptedA.iv,
      encryptedA.tag,
      pin,
      encryptedA.salt
    );
    const shardB = await ShardStorage.retrieveShardB(shardBId);
    assert.ok(shardB);

    assert.deepStrictEqual(MpcKeyGenerator.reconstructEntropy(shardA, shardB), seed.entropy);

    const wallet = deriveWalletFromShards({ shardA, shardB, chainType: ChainType.ETHEREUM });
    assert.strictEqual(wallet.chainType, ChainType.ETHEREUM);
    assert.match(wallet.address, /^0x[0-9a-f]{40}$/);
  });

  test('imported mnemonic derives the reference address from shards', () => {
    const { shardA, shardB } = MpcKeyGenerator.importMpcSeed(`  ${TEST_MNEMONIC.toUpperCase()} `);
    const wallet = deriveWalletFromShards({ shardA, shardB, chainType: ChainType.ETHEREUM });
    assert.strictEqual(wallet.address, '0x9858effd232b4033e47d90003d41ec34ecaeda94');
  });

  test('imported private key derives the expected address', () => {
    const key = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
    const { shardA, shardB, entropy } = MpcKeyGenerator.importPrivateKey(key);
    const wallet = deriveWalletFromShards({
      shardA,
      shardB,
      chainType: ChainType.ETHEREUM,
      isSeedPhrase: false,
    });
    assert.strictEqual(wallet.address, '0x2c7536e3605d9c16a7a3d7b1898e529396a65c23');
    assert.strictEqual(wallet.derivationPath, 'imported');
    assert.ok(MpcKeyGenerator.verifyImport(entropy, wallet.address, ChainType.ETHEREUM, false));
  });

  test('rejects malformed private keys', () => {
    assert.throws(() => MpcKeyGenerator.importPrivateKey('0x1234'), /Invalid private key/);
    assert.throws(() => MpcKeyGenerator.importPrivateKey('zz'.repeat(32)), /Invalid private key/);
  });

  test('deriveAddresses returns the first N receive addresses', () => {
    const { entropy } = MpcKeyGenerator.importMpcSeed(TEST_MNEMONIC);
    const addresses = MpcKeyGenerator.deriveAddresses(entropy, ChainType.ETHEREUM, true, 2);
    assert.deepStrictEqual(
      addresses.map((a) => a.address),
      ['0x9858effd232b4033e47d90003d41ec34ecaeda94', '0x6fac4d18c912343bf86fa7049364dd4e424ab9c0']
    );
  });

  test('rotateShardB keeps the old record if writing the new one fails', async () => {
    const inner = new InMemoryShardStorageAdapter();
    ShardStorage.setAdapter(inner);
    const { shardB } = MpcKeyGenerator.createMpcSeed(12);
    const oldId = await ShardStorage.storeShardB(shardB);

    const failingWrites: ShardStorageAdapter = {
      get: (k) => inner.get(k),
      set: async () => {
        throw new Error('write failed');
      },
      del: (k) => inner.del(k),
    };
    ShardStorage.setAdapter(failingWrites);

    await assert.rejects(ShardStorage.rotateShardB(oldId, shardB), /write failed/);
    assert.ok(await ShardStorage.retrieveShardB(oldId));
  });
});
