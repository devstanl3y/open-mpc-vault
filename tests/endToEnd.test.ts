import { test, describe } from 'node:test';
import assert from 'node:assert';
import { MpcKeyGenerator } from '../src/crypto/keyGenerator';
import { ShardEncryption } from '../src/crypto/shardEncryption';
import { ShamirSecretSharing } from '../src/crypto/shamir';
import { deriveWalletFromShards } from '../src/crypto/walletDerivation';
import { ChainType, CurveType } from '../src/types';

describe('End-to-End MPC Vault Lifecycle', () => {
  const pin = '918273';

  test('creates MPC seed, encrypts shards, reconstructs, and derives exact address', () => {
    // 1. Create fresh 2-of-2 MPC seed shards
    const seedShards = MpcKeyGenerator.createMpcSeed(12);
    assert.ok(seedShards.mnemonic);
    assert.strictEqual(seedShards.shardA.length, 34);
    assert.strictEqual(seedShards.shardB.length, 34);

    // 2. Client encrypts Shard A with PIN
    const encryptedShardA = ShardEncryption.encryptShardA(seedShards.shardA, pin);

    // 3. Server encrypts Shard B with server secret
    const encryptedShardB = ShardEncryption.encryptShardB(seedShards.shardB);

    // 4. In a signing session, decrypt Shard A (client PIN) and Shard B (server)
    const decryptedShardA = ShardEncryption.decryptShardA(
      encryptedShardA.encrypted,
      encryptedShardA.iv,
      encryptedShardA.tag,
      pin,
      encryptedShardA.salt
    );
    const decryptedShardB = ShardEncryption.decryptShardB(encryptedShardB);

    // 5. Reconstruct entropy
    const reconstructedEntropy = ShamirSecretSharing.reconstructSecret([
      decryptedShardA,
      decryptedShardB,
    ]);
    assert.strictEqual(
      reconstructedEntropy.toString('hex'),
      seedShards.entropy.toString('hex')
    );

    // 6. Derive EVM wallet directly from shards
    const derivedEth = deriveWalletFromShards({
      shardA: decryptedShardA,
      shardB: decryptedShardB,
      chainType: ChainType.ETHEREUM,
      curveType: CurveType.SECP256K1,
      isSeedPhrase: true,
      accountIndex: 0,
      addressIndex: 0,
    });

    assert.ok(derivedEth.address.startsWith('0x'));
    assert.strictEqual(derivedEth.chainType, ChainType.ETHEREUM);
  });
});
