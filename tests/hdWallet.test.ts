import { test, describe } from 'node:test';
import assert from 'node:assert';
import { SeedPhraseUtils } from '../src/crypto/seedPhrase';
import { HDWalletDerivation, ChainType } from '../src/crypto/hdWallet';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('HDWalletDerivation', () => {
  const seed = SeedPhraseUtils.mnemonicToSeed(TEST_MNEMONIC);

  test('generates valid 12- and 24-word mnemonics', () => {
    const m12 = SeedPhraseUtils.generate12Word();
    const m24 = SeedPhraseUtils.generate24Word();
    assert.strictEqual(m12.split(' ').length, 12);
    assert.strictEqual(m24.split(' ').length, 24);
    assert.ok(SeedPhraseUtils.validate(m12));
    assert.ok(SeedPhraseUtils.validate(m24));
  });

  test('derives BIP-44 Ethereum addresses matching reference vectors', () => {
    const first = HDWalletDerivation.deriveEthereumWallet(seed, 0, 0);
    const second = HDWalletDerivation.deriveEthereumWallet(seed, 0, 1);
    assert.strictEqual(first.address, '0x9858effd232b4033e47d90003d41ec34ecaeda94');
    assert.strictEqual(second.address, '0x6fac4d18c912343bf86fa7049364dd4e424ab9c0');
    assert.strictEqual(first.derivationPath, "m/44'/60'/0'/0/0");
    assert.strictEqual(first.privateKey.length, 32);
  });

  test('derives BIP-84 Bitcoin address matching reference vector', () => {
    const wallet = HDWalletDerivation.deriveBitcoinWallet(seed, 0, 0);
    assert.strictEqual(wallet.address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
    assert.strictEqual(wallet.derivationPath, "m/84'/0'/0'/0/0");
  });

  test('pins current Solana derivation output', () => {
    // This is NOT SLIP-0010: the key is derived with secp256k1 BIP-32 and
    // reused as an ed25519 seed. Standard wallets (Phantom, Solflare) derive
    // HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk for this mnemonic.
    // Changing this alters every existing Solana address; see REVIEW.md.
    const wallet = HDWalletDerivation.deriveSolanaWallet(seed, 0);
    assert.strictEqual(wallet.address, '4nFZgXtZAEwbfA56LRVRdsDGNeW3U55gr5hL9c5E5de5');
    assert.strictEqual(wallet.derivationPath, "m/44'/501'/0'/0'");
  });

  test('deriveWallet dispatches to the chain-specific derivation', () => {
    for (const chain of Object.values(ChainType)) {
      const viaDispatch = HDWalletDerivation.deriveWallet(seed, chain, 0, 0);
      assert.strictEqual(viaDispatch.chainType, chain);
    }
  });

  test('rejects non-integer and out-of-range indices', () => {
    assert.throws(() => HDWalletDerivation.buildPath(ChainType.ETHEREUM, -1, 0), /account/);
    assert.throws(() => HDWalletDerivation.buildPath(ChainType.ETHEREUM, 0, 1.5), /index/);
    assert.throws(() => HDWalletDerivation.buildPath(ChainType.ETHEREUM, 0, 2 ** 31), /index/);
    assert.throws(
      () => HDWalletDerivation.buildPath(ChainType.ETHEREUM, "0'/1" as unknown as number, 0),
      /account/
    );
  });
});
