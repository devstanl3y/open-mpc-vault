import { test, describe } from 'node:test';
import assert from 'node:assert';
import { SeedPhraseUtils } from '../src/crypto/seedPhrase';
import { HDWalletDerivation, ChainType } from '../src/crypto/hdWallet';

describe('HDWalletDerivation', () => {
  const mnemonic = SeedPhraseUtils.generate12Word();
  const seed = SeedPhraseUtils.mnemonicToSeed(mnemonic);

  test('validates and generates 12-word seed phrase', () => {
    assert.strictEqual(mnemonic.split(' ').length, 12);
    assert.strictEqual(SeedPhraseUtils.validate(mnemonic), true);
  });

  test('derives Ethereum address with 0x prefix and 42 characters', () => {
    const ethWallet = HDWalletDerivation.deriveEthereumWallet(seed, 0, 0);
    assert.strictEqual(ethWallet.chainType, ChainType.ETHEREUM);
    assert.ok(ethWallet.address.startsWith('0x'));
    assert.strictEqual(ethWallet.address.length, 42);
    assert.strictEqual(ethWallet.privateKey.length, 32);
  });

  test('derives Solana base58 address', () => {
    const solWallet = HDWalletDerivation.deriveSolanaWallet(seed, 0);
    assert.strictEqual(solWallet.chainType, ChainType.SOLANA);
    assert.ok(solWallet.address.length >= 32);
    assert.strictEqual(solWallet.privateKey.length, 32);
  });

  test('derives Bitcoin SegWit bc1 address', () => {
    const btcWallet = HDWalletDerivation.deriveBitcoinWallet(seed, 0, 0);
    assert.strictEqual(btcWallet.chainType, ChainType.BITCOIN);
    assert.ok(btcWallet.address.startsWith('bc1'));
    assert.strictEqual(btcWallet.privateKey.length, 32);
  });
});
