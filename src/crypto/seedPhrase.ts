import * as bip39 from 'bip39';
import * as crypto from 'crypto';

export class SeedPhraseUtils {
  static generate12Word(): string {
    return bip39.entropyToMnemonic(crypto.randomBytes(16).toString('hex'));
  }

  static generate24Word(): string {
    return bip39.entropyToMnemonic(crypto.randomBytes(32).toString('hex'));
  }

  static validate(mnemonic: string): boolean {
    return bip39.validateMnemonic(mnemonic);
  }

  static mnemonicToEntropy(mnemonic: string): Buffer {
    return Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex');
  }

  static entropyToMnemonic(entropy: Buffer): string {
    return bip39.entropyToMnemonic(entropy.toString('hex'));
  }

  static mnemonicToSeed(mnemonic: string, passphrase = ''): Buffer {
    return Buffer.from(bip39.mnemonicToSeedSync(mnemonic, passphrase));
  }
}