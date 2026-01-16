import * as bip39 from 'bip39';
import * as crypto from 'crypto';

export class SeedPhraseUtils {
  static generate12Word(): string {
    const entropy = crypto.randomBytes(16);
    return bip39.entropyToMnemonic(entropy.toString('hex'));
  }

  static generate24Word(): string {
    const entropy = crypto.randomBytes(32);
    return bip39.entropyToMnemonic(entropy.toString('hex'));
  }

  static validate(mnemonic: string): boolean {
    return bip39.validateMnemonic(mnemonic);
  }

  static mnemonicToEntropy(mnemonic: string): Buffer {
    const entropyHex = bip39.mnemonicToEntropy(mnemonic);
    return Buffer.from(entropyHex, 'hex');
  }

  static entropyToMnemonic(entropy: Buffer): string {
    return bip39.entropyToMnemonic(entropy.toString('hex'));
  }

  static mnemonicToSeed(mnemonic: string, passphrase: string = ''): Buffer {
    return Buffer.from(bip39.mnemonicToSeedSync(mnemonic, passphrase));
  }
}