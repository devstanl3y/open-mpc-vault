import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;

export interface EncryptedShard {
  encrypted: string;
  iv: string;
  tag: string;
  salt?: string;
}

export class ShardEncryption {
  static deriveKey(pin: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(
      pin,
      salt,
      PBKDF2_ITERATIONS,
      KEY_LENGTH,
      'sha512'
    );
  }

  /**
   * Encrypts Shard A with a PIN-derived key
   * The salt is returned separately so it can be stored and used for decryption
   */
  static encryptShardA(shard: Buffer, pin: string): EncryptedShard {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = this.deriveKey(pin, salt);
    const iv = crypto.randomBytes(IV_LENGTH);
    
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(shard),
      cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    return {
      encrypted: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      salt: salt.toString('hex')
    };
  }

  /**
   * Decrypts Shard A using the PIN and salt
   * @param encrypted - The encrypted shard data (hex string)
   * @param iv - Initialization vector (hex string)
   * @param tag - Authentication tag (hex string)
   * @param pin - User's PIN
   * @param salt - Optional salt (hex string). If not provided, attempts to extract from encrypted data (legacy support)
   */
  static decryptShardA(
    encrypted: string,
    iv: string,
    tag: string,
    pin: string,
    salt?: string
  ): Buffer {
    const encryptedBuffer = Buffer.from(encrypted, 'hex');
    const ivBuffer = Buffer.from(iv, 'hex');
    const tagBuffer = Buffer.from(tag, 'hex');

    let saltBuffer: Buffer;
    let actualEncryptedData: Buffer;

    if (salt) {
      saltBuffer = Buffer.from(salt, 'hex');
      actualEncryptedData = encryptedBuffer;
    } else {

      console.warn('Legacy decryption format detected - salt embedded in encrypted data');
      
      throw new Error('Legacy format not supported. Salt parameter is required.');
    }

    const key = this.deriveKey(pin, saltBuffer);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, ivBuffer);
    decipher.setAuthTag(tagBuffer);

    const decrypted = Buffer.concat([
      decipher.update(actualEncryptedData),
      decipher.final()
    ]);

    return decrypted;
  }

  static encryptShardB(shard: Buffer): string {
    const serverSecret = process.env.MPC_SERVER_SECRET || crypto.randomBytes(32).toString('hex');
    const key = crypto.scryptSync(serverSecret, 'vera-mpc-salt', 32);
    const iv = crypto.randomBytes(IV_LENGTH);
    
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(shard), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([iv, tag, encrypted]).toString('hex');
  }

  static decryptShardB(encryptedHex: string): Buffer {
    const serverSecret = process.env.MPC_SERVER_SECRET || crypto.randomBytes(32).toString('hex');
    const key = crypto.scryptSync(serverSecret, 'vera-mpc-salt', 32);
    
    const combined = Buffer.from(encryptedHex, 'hex');
    const iv = combined.slice(0, IV_LENGTH);
    const tag = combined.slice(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encrypted = combined.slice(IV_LENGTH + TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }
}