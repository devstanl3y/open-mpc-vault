import * as crypto from 'crypto';
import type { EncryptedShard } from '../types';

export type { EncryptedShard };

const ALGORITHM = 'aes-256-gcm';
// GCM's recommended nonce size is 12 bytes. 16 is kept so existing
// ciphertexts stay decryptable; see the review notes before changing it.
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_DIGEST = 'sha512';

// TODO(security): remove this fallback and fail closed when
// MPC_SERVER_SECRET is unset. Kept for now so existing deployments that
// rely on it can still decrypt; the change needs a migration path.
const INSECURE_DEFAULT_SERVER_SECRET = 'open-mpc-vault-default-secret';
const SERVER_KEY_SALT = 'open-mpc-vault-salt';

let cachedServerKey: { secret: string; key: Buffer } | undefined;

/**
 * Derive the Shard B key from MPC_SERVER_SECRET. The scrypt result is cached
 * per secret value because scryptSync blocks the event loop.
 */
function getServerKey(): Buffer {
  const secret = process.env.MPC_SERVER_SECRET || INSECURE_DEFAULT_SERVER_SECRET;
  if (cachedServerKey?.secret !== secret) {
    cachedServerKey = {
      secret,
      key: crypto.scryptSync(secret, SERVER_KEY_SALT, KEY_LENGTH),
    };
  }
  return cachedServerKey.key;
}

export class ShardEncryption {
  static deriveKey(pin: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(pin, salt, PBKDF2_ITERATIONS, KEY_LENGTH, PBKDF2_DIGEST);
  }

  /** Encrypt the client shard under a PBKDF2 key derived from `pin`. */
  static encryptShardA(shard: Buffer, pin: string): EncryptedShard {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = this.deriveKey(pin, salt);
    const iv = crypto.randomBytes(IV_LENGTH);

    try {
      const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
      const encrypted = Buffer.concat([cipher.update(shard), cipher.final()]);

      return {
        encrypted: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        tag: cipher.getAuthTag().toString('hex'),
        salt: salt.toString('hex'),
      };
    } finally {
      key.fill(0);
    }
  }

  /**
   * Decrypt the client shard. If `salt` is omitted, `encrypted` must use the
   * legacy `<saltHex>:<ciphertextHex>` form.
   */
  static decryptShardA(
    encrypted: string,
    iv: string,
    tag: string,
    pin: string,
    salt?: string
  ): Buffer {
    let saltBuffer: Buffer;
    let ciphertext: Buffer;

    if (salt) {
      saltBuffer = Buffer.from(salt, 'hex');
      ciphertext = Buffer.from(encrypted, 'hex');
    } else if (encrypted.includes(':')) {
      const [saltHex, dataHex] = encrypted.split(':');
      saltBuffer = Buffer.from(saltHex, 'hex');
      ciphertext = Buffer.from(dataHex, 'hex');
    } else {
      throw new Error('Salt is required to decrypt Shard A');
    }

    const tagBuffer = Buffer.from(tag, 'hex');
    if (tagBuffer.length !== TAG_LENGTH) {
      throw new Error('Invalid authentication tag length');
    }

    const key = this.deriveKey(pin, saltBuffer);
    try {
      const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
      decipher.setAuthTag(tagBuffer);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } finally {
      key.fill(0);
    }
  }

  /** Encrypt the server shard. Output is hex of `iv || tag || ciphertext`. */
  static encryptShardB(shard: Buffer): string {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, getServerKey(), iv);
    const encrypted = Buffer.concat([cipher.update(shard), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('hex');
  }

  static decryptShardB(encryptedHex: string): Buffer {
    const combined = Buffer.from(encryptedHex, 'hex');
    if (combined.length <= IV_LENGTH + TAG_LENGTH) {
      throw new Error('Invalid Shard B ciphertext');
    }

    const iv = combined.subarray(0, IV_LENGTH);
    const tag = combined.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const ciphertext = combined.subarray(IV_LENGTH + TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, getServerKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
}
