import crypto from 'crypto';

/**
 * Shamir secret sharing over the secp256k1 base field
 * (p = 2^256 - 2^32 - 977).
 *
 * Share encoding (current, 34 bytes):
 *   [0]     x-coordinate (1..255)
 *   [1]     original secret length in bytes (1..32)
 *   [2..34) y-coordinate, big-endian, zero-padded to 32 bytes
 *
 * Legacy encoding (33 bytes) omits the length byte and always reconstructs a
 * 32-byte secret. It is accepted for reconstruction only.
 */
export class ShamirSecretSharing {
  private static readonly PRIME =
    BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
  private static readonly MAX_SECRET_BYTES = 32;
  private static readonly LEGACY_SHARE_BYTES = 1 + 32;
  private static readonly SHARE_BYTES = 1 + 1 + 32;
  private static readonly MAX_SHARES = 255;

  private static mod(a: bigint): bigint {
    const r = a % this.PRIME;
    return r >= 0n ? r : r + this.PRIME;
  }

  private static modPow(base: bigint, exponent: bigint): bigint {
    let result = 1n;
    base = this.mod(base);
    while (exponent > 0n) {
      if (exponent & 1n) result = (result * base) % this.PRIME;
      exponent >>= 1n;
      base = (base * base) % this.PRIME;
    }
    return result;
  }

  /** Inverse via Fermat's little theorem; PRIME is prime. */
  private static modInverse(a: bigint): bigint {
    const reduced = this.mod(a);
    if (reduced === 0n) throw new Error('Modular inverse of zero');
    return this.modPow(reduced, this.PRIME - 2n);
  }

  private static randomFieldElement(): bigint {
    // Rejection sampling avoids modulo bias.
    for (;;) {
      const candidate = BigInt('0x' + crypto.randomBytes(32).toString('hex'));
      if (candidate < this.PRIME) return candidate;
    }
  }

  private static toFixedBytes(value: bigint): Buffer {
    return Buffer.from(value.toString(16).padStart(this.MAX_SECRET_BYTES * 2, '0'), 'hex');
  }

  /**
   * Split `secret` into `shareCount` shares, any `threshold` of which
   * reconstruct it.
   */
  static splitSecret(secret: Buffer, threshold = 2, shareCount = 2): Buffer[] {
    if (secret.length < 1 || secret.length > this.MAX_SECRET_BYTES) {
      throw new Error(`Secret length must be between 1 and ${this.MAX_SECRET_BYTES} bytes`);
    }
    if (!Number.isInteger(threshold) || threshold < 2) {
      throw new Error('Threshold must be an integer >= 2');
    }
    if (!Number.isInteger(shareCount) || shareCount < threshold || shareCount > this.MAX_SHARES) {
      throw new Error(`Share count must be an integer between threshold and ${this.MAX_SHARES}`);
    }

    const secretNum = BigInt('0x' + secret.toString('hex'));
    if (secretNum >= this.PRIME) throw new Error('Secret exceeds field size');

    const coefficients = [secretNum];
    for (let i = 1; i < threshold; i++) {
      coefficients.push(this.randomFieldElement());
    }

    const shares: Buffer[] = [];
    for (let x = 1; x <= shareCount; x++) {
      const xBig = BigInt(x);
      let y = 0n;
      let xPow = 1n;
      for (const coef of coefficients) {
        y = (y + coef * xPow) % this.PRIME;
        xPow = (xPow * xBig) % this.PRIME;
      }
      shares.push(Buffer.concat([Buffer.from([x, secret.length]), this.toFixedBytes(y)]));
    }

    return shares;
  }

  /**
   * Reconstruct the secret from at least `threshold` shares. The threshold is
   * not encoded in the share, so supplying too few shares yields an incorrect
   * value rather than an error.
   */
  static reconstructSecret(shares: Buffer[]): Buffer {
    if (shares.length < 2) throw new Error('At least 2 shares required');

    const isCurrentFormat = shares.every((s) => s.length === this.SHARE_BYTES);
    const isLegacyFormat = shares.every((s) => s.length === this.LEGACY_SHARE_BYTES);
    if (!isCurrentFormat && !isLegacyFormat) {
      throw new Error('Invalid share format');
    }

    const secretLength = isCurrentFormat ? shares[0][1] : this.MAX_SECRET_BYTES;
    if (secretLength < 1 || secretLength > this.MAX_SECRET_BYTES) {
      throw new Error('Invalid secret length in share');
    }
    if (isCurrentFormat && !shares.every((s) => s[1] === secretLength)) {
      throw new Error('Inconsistent secret lengths across shares');
    }

    const yOffset = isCurrentFormat ? 2 : 1;
    const points = shares.map((share) => ({
      x: BigInt(share[0]),
      y: BigInt('0x' + share.subarray(yOffset).toString('hex')),
    }));

    const seen = new Set<bigint>();
    for (const { x } of points) {
      if (x === 0n) throw new Error('Invalid share: x-coordinate must be non-zero');
      if (seen.has(x)) throw new Error('Duplicate share x-coordinate');
      seen.add(x);
    }

    // Lagrange interpolation evaluated at x = 0.
    let secret = 0n;
    for (let i = 0; i < points.length; i++) {
      let numerator = 1n;
      let denominator = 1n;
      for (let j = 0; j < points.length; j++) {
        if (i === j) continue;
        numerator = this.mod(numerator * -points[j].x);
        denominator = this.mod(denominator * (points[i].x - points[j].x));
      }
      const basis = (numerator * this.modInverse(denominator)) % this.PRIME;
      secret = (secret + points[i].y * basis) % this.PRIME;
    }

    const full = this.toFixedBytes(secret);
    return Buffer.from(full.subarray(this.MAX_SECRET_BYTES - secretLength));
  }
}
