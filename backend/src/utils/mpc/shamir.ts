import crypto from 'crypto';

export class ShamirSecretSharing {
  private static readonly PRIME =
    BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');

  private static modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    let result = 1n;
    base = base % modulus;
    while (exponent > 0) {
      if (exponent % 2n === 1n) result = (result * base) % modulus;
      exponent >>= 1n;
      base = (base * base) % modulus;
    }
    return result;
  }

  private static modInverse(a: bigint, m: bigint): bigint {
    const [g, x] = this.extendedGcd(a, m);
    if (g !== 1n) throw new Error('Modular inverse does not exist');
    return (x % m + m) % m;
  }

  private static extendedGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
    if (a === 0n) return [b, 0n, 1n];
    const [g, x1, y1] = this.extendedGcd(b % a, a);
    const x = y1 - (b / a) * x1;
    const y = x1;
    return [g, x, y];
  }

  static splitSecret(secret: Buffer, threshold: number, p0: number): Buffer[] {
    const secretNum = BigInt('0x' + secret.toString('hex'));
    if (secretNum >= this.PRIME) throw new Error('Secret exceeds field size');

    const coefficients = [secretNum];
    for (let i = 1; i < threshold; i++) {
      coefficients.push(
        BigInt('0x' + crypto.randomBytes(32).toString('hex')) % this.PRIME
      );
    }

    const shares: Buffer[] = [];
    for (let x = 1; x <= 2; x++) {
      let y = 0n;
      let xPow = 1n;
      for (const coef of coefficients) {
        y = (y + coef * xPow) % this.PRIME;
        xPow = (xPow * BigInt(x)) % this.PRIME;
      }
      const xByte = Buffer.from([x]);
      const yBuffer = Buffer.from(y.toString(16).padStart(64, '0'), 'hex');
      shares.push(Buffer.concat([xByte, yBuffer]));
    }

    return shares;
  }

  static reconstructSecret(shares: Buffer[]): Buffer {
    if (shares.length < 2) throw new Error('At least 2 shares required');

    const parsed = shares.map((share) => {
      const x = BigInt(share[0]);
      const y = BigInt('0x' + share.slice(1).toString('hex'));
      return { x, y };
    });

    let secret = 0n;

    for (let i = 0; i < parsed.length; i++) {
      const { x: x1, y: y1 } = parsed[i];

      let numerator = 1n;
      let denominator = 1n;

      for (let j = 0; j < parsed.length; j++) {
        if (i === j) continue;
        const { x: x2 } = parsed[j];
        numerator = (numerator * (0n - x2 + this.PRIME)) % this.PRIME;
        denominator = (denominator * (x1 - x2 + this.PRIME)) % this.PRIME;
      }

      const lagrangeCoefficient =
        (numerator * this.modInverse(denominator, this.PRIME)) % this.PRIME;
      secret = (secret + y1 * lagrangeCoefficient) % this.PRIME;
    }

    return Buffer.from(secret.toString(16).padStart(64, '0'), 'hex');
  }
}
