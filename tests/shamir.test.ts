import { test, describe } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { ShamirSecretSharing } from '../src/crypto/shamir';

function fieldSafeSecret(bytes: number): Buffer {
  const secret = crypto.randomBytes(bytes);
  secret[0] &= 0x7f;
  return secret;
}

describe('ShamirSecretSharing', () => {
  test('round-trips a 32-byte secret', () => {
    const secret = fieldSafeSecret(32);
    const shares = ShamirSecretSharing.splitSecret(secret, 2, 2);
    assert.strictEqual(shares.length, 2);
    assert.deepStrictEqual(ShamirSecretSharing.reconstructSecret(shares), secret);
  });

  test('round-trips a 16-byte secret, preserving leading zero bytes', () => {
    const secret = Buffer.concat([Buffer.alloc(2), crypto.randomBytes(14)]);
    const shares = ShamirSecretSharing.splitSecret(secret, 2, 2);
    assert.deepStrictEqual(ShamirSecretSharing.reconstructSecret(shares), secret);
  });

  test('honours shareCount and reconstructs from any threshold subset', () => {
    const secret = fieldSafeSecret(32);
    const shares = ShamirSecretSharing.splitSecret(secret, 3, 5);
    assert.strictEqual(shares.length, 5);
    assert.deepStrictEqual(
      ShamirSecretSharing.reconstructSecret([shares[0], shares[2], shares[4]]),
      secret
    );
    assert.deepStrictEqual(
      ShamirSecretSharing.reconstructSecret([shares[1], shares[3], shares[4]]),
      secret
    );
  });

  test('reconstructs legacy 33-byte shares', () => {
    const secret = fieldSafeSecret(32);
    const legacy = ShamirSecretSharing.splitSecret(secret, 2, 2).map((s) =>
      Buffer.concat([s.subarray(0, 1), s.subarray(2)])
    );
    assert.deepStrictEqual(ShamirSecretSharing.reconstructSecret(legacy), secret);
  });

  test('rejects fewer than 2 shares', () => {
    const shares = ShamirSecretSharing.splitSecret(fieldSafeSecret(32), 2, 2);
    assert.throws(() => ShamirSecretSharing.reconstructSecret([shares[0]]), /At least 2 shares/);
  });

  test('rejects duplicate and zero x-coordinates', () => {
    const [a] = ShamirSecretSharing.splitSecret(fieldSafeSecret(32), 2, 2);
    assert.throws(() => ShamirSecretSharing.reconstructSecret([a, Buffer.from(a)]), /Duplicate/);

    const zeroX = Buffer.from(a);
    zeroX[0] = 0;
    assert.throws(() => ShamirSecretSharing.reconstructSecret([zeroX, a]), /non-zero/);
  });

  test('rejects invalid split parameters', () => {
    const secret = fieldSafeSecret(32);
    assert.throws(() => ShamirSecretSharing.splitSecret(secret, 1, 2), /Threshold/);
    assert.throws(() => ShamirSecretSharing.splitSecret(secret, 3, 2), /Share count/);
    assert.throws(() => ShamirSecretSharing.splitSecret(Buffer.alloc(0), 2, 2), /Secret length/);
    assert.throws(() => ShamirSecretSharing.splitSecret(Buffer.alloc(33), 2, 2), /Secret length/);
  });
});
