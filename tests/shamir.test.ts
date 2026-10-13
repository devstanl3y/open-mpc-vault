import { test, describe } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { ShamirSecretSharing } from '../src/crypto/shamir';

describe('ShamirSecretSharing', () => {
  test('splits 32-byte secret into 2 shares and reconstructs exactly', () => {
    const secret = crypto.randomBytes(32);
    // Ensure secret is within prime field
    secret[0] &= 0x7f;

    const shares = ShamirSecretSharing.splitSecret(secret, 2, 2);
    assert.strictEqual(shares.length, 2);

    const reconstructed = ShamirSecretSharing.reconstructSecret(shares);
    assert.strictEqual(reconstructed.toString('hex'), secret.toString('hex'));
  });

  test('splits 16-byte secret (12-word seed entropy) and reconstructs exactly', () => {
    const secret = crypto.randomBytes(16);
    const shares = ShamirSecretSharing.splitSecret(secret, 2, 2);
    assert.strictEqual(shares.length, 2);

    const reconstructed = ShamirSecretSharing.reconstructSecret(shares);
    assert.strictEqual(reconstructed.toString('hex'), secret.toString('hex'));
  });

  test('fails reconstruction with less than 2 shares', () => {
    const secret = crypto.randomBytes(32);
    secret[0] &= 0x7f;
    const shares = ShamirSecretSharing.splitSecret(secret, 2, 2);

    assert.throws(() => {
      ShamirSecretSharing.reconstructSecret([shares[0]]);
    }, /At least 2 shares required/);
  });
});
