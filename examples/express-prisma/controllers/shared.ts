import bcrypt from 'bcrypt';
import { CurveType } from '@prisma/client';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { ChainType, addressesEqual } from 'open-mpc-vault';
import { prisma, PIN_PEPPER_SECRET, type BackupPayloadV4 } from '../host';

export const PIN_PEPPER = PIN_PEPPER_SECRET;

const MAX_HD_INDEX = 0x7fffffff;
const HEX = /^[0-9a-fA-F]*$/;

export function zeroizeBuffers(...buffers: Array<Buffer | undefined>): void {
  for (const buffer of buffers) {
    if (buffer && Buffer.isBuffer(buffer)) buffer.fill(0);
  }
}

export type PinCheck =
  | { ok: true; pinWithPepper: string }
  | { ok: false; status: number; message: string };

/** Verify `pin` against the user's stored bcrypt hash. */
export async function verifyUserPin(userId: number, pin: unknown): Promise<PinCheck> {
  if (typeof pin !== 'string' || pin.length === 0) {
    return { ok: false, status: 400, message: 'PIN is required' };
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { pin_hash: true },
  });
  if (!user?.pin_hash) {
    return { ok: false, status: 401, message: 'User PIN not set' };
  }

  const pinWithPepper = pin + PIN_PEPPER;
  if (!(await bcrypt.compare(pinWithPepper, user.pin_hash))) {
    return { ok: false, status: 401, message: 'Invalid PIN' };
  }
  return { ok: true, pinWithPepper };
}

/** Parse a BIP-32 non-hardened index from untrusted input. */
export function parseHdIndex(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= MAX_HD_INDEX
    ? value
    : null;
}

export function parseChainType(value: unknown): ChainType | null {
  return Object.values(ChainType).includes(value as ChainType) ? (value as ChainType) : null;
}

export function chainLabel(chain: ChainType): string {
  switch (chain) {
    case ChainType.ETHEREUM:
      return 'EVM';
    case ChainType.SOLANA:
      return 'Solana';
    case ChainType.BITCOIN:
      return 'Bitcoin';
    default:
      throw new Error(`Unsupported chain type: ${String(chain)}`);
  }
}

/** Decode a hex string with an optional 0x prefix. Returns null if malformed. */
export function decodeHex(value: unknown): Buffer | null {
  if (typeof value !== 'string') return null;
  const hex = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (hex.length === 0 || hex.length % 2 !== 0 || !HEX.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}

export interface DigestSignature {
  /** secp256k1: 0x-prefixed 64-byte compact r||s. ed25519: 64-byte hex. */
  signature: string;
  /** secp256k1 recovery id (0 or 1); required to build Ethereum `v`. */
  recovery?: number;
}

/**
 * Sign `message` with `privateKey`. For secp256k1, `message` must be a
 * 32-byte digest. For ed25519 it is the raw message bytes.
 */
export function signMessage(
  curve: CurveType,
  message: Buffer,
  privateKey: Buffer
): DigestSignature {
  if (curve === CurveType.SECP256K1) {
    if (message.length !== 32) {
      throw new RangeError('secp256k1 signing requires a 32-byte digest');
    }
    const sig = secp256k1.sign(message, privateKey);
    return { signature: '0x' + sig.toCompactHex(), recovery: sig.recovery };
  }
  return { signature: Buffer.from(ed25519.sign(message, privateKey)).toString('hex') };
}

type RecoveryIdentityWallet = {
  id: string;
  userId: number;
  publicAddress: string;
  chainType: ChainType | null;
  curveType: CurveType;
  derivationPath: string | null;
  accountIndex: number;
  addressIndex: number;
  shardBId: string;
};

export function getRecoveryIdentityMismatch(
  existingWallet: RecoveryIdentityWallet,
  backupData: BackupPayloadV4,
  userId: number
): string | null {
  if (existingWallet.userId !== userId) return 'wallet ownership mismatch';
  if (!addressesEqual(existingWallet.publicAddress, backupData.publicAddress)) {
    return 'publicAddress mismatch';
  }
  if (existingWallet.chainType !== backupData.chainType) return 'chainType mismatch';
  if (existingWallet.curveType !== backupData.curveType) return 'curveType mismatch';
  if ((existingWallet.derivationPath || '') !== backupData.derivationPath) {
    return 'derivationPath mismatch';
  }
  if (existingWallet.accountIndex !== backupData.accountIndex) return 'accountIndex mismatch';
  if (existingWallet.addressIndex !== backupData.addressIndex) return 'addressIndex mismatch';
  if (existingWallet.shardBId !== backupData.shardBId) return 'shardBId mismatch';
  return null;
}

export function getCloudRecoveryErrorStatus(message: string): number {
  if (/not found|no cloud backup/i.test(message)) return 404;
  if (/integrity|checksum|metadata|unsupported|invalid|mismatch|ownership|backup/i.test(message)) {
    return 400;
  }
  return 500;
}
