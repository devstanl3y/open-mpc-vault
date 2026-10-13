import { Router, type RequestHandler } from 'express';
import { requireAuth, checkBanStatus, checkUserBanStatus, strictLimiter } from './host';
import {
  createMpcWallet,
  importMpcWallet,
  verifyImportAddress,
  deriveAdditionalWallet,
  getMpcWallets,
  getUserVaults,
  signWithMpcWallet,
  signWithSession,
  deleteMpcWallet,
  recoverFromCloud,
  recoverAllWalletsFromCloud,
  listRecoverableVaults,
  internal,
} from './controllers';

/** User-facing routes. Mount under e.g. `/api/v1/mpc`. */
export const mpcRouter = Router();

mpcRouter.use(checkBanStatus, requireAuth, checkUserBanStatus);

// Every endpoint that verifies a PIN is rate limited to slow down PIN guessing.
mpcRouter.post('/create', strictLimiter, createMpcWallet);
mpcRouter.post('/import', strictLimiter, importMpcWallet);
mpcRouter.post('/import/verify', strictLimiter, verifyImportAddress);
mpcRouter.post('/derive', strictLimiter, deriveAdditionalWallet);
mpcRouter.get('/wallets', getMpcWallets);
mpcRouter.get('/vaults', getUserVaults);
mpcRouter.post('/sign', strictLimiter, signWithMpcWallet);
mpcRouter.post('/sign/session', strictLimiter, signWithSession);
mpcRouter.delete('/wallets/:walletId', strictLimiter, deleteMpcWallet);

mpcRouter.post('/recovery/single', strictLimiter, recoverFromCloud);
mpcRouter.post('/recovery/all', strictLimiter, recoverAllWalletsFromCloud);
mpcRouter.get('/recovery/vaults', listRecoverableVaults);

/**
 * Service-to-service routes used by the Rust loader. Several return plaintext
 * key material. `serviceAuth` must authenticate the calling service (mTLS or
 * a signed service token). Never mount this on a public listener.
 */
export function createInternalRouter(serviceAuth: RequestHandler): Router {
  const router = Router();
  router.use(serviceAuth);

  router.get('/health', internal.healthCheckInternal);
  router.get('/mpc-wallet/:walletId', internal.getMpcWalletInternal);
  router.get('/mpc-wallet/:walletId/shard-data', internal.getWalletShardDataInternal);
  router.post('/decrypt-shard-a', internal.decryptShardAInternal);
  router.post('/encrypt-shard-a', internal.encryptShardAInternal);
  router.get('/shard-b/:shardBId', internal.getShardBInternal);
  router.post('/reconstruct', internal.reconstructKeyInternal);
  router.post('/derive-address', internal.deriveAddressInternal);
  router.post('/validate-shard', internal.validateShardInternal);
  return router;
}
