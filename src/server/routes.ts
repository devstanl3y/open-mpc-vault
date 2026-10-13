import { Router } from 'express';
import { requireAuth } from '../middleware/requireAuth';
import {
  checkBanStatus,
  checkUserBanStatus,
  strictLimiter,
} from '../middleware/rateLimiter';
import {
  createMpcWallet,
  importMpcWallet,
  verifyImportAddress,
  deriveAdditionalWallet,
  getMpcWallets,
  signWithMpcWallet,
  signWithSession,
  deleteMpcWallet,
  recoverFromCloud,
  recoverAllWalletsFromCloud,
  listRecoverableVaults
} from '../controllers/mpc.controller';

const router = Router();

router.use(checkBanStatus, requireAuth, checkUserBanStatus);

router.post('/create', createMpcWallet);
router.post('/import', importMpcWallet);
router.post('/import/verify', verifyImportAddress);
router.post('/derive', deriveAdditionalWallet);
router.get('/wallets', getMpcWallets);
router.post('/sign', strictLimiter, signWithMpcWallet);
router.post('/sign/session', strictLimiter, signWithSession);
router.delete('/wallets/:walletId', deleteMpcWallet);

router.post('/recovery/single', recoverFromCloud);
router.post('/recovery/all', recoverAllWalletsFromCloud);
router.get('/recovery/vaults', listRecoverableVaults);

export default router;
