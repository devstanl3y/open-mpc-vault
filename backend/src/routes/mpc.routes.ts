import { Router } from 'express';
import { requireAuth } from '../middleware/requireAuth';
import { enforcePolicy } from '../middleware/enforcePolicy';
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

router.post('/create', requireAuth, createMpcWallet);
router.post('/import', requireAuth, importMpcWallet);
router.post('/import/verify', requireAuth, verifyImportAddress);
router.post('/derive', requireAuth, deriveAdditionalWallet);
router.get('/wallets', requireAuth, getMpcWallets);
router.post('/sign', requireAuth, enforcePolicy, signWithMpcWallet);
router.post('/sign/session', requireAuth, enforcePolicy, signWithSession);
router.delete('/wallets/:walletId', requireAuth, deleteMpcWallet);

router.post('/recovery/single', requireAuth, recoverFromCloud);
router.post('/recovery/all', requireAuth, recoverAllWalletsFromCloud);
router.get('/recovery/vaults', requireAuth, listRecoverableVaults);

export default router;