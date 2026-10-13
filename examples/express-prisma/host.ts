/**
 * Host-application dependencies used by this example.
 *
 * These modules are NOT part of open-mpc-vault. `@app/*` is a placeholder
 * alias for the host application (map it via tsconfig `paths`, or replace
 * the specifiers directly). The expected contracts are listed in
 * examples/README.md.
 */
export { default as prisma } from '@app/utils/prisma';
export { logger } from '@app/utils/logger';
export type { IUserRequest } from '@app/middleware/requireAuth';
export { requireAuth } from '@app/middleware/requireAuth';
export {
  checkBanStatus,
  checkUserBanStatus,
  strictLimiter,
} from '@app/middleware/rateLimiter';
export { cloudBackupService, type BackupPayloadV4 } from '@app/utils/cloudBackup';
export { SessionKeyManager } from '@app/utils/sessionKey';
export { getSessionShardFromRequestBody } from '@app/utils/sessionShard';
export { logSecurityEvent } from '@app/utils/securityLogger';
export { getRequestContext } from '@app/utils/context';
export { PolicyService } from '@app/utils/policyService';
export { getKillSwitchMatch } from '@app/modules/admin/kill-switches/adminKillSwitches.service';
export { PIN_PEPPER_SECRET } from '@app/config/env';
