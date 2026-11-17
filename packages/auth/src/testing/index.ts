/**
 * @noctcore/auth/testing: the conformance suite every store adapter must pass,
 * in-memory stores that pass it, and fakes for unit tests.
 */
export { counterStoreConformance } from './conformance/counter-store';
export { membershipStoreConformance } from './conformance/membership-store';
export {
  sessionStoreConformance,
  type SessionStoreConformanceOptions,
} from './conformance/session-store';
export { tokenStoreConformance } from './conformance/token-store';
export { twoFactorStoreConformance } from './conformance/two-factor-store';
export { userStoreConformance, type UserStoreConformanceOptions } from './conformance/user-store';
export {
  runConformance,
  sleep,
  uniqueId,
  type ConformanceCase,
  type ConformanceContext,
  type TestApi,
} from './harness';
export { MemoryCounterStore } from './memory/counter-store';
export { MemoryMembershipStore } from './memory/membership-store';
export { memoryStores, type MemoryStores } from './memory/memory-stores';
export { MemorySessionStore } from './memory/session-store';
export { MemoryTokenStore } from './memory/token-store';
export { MemoryTwoFactorStore } from './memory/two-factor-store';
export { MemoryUserStore } from './memory/user-store';
export {
  manualClock,
  plainHasher,
  recordingAudit,
  recordingMailer,
  type ManualClock,
  type RecordingAudit,
  type RecordingMailer,
} from './fakes';
