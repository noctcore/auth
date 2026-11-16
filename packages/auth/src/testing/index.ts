/**
 * @noctcore/auth/testing: the conformance suite every store adapter must pass,
 * in-memory stores that pass it, and fakes for unit tests.
 */
export {
  counterStoreConformance,
  sessionStoreConformance,
  tokenStoreConformance,
  userStoreConformance,
  type SessionStoreConformanceOptions,
  type UserStoreConformanceOptions,
} from './conformance';
export { runConformance, sleep, uniqueId, type ConformanceCase, type ConformanceContext, type TestApi } from './harness';
export {
  memoryStores,
  MemoryCounterStore,
  MemorySessionStore,
  MemoryTokenStore,
  MemoryUserStore,
  type MemoryStores,
} from './memory';
export {
  manualClock,
  plainHasher,
  recordingAudit,
  recordingMailer,
  type ManualClock,
  type RecordingAudit,
  type RecordingMailer,
} from './fakes';
