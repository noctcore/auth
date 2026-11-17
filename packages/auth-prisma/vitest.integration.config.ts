import { defineConfig } from 'vitest/config';

// Integration tests against real backends (see docker-compose.yml). They read
// REDIS_URL and DATABASE_URL; CI sets AUTH_REQUIRE_SERVICES=1 so a missing
// backend fails the run instead of skipping it.
//
// The unit tests run here too, so coverage counts the error mapping they pin
// down alongside the conformance suite. Coverage is measured, and its
// thresholds enforced, only when AUTH_REQUIRE_SERVICES=1: without a backend the
// suites skip and the numbers would mean nothing. The thresholds sit at or just
// under today's numbers; raise them with new tests, never lower one without
// saying why in the pull request.
const requireServices = process.env['AUTH_REQUIRE_SERVICES'] === '1';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
    coverage: {
      enabled: requireServices,
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text-summary', 'json-summary'],
      thresholds: { lines: 100, branches: 93, functions: 100, statements: 100 },
    },
  },
});
