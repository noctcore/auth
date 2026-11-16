import { defineConfig } from 'vitest/config';

// Integration tests against real backends (see docker-compose.yml). They read
// REDIS_URL and DATABASE_URL; CI sets AUTH_REQUIRE_SERVICES=1 so a missing
// backend fails the run instead of skipping it.
export default defineConfig({
  test: {
    include: ['tests/**/*.int.test.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
