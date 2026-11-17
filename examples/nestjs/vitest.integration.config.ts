import { defineConfig } from 'vitest/config';

// The end-to-end test needs Redis and PostgreSQL (docker-compose.yml).
export default defineConfig({
  test: {
    include: ['tests/**/*.int.test.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
