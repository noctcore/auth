import { defineConfig } from 'vitest/config';

// The compile test boots the whole AppModule without Redis or Postgres (both
// clients connect lazily), so a missing provider fails here, not at deploy.
export default defineConfig({
  test: { include: ['tests/**/*.test.ts'], exclude: ['tests/**/*.int.test.ts'] },
});
