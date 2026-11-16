import { defineConfig } from 'vitest/config';

// Fast unit tests: no network, no real backends.
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['tests/**/*.int.test.ts'],
  },
});
