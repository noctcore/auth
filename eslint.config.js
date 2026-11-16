// Lints the package sources, their tests and the repo scripts with
// typescript-eslint's recommended rules plus a few house rules that matter for
// auth code: no console output from library code, no non-null assertions on
// values that came from a store.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/generated/**', 'site/**', '**/*.d.ts'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      eqeqeq: ['error', 'always'],
    },
  },
  {
    // Library code never writes to the console: logging goes through the
    // injected Logger so the app decides where it lands and what is redacted.
    files: ['packages/*/src/**/*.ts'],
    rules: { 'no-console': 'error' },
  },
);
