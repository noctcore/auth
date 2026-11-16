// Lints the package sources, their tests, the example app and the repo scripts.
//
// - typescript-eslint's type-checked rules, so a promise nobody awaits (a lost
//   audit write, a session that never got stored) fails lint instead of
//   failing silently in production. Type information comes from each
//   package's tsconfig through `projectService`; never run this with `--cache`,
//   because the cache does not notice when an imported function's type changes.
// - The noctcore plugins that fit a TypeScript library: code quality, async
//   safety, security, observability, contracts, monorepo boundaries, Prisma
//   (the Prisma adapter and the example app only) and the folder layers of the
//   core package.
// - Blank lines between logical steps (`@stylistic/padding-line-between-statements`)
//   so a function reads as a sequence of steps, not a wall of statements.
//   Formatting itself is Prettier's job (`bun run format`).
import js from '@eslint/js';
import architecture from '@noctcore/eslint-plugin-architecture';
import asyncSafety from '@noctcore/eslint-plugin-async-safety';
import codeQuality from '@noctcore/eslint-plugin-code-quality';
import contracts from '@noctcore/eslint-plugin-contracts';
import monorepo from '@noctcore/eslint-plugin-monorepo';
import observability from '@noctcore/eslint-plugin-observability';
import prisma from '@noctcore/eslint-plugin-prisma';
import security from '@noctcore/eslint-plugin-security';
import stylistic from '@stylistic/eslint-plugin';
import tseslint from 'typescript-eslint';

const TS = ['**/*.ts'];
const TESTS = ['**/tests/**/*.ts'];
const SCRIPTS = ['scripts/**/*.ts', '**/*.config.ts', 'examples/**/*.ts'];

// The statement kinds `padding-line-between-statements` treats as one step.
const DECLARATIONS = ['const', 'let', 'var'];
const MULTILINE = [
  'multiline-block-like',
  'multiline-expression',
  'multiline-const',
  'multiline-let',
  'multiline-var',
];

const padding = [
  // A return is the result of the steps above it, so it stands apart.
  { blankLine: 'always', prev: '*', next: 'return' },
  // Declarations are gathered first, then used.
  { blankLine: 'always', prev: DECLARATIONS, next: '*' },
  { blankLine: 'any', prev: DECLARATIONS, next: DECLARATIONS },
  // A guard is set apart from the work around it, but a run of one-line
  // guards (`if (!user) return refuse(...)`) reads as one checklist.
  { blankLine: 'always', prev: '*', next: 'if' },
  { blankLine: 'always', prev: 'if', next: '*' },
  { blankLine: 'any', prev: 'if', next: 'if' },
  // Anything spanning several lines is its own step.
  { blankLine: 'always', prev: '*', next: MULTILINE },
  { blankLine: 'always', prev: MULTILINE, next: '*' },
  { blankLine: 'always', prev: '*', next: ['block-like', 'try', 'for', 'while', 'switch'] },
  { blankLine: 'always', prev: ['block-like', 'try', 'for', 'while', 'switch'], next: '*' },
];

// The core package's folders are layers. Each one names the folders it may
// import from; everything else is banned, so the primitives never grow a
// dependency on the flows that use them, and session, tokens and throttle
// stay independent of one another. `index.ts` and `create-auth.ts` at the top
// are the composition root and may import anything.
const LAYERS = {
  shared: [],
  crypto: ['shared'],
  ports: ['shared', 'crypto'],
  http: ['shared', 'crypto', 'ports'],
  password: ['shared', 'crypto', 'ports'],
  session: ['shared', 'crypto', 'ports'],
  tokens: ['shared', 'crypto', 'ports'],
  throttle: ['shared', 'crypto', 'ports'],
  core: ['shared', 'crypto', 'ports', 'http', 'password', 'session', 'tokens', 'throttle'],
  flows: ['shared', 'crypto', 'ports', 'http', 'password', 'session', 'tokens', 'throttle', 'core'],
  // The test kit builds on the stores and primitives, never on the flows.
  testing: ['shared', 'crypto', 'ports', 'password', 'session'],
};

function layerBoundaries() {
  const folders = [...Object.keys(LAYERS), 'create-auth'];
  const bans = Object.fromEntries(
    folders.map((folder) => [
      folder,
      [{ modules: [`**/${folder}`], message: `Only a higher layer may import from ${folder}.` }],
    ]),
  );
  const layers = Object.entries(LAYERS).map(([folder, allowed]) => ({
    files: [`packages/auth/src/${folder}/**`],
    bans: folders.filter((other) => other !== folder && !allowed.includes(other)),
  }));

  return { bans, layers };
}

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/generated/**', 'site/**', '**/*.d.ts'],
  },
  {
    linterOptions: { reportUnusedDisableDirectives: 'error' },
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked.map((config) => ({ ...config, files: TS })),
  {
    files: TS,
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { '@stylistic': stylistic },
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/return-await': ['error', 'in-try-catch'],
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      eqeqeq: ['error', 'always'],
      '@stylistic/padding-line-between-statements': ['error', ...padding],
    },
  },
  { ...codeQuality.configs.strict, files: TS },
  { ...asyncSafety.configs.recommended, files: TS },
  { ...security.configs.recommended, files: TS },
  { ...observability.configs.recommended, files: TS },
  { ...contracts.configs.recommended, files: TS },
  {
    ...monorepo.configs.recommended,
    files: TS,
    rules: {
      ...monorepo.configs.recommended.rules,
      // A consumer, the example app included, may only import what a
      // package's `exports` map publishes.
      'noctcore-monorepo/no-unexported-subpath-import': ['error', { scopes: ['@noctcore'] }],
    },
  },
  {
    ...prisma.configs.recommended,
    files: ['packages/auth-prisma/**/*.ts', 'examples/**/*.ts'],
  },
  {
    // Library code never writes to the console: logging goes through the
    // injected Logger so the app decides where it lands and what is redacted.
    files: ['packages/*/src/**/*.ts'],
    rules: { 'no-console': 'error' },
  },
  {
    // Scripts, configs and the example app are the processes that own the
    // environment, so they read it directly.
    files: SCRIPTS,
    rules: { 'noctcore-contracts/no-direct-process-env': 'off' },
  },
  {
    // Command-line scripts print for a person reading a terminal, not for a
    // log pipeline, so a sentence with the value in it is the right output.
    files: ['scripts/**/*.ts'],
    rules: { 'noctcore-observability/structured-log-arguments': 'off' },
  },
  {
    // The in-memory stores and fakes implement the Promise-returning store
    // contracts without doing any I/O. They stay `async` so a thrown error
    // reaches the caller as a rejection, exactly like a real adapter.
    files: ['packages/auth/src/testing/**/*.ts', '**/tests/**/*.ts', 'examples/basic/src/main.ts'],
    rules: { '@typescript-eslint/require-await': 'off' },
  },
  {
    files: TESTS,
    rules: {
      // Tests build stores and fakes inline and hand them across as doubles.
      '@typescript-eslint/unbound-method': 'off',
      // Casts in tests pin the exact config and session types a case
      // exercises, even where inference would reach the same type today.
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
    },
  },
  {
    // The background-task failure log names the task in its message so the
    // alerts apps already match on keep working; moving the label into the
    // fields is a log-format change for a release note, not for a refactor.
    files: ['packages/auth/src/core/auth-core.ts'],
    rules: { 'noctcore-observability/structured-log-arguments': 'off' },
  },
  {
    // These cases predate the test-discipline rules and this change keeps
    // test code as it is. Each one guards an assertion behind the result it
    // just checked (or waits a tick for a background send); rewriting them is
    // tracked as its own change.
    files: [
      'packages/auth/tests/flows/email-verification.test.ts',
      'packages/auth/tests/flows/login.test.ts',
      'packages/auth/tests/flows/password-reset.test.ts',
      'packages/auth/tests/flows/plugins.test.ts',
      'packages/auth/tests/flows/register.test.ts',
    ],
    rules: {
      'noctcore-code-quality/no-conditional-expect': 'off',
      'noctcore-code-quality/no-vacuous-expect': 'off',
      'noctcore-async-safety/no-leaky-race-timeout': 'off',
      // A hook argument the plugin helper does not infer yet.
      '@typescript-eslint/no-unsafe-assignment': 'off',
    },
  },
  {
    // Prisma generates a different delegate type per model, so the adapter
    // accepts any delegate with the methods it calls: these shapes are `any`
    // on purpose, and every row read through them is typed where it lands.
    files: ['packages/auth-prisma/src/delegates.ts'],
    rules: { '@typescript-eslint/no-explicit-any': 'off' },
  },
  {
    // Integration suites talk to a real server, Redis and Postgres by design:
    // the example's e2e client calls the app it started on a local port and
    // asserts on every status, error bodies included.
    files: ['**/*.int.test.ts'],
    rules: {
      'noctcore-code-quality/no-real-network-in-unit-tests': 'off',
      'noctcore-security/no-user-controlled-fetch-url': 'off',
      'noctcore-contracts/fetch-must-check-ok': 'off',
    },
  },
  {
    ...architecture.configs.recommended,
    files: ['packages/auth/src/**/*.ts'],
    rules: {
      ...architecture.configs.recommended.rules,
      'noctcore-architecture/no-restricted-imports-layered': ['error', layerBoundaries()],
    },
  },
);
