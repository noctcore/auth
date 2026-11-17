// Mutation testing for the modules that decide who is signed in.
//
// Stryker changes one operator, condition or literal at a time and reruns the
// tests that cover it; a mutant the suite does not notice "survives". Run with
// `bun run test:mutation` (about two minutes); CI runs it weekly and on demand.
//
// Scope: crypto, tokens, session, throttle, the two-factor plugin and the email
// change flow, plus the CSRF and client IP checks the attack suite leans on. The rest of http (cookie, turnstile) and
// password are measured from time to time but not gated yet.
//
// `break` sits just under the measured score, so a change that lets mutants
// survive fails the run. Raise it when tests improve; never lower it without
// saying why in the pull request.
//
// Accepted survivors (equivalent mutants: no test can tell them apart):
// - crypto/random.ts: the `u` flag on TOKEN_PATTERN. The pattern is ASCII only.
// - throttle/device-token.ts: the `= ''` defaults when destructuring the match
//   (no coverage). Every group always matches; noUncheckedIndexedAccess needs them.
// - throttle/throttle.ts: `lock.count > 0`. A lock counter only exists after an
//   increment (count >= 1) and is deleted to unlock, so `lock !== null` decides.
// - tokens/one-time-tokens.ts: the '000000' stand-in code. It only keeps the
//   HMAC work the same for malformed input; the result is decided afterwards.
// - tokens/one-time-tokens.ts, `extendLink`: the `isTokenShape` guard (a value
//   of another shape hashes to a row that does not exist, so nothing changes)
//   and `>=` vs `>` on the expiry (moving a link to the expiry it already has
//   writes the same row).
// - http/csrf.ts:
//   - the regex `/[a-z]+/` vs `/[a-z]/` (same result);
//   - `toLowerCase()` turned into `toUpperCase()` on the origin: both sides go
//     through the same fold, so either direction matches the same pairs.
//     The fold itself is needed (a custom scheme keeps its host's case:
//     `new URL('app://APP').host` is 'APP'), and a test pins that;
//   - the `!origin || origin === 'null'` guard (an absent or 'null' origin
//     fails URL parsing anyway);
//   - the empty-secrets guard (no secret, no match);
//   - the cookie and header presence checks (secretsEqual refuses a missing one);
//   - the `dot <= 0` boundary (an empty or missing nonce fails NONCE).
// - http/ip.ts:
//   - the empty-chain guard (indexing an empty chain gives undefined too);
//   - `groups.length < 3` vs `<= 3` (the extra group is sliced off);
//   - the `?? ''` after split (split always returns one element).
// - plugins/two-factor:
//   - options.ts: `never` returning undefined instead of false (both falsy);
//   - proofs.ts: the 'totp' kind from `parseProof` turned into '' (anything
//     that is not 'recovery-code' is checked as a TOTP code);
//   - proofs.ts: `owner !== null` in the recovery-code subject turned true
//     (without a factor the delete runs under a null id, which finds nothing,
//     as NO_SUCH_USER_ID does) and `code !== null` turned true (the HMAC of an
//     empty code is never stored).
/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  testRunner: 'vitest',
  // Named explicitly: bun's isolated installs hide the runner from Stryker's plugin discovery.
  plugins: ['@stryker-mutator/vitest-runner'],
  vitest: { configFile: 'vitest.config.ts' },
  coverageAnalysis: 'perTest',
  mutate: [
    'src/crypto/**/*.ts',
    'src/tokens/**/*.ts',
    'src/session/**/*.ts',
    'src/throttle/**/*.ts',
    'src/plugins/**/*.ts',
    'src/http/csrf.ts',
    'src/http/ip.ts',
    'src/flows/email-change.ts',
  ],
  reporters: ['clear-text', 'progress', 'html', 'json'],
  htmlReporter: { fileName: 'reports/mutation/index.html' },
  jsonReporter: { fileName: 'reports/mutation/mutation.json' },
  // Measured 98.52 on 2026-11-17, with the two-factor plugin and the email change flow in scope.
  thresholds: { high: 98, low: 90, break: 98 },
  concurrency: 4,
  timeoutMS: 10_000,
  tempDirName: '.stryker-tmp',
  cleanTempDir: 'always',
};
