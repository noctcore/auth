# Contributing

## Before you start

- Open an issue with one of the forms first for anything larger than a small fix, so we agree on
  the shape before you write code. A stricter default or a missing check goes in the "Security
  hardening idea" form.
- A vulnerability never goes in a public issue: see [SECURITY.md](SECURITY.md).
- Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Layout

```
packages/auth          core: primitives, flows, plugin seams, /argon2 and /testing subpaths
packages/auth-redis    SessionStore and CounterStore on ioredis
packages/auth-prisma   UserStore and TokenStore on Prisma, plus prisma/auth.prisma
```

`packages/auth/src` is split into folders that form layers. A folder may import only from the
folders listed before it, and lint enforces it (`LAYERS` in `eslint.config.js`):

```
shared/      email, durations, results and errors, request meta
crypto/      randomness, hashing, the server secret and its derived keys
ports/       the contracts the app implements: stores, mail, audit, logging, clock, captcha
http/        cookies, CSRF, client IP, the Turnstile client
password/    policy, breach check, hasher contract, Argon2id, timing-safe verify
session/     SessionManager and its options     (session, tokens and throttle never
tokens/      one-time codes and links            import one another)
throttle/    rate limits, lockout, device tokens
core/        AuthCore, config, hooks, plugins, the plugin context
flows/       register, login, verification, reset, password change, session management
testing/     the /testing subpath: in-memory stores, fakes, conformance suites
create-auth.ts and index.ts   the composition root and the public barrel
```

## Checks

```sh
bun run build && bun run format:check && bun run typecheck && bun run lint && bun run test
bun run check:package && bun run check:api
bun run services:up && bun run test:integration
```

`test:integration` reads `REDIS_URL` and `DATABASE_URL` (values in `.env.example`, matching
`docker-compose.yml`). Without them the integration suites skip locally; CI sets
`AUTH_REQUIRE_SERVICES=1` so they can never skip there.

- `bun run format` rewrites every file with Prettier; `format:check` only reports.
- `bun run lint` uses type information, so run it after `bun run build` (the adapters read the
  core package's emitted declarations) and `bun run typecheck` (which generates the Prisma
  clients), and never with `--cache`: the cache does not notice when an
  imported function's type changes. `bunx eslint . --fix` applies the blank-line rules.
- `bun run check:api` compares each entry point's public API (runtime export names and the
  emitted declarations) with the reports in `api/`. When a change to the API is intended, run
  `bun run api:update` after the build and commit the new reports with the change.

## Conventions

- Commits are `type(scope): lowercase summary`, one logical change each.
- Every source module starts with a comment that says which attack or mistake it exists for.
- Flows return `AuthResult` values; they never throw for a user error and never touch HTTP.
- A refusal's public `code` never reveals account state. The internal `reason` is for audit rows only.
- No em or en dashes in code, comments or docs.
- One blank line between logical steps: lint asks for one before a `return`, after a run of
  declarations, and around blocks and multi-line statements. A run of one-line guards stays
  together.
- A lint exception goes in a scoped `files` override in `eslint.config.js` with the reason, never
  in an inline disable comment.

## Attack tests

`packages/auth/tests/attacks/` holds one numbered file per attack the library defends against
(`A001-...test.ts`), indexed in [ATTACKS.md](packages/auth/tests/attacks/ATTACKS.md).

- Attack tests are never deleted, and a number is never reused. An attack that stops applying keeps
  its file, with a comment saying why.
- Every security fix adds an attack test that fails before the fix: a new numbered file, or a test
  in the file of the attack it closes. Add the row to ATTACKS.md in the same commit.
- Each file starts with a header naming the attack, the module that stops it and its Learn page.
  `tests/attacks/index.test.ts` fails when the files, the index or the numbering disagree.

## Production readiness

The site page [How this library is tested](https://noctcore.github.io/auth/security/testing/)
explains what each gate catches. Run the local command before pushing.

**Required on every pull request.** These jobs are required checks on `main`: a pull request cannot
merge until each one passes, and none is `continue-on-error`.

| Gate | CI job | Locally |
|---|---|---|
| Formatting | `build · lint · typecheck · package shape` | `bun run format:check` |
| Types (strict, `exactOptionalPropertyTypes`, `noPropertyAccessFromIndexSignature`) | `build · lint · typecheck · package shape` | `bun run typecheck` |
| Lint, including layering and the secret-comparison rule | `build · lint · typecheck · package shape` | `bun run lint` (after a build) |
| Public API unchanged | `build · lint · typecheck · package shape` | `bun run check:api` (after a build) |
| Package shape | `build · lint · typecheck · package shape` | `bun run check:package` (after a build) |
| Runtime dependency allowlist | `build · lint · typecheck · package shape` | `bun run check:deps` |
| Actions pinned to SHAs, least-privilege permissions | `build · lint · typecheck · package shape` | `bun run check:workflows` |
| Unit, attack and property tests with coverage thresholds | `test`, `test · windows` | `bun run test` |
| Attack suite index (files, rows and numbering agree) | `test`, `test · windows` | `bun run test` |
| Conformance and end to end on Redis and Postgres | `integration · redis + postgres` | `bun run services:up && bun run test:integration` |
| A changeset on every package change | `changeset status` | `bun run changeset` |
| CodeQL (security-extended) | `codeql · javascript-typescript` | CI only |
| Dependency review (high severity, licence allowlist) | `dependency review` | CI only |

**Scheduled, not required to merge.** These run on a schedule, and each can also be started by hand. A
failure shows as a failed run on `main` to fix, not as a blocked pull request.

| Check | CI job | Locally |
|---|---|---|
| Property tests with a new seed and 20000 cases | `fuzz · property tests (nightly)` | `FC_SEED=<n> FC_NUM_RUNS=20000 bunx vitest run tests/property` in `packages/auth` |
| Mutation score at or above `break` in `packages/auth/stryker.config.mjs` | `mutation · stryker (weekly)` | `bun run test:mutation` |
| OpenSSF Scorecard, target 7.5 | `scorecard` (weekly and on every push to `main`) | the badge in the README |

`bun run bench:timing` measures login, sign-up and reset timing on the wall clock. It is for
reading, not a gate, and no job runs it.

## Changesets

A pull request that changes a published package carries a changeset (`bun run changeset`). Changes
that release nothing opt out with `bun run changeset --empty`.

## Releasing

Releases go out through the `release` workflow. The flow, the owner-only steps and how
prereleases work are in [RELEASING.md](RELEASING.md).
