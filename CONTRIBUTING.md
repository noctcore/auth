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

## Changesets

A pull request that changes a published package carries a changeset (`bun run changeset`). Changes
that release nothing opt out with `bun run changeset --empty`.

## Releasing

The release workflow is a dry run until npm trusted publishing is set up. The owner's steps:

1. Publish each package once by hand so the name exists on npm (`npm publish --access public` from
   `packages/<name>` after `bun run build`), or create it through the npm website.
2. On npmjs.com, for each of `@noctcore/auth`, `@noctcore/auth-redis` and `@noctcore/auth-prisma`
   (and later `@noctcore/auth-nestjs`, `@noctcore/auth-trpc`), add a trusted publisher: GitHub
   Actions, repository `noctcore/auth`, workflow `release.yml`.
3. In `.github/workflows/release.yml`, change `publish-script` to `bunx changeset publish`.
4. Consumers add `@noctcore/*` to their minimum-release-age exclusions so a security release can be
   adopted the same day.
