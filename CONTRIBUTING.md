# Contributing

## Layout

```
packages/auth          core: primitives, flows, plugin seams, /argon2 and /testing subpaths
packages/auth-redis    SessionStore and CounterStore on ioredis
packages/auth-prisma   UserStore and TokenStore on Prisma, plus prisma/auth.prisma
```

## Checks

```sh
bun run build && bun run lint && bun run typecheck && bun run test && bun run check:package
bun run services:up && bun run test:integration
```

`test:integration` reads `REDIS_URL` and `DATABASE_URL` (values in `.env.example`, matching
`docker-compose.yml`). Without them the integration suites skip locally; CI sets
`AUTH_REQUIRE_SERVICES=1` so they can never skip there.

## Conventions

- Commits are `type(scope): lowercase summary`, one logical change each.
- Every source module starts with a comment that says which attack or mistake it exists for.
- Flows return `AuthResult` values; they never throw for a user error and never touch HTTP.
- A refusal's public `code` never reveals account state. The internal `reason` is for audit rows only.
- No em or en dashes in code, comments or docs.

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
