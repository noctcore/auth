# @noctcore/auth

Authentication for TypeScript servers in the spirit of Lucia: small modules you can read in an
afternoon, each one tied to the attack it stops.

- **Core** (`@noctcore/auth`): pure TypeScript, no framework and no I/O of its own. Sessions with
  idle and absolute expiry, Argon2id password hashing with rehash on login, hashed single-use
  tokens, throttling without permanent lockout, CSRF and captcha helpers, and flows (register,
  login, email verification, password reset, password change, session management) that return
  results instead of throwing HTTP errors.
- **Stores**: `@noctcore/auth-redis` (sessions, counters) and `@noctcore/auth-prisma` (users,
  one-time tokens). Any store that passes the conformance suite in `@noctcore/auth/testing` works.

The app keeps its own routes. The package ships the logic, the stores and the checks; plugins add
flows (functions), never endpoints.

## Status

Pre-release. Nothing is published to npm yet, and the API will change until 1.0.

## Development

```sh
bun install
bun run build
bun run format:check && bun run lint && bun run typecheck
bun run test                 # unit tests on in-memory fakes
bun run services:up          # Redis and Postgres in Docker
bun run test:integration     # conformance on the real backends (reads .env.example values)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the release process and [SECURITY.md](SECURITY.md) for
how to report a vulnerability.

## License

MIT
