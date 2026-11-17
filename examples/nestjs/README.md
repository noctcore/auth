# Example: NestJS with Prisma and Redis

The same JSON API as `examples/basic`, on NestJS with `@noctcore/auth-nestjs`: register, sign in, read the account, list sessions, re-authenticate, change the password behind a fresh proof, an admin route, sign out. Every route needs a session unless it says `@Public()`.

```sh
bun run services:up                      # Redis and PostgreSQL from docker-compose.yml (repo root)
cd examples/nestjs
bun run generate && bunx prisma db push  # creates the tables in the "example_nestjs" schema
AUTH_SECRET=$(openssl rand -hex 32) CSRF_SECRET=$(openssl rand -hex 32) bun start
```

Mail is printed to stdout. `TRUST_PROXY` is the number of reverse proxies in front of the app; with `NODE_ENV=production` the app refuses to start without it.

- `bun run test` is the compile test: it boots the whole `AppModule` (no services needed), pins the list of routes open without a session, and calls every other route to check it answers 401.
- `bun run test:integration` runs the app end to end against the same services: sign-in, rotation, a role granted and taken away in the database, a password change behind a fresh proof.
