# Example: node:http with Prisma and Redis

A small JSON API on `@noctcore/auth`: register, sign in, verify the address with a code, read the account, list sessions, sign out. It wires every piece a production app needs (Argon2id, the Prisma and Redis stores, the session cookie, CSRF protection) without a framework, so each step is visible in `src/app.ts`.

```sh
bun run services:up                      # Redis and PostgreSQL from docker-compose.yml (repo root)
cd examples/basic
bun run generate && bunx prisma db push  # creates the tables in the "example" schema
AUTH_SECRET=$(openssl rand -hex 32) bun start
```

Mail is printed to stdout. `bun run test:integration` runs the end-to-end test against the same services.

CSRF: every unsafe request needs an allowed `Origin`, `Sec-Fetch-Site: same-origin` whenever the browser sends it, and an `X-CSRF-Token` header matching the `csrf` cookie, signed and bound to the current session (a new token is handed out whenever the session changes).
