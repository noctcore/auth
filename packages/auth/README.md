> **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

# @noctcore/auth

The framework-free core of [noctcore auth](https://github.com/noctcore/auth): sessions, password hashing, one-time tokens, throttling and flows over storage interfaces you implement or take from the adapter packages.

```sh
bun add @noctcore/auth @node-rs/argon2
# or: npm install @noctcore/auth @node-rs/argon2
```

`@node-rs/argon2` is an optional peer dependency, needed only for the Argon2id hasher in `@noctcore/auth/argon2`. The stores come from [`@noctcore/auth-prisma`](https://github.com/noctcore/auth/tree/main/packages/auth-prisma) and [`@noctcore/auth-redis`](https://github.com/noctcore/auth/tree/main/packages/auth-redis), or from your own adapters.

```ts
import { createAuth, pwnedPasswords } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';

const auth = createAuth({
  stores: { users, tokens, sessions, counters },
  password: { hasher: argon2id(), breachCheck: pwnedPasswords() },
  secret: process.env.AUTH_SECRET!, // 32 bytes or more
  urls: { resetPassword: (token) => `https://app.example/reset-password#${token}` },
  mailer, // sends verification codes, reset links and lock notices
});

const result = await auth.login({ email, password, meta });
```

A second factor is a plugin: `twoFactor` from `@noctcore/auth/two-factor` adds TOTP, recovery codes, trusted devices and step-up, with its flows under `auth.twoFactor`.

Membership guards are a plugin too: `membership` from `@noctcore/auth/membership` refuses acting on yourself and demoting or removing the last admin of a scope (decided atomically by the store), reads the acting user's role from the store on every call, and, with `revokeSessionsOnChange` on, revokes a member's sessions on an attempted role change or removal (including one the store refuses), with its flows under `auth.membership`.

Invitations are a plugin as well: `invitations` from `@noctcore/auth/invitations` mails a single-use link bound to an address, lets its verified owner accept into their account or create one, never issues a session that skips a second factor, and refuses to start without the app's `authorize` check, with its flows under `auth.invitations`.

Flows return results instead of throwing HTTP errors, and your app keeps its own routes. The root README has a complete wiring example and the list of modules.

- [Root README](https://github.com/noctcore/auth#readme)
- [Docs](https://noctcore.github.io/auth/)
