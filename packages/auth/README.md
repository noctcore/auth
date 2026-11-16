# @noctcore/auth

The framework-free core of [noctcore auth](https://github.com/noctcore/auth): sessions, password hashing, one-time tokens, throttling and flows over storage interfaces you implement or take from the adapter packages.

> [!WARNING]
> **Early development.** This library is not ready for production apps yet. The API may change in any release before 1.0. Try it and read it, but do not put real users behind it yet.

```sh
npm install @noctcore/auth @node-rs/argon2
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

Flows return results instead of throwing HTTP errors, and your app keeps its own routes. The root README has a complete wiring example and the list of modules.

- [Root README](https://github.com/noctcore/auth#readme)
- [Docs](https://noctcore.github.io/auth/) (coming soon)
