# @noctcore/auth-prisma

Prisma 7 user and one-time token stores for [`@noctcore/auth`](https://github.com/noctcore/auth).

1. Copy the `AuthToken` model from `node_modules/@noctcore/auth-prisma/prisma/auth.prisma` into your schema and migrate.
2. Hand the stores your client's delegates:

```ts
import { prismaStores } from '@noctcore/auth-prisma';

const { users, tokens } = prismaStores({
  delegate: prisma.user,
  tokenDelegate: prisma.authToken,
  // Only when your columns are named differently:
  fields: { passwordHash: 'password', deletedAt: null },
});
```

- The user model needs an id, a unique email (stored normalised: trimmed, NFC, lowercase), a boolean `emailVerified` and a nullable password hash. Soft deletion uses a nullable `deletedAt` unless you set it to `null`.
- `select`, `toUser` and `createData` let the store return your own user type and fill your required columns on sign-up.
- A unique violation on sign-up returns `null`; guarded writes are single `updateMany` statements; consuming a token is a delete that returns the row; the attempt cap is enforced in the update's `where`.

Both stores pass the conformance suite from `@noctcore/auth/testing` on PostgreSQL in CI.
