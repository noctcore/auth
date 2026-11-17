> **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

# @noctcore/auth-prisma

Prisma 7 user, one-time token, two-factor and membership stores for [`@noctcore/auth`](https://github.com/noctcore/auth).

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

- The user model needs an id, a unique email (stored normalised: trimmed, with ASCII letters lowercased; an address with any non-ASCII character is refused, and internationalised domains go in as punycode), a boolean `emailVerified` and a nullable password hash. Soft deletion uses a nullable `deletedAt` unless you set it to `null`.
- `select`, `toUser` and `createData` let the store return your own user type and fill your required columns on sign-up.
- A taken address on sign-up returns `null`. On PostgreSQL and CockroachDB the insert goes through `createManyAndReturn` with `skipDuplicates`, so a taken address is a skipped insert rather than a failed statement (a failed statement slowed the next query on the pool, which showed in sign-up timing). Everywhere else the store uses `create` and a unique violation (P2002) returns `null`: on MySQL and SQL Server (no `createManyAndReturn`), on SQLite (no `skipDuplicates`), and when `createData` or `select` uses nested writes or relations, which a bulk insert does not take. In the last two cases Prisma refuses the bulk insert in the client, before any statement; the store falls back on that first refusal and remembers it. Only the `skipDuplicates` path has the timing benefit. A unique violation on an email change returns `'taken'`; guarded writes (an email change included) are single `updateMany` statements; consuming a token is a delete that returns the row; the attempt cap is enforced in the update's `where`.

## Two-factor store

For the two-factor plugin (`@noctcore/auth/two-factor`), copy the `AuthTwoFactor`, `AuthRecoveryCodes`, `AuthTrustedDevice` and `AuthStepUp` models from the same file, migrate, and hand the store their delegates:

```ts
import { PrismaTwoFactorStore } from '@noctcore/auth-prisma';

const store = new PrismaTwoFactorStore({
  factor: prisma.authTwoFactor,
  recoveryCodes: prisma.authRecoveryCodes,
  trustedDevice: prisma.authTrustedDevice,
  stepUp: prisma.authStepUp,
});
```

- No column holds a secret in the clear: `secret` is what your `SecretCipher` wrote, recovery codes and device tokens are hashes.
- Moving the last accepted TOTP step and confirming an enrollment are single `updateMany` statements with the guard in `where`. A user's recovery codes are one row; a code is spent by an update guarded on the row's `version`.
- Delete a user's factor and recovery codes with the user (or add relations with `onDelete: Cascade`). Expired devices are deleted when the user adds one; sweep expired step-up proofs with `deleteMany({ where: { expiresAt: { lt: new Date() } } })`.

## Membership store

For the membership plugin (`@noctcore/auth/membership`), copy the `AuthMember` and `AuthMemberScope` models, migrate, and hand the store the client and their delegates:

```ts
import { PrismaMembershipStore } from '@noctcore/auth-prisma';

const store = new PrismaMembershipStore({
  client: prisma,
  member: prisma.authMember,
  scope: prisma.authMemberScope,
});
```

- A role change or a removal reads the scope's version, the member and the other admins, then commits a version-guarded update of the scope row and the member write in one `$transaction`. If another write of the scope committed in between, the transaction rolls back and the store decides again on fresh rows, so two admins demoting each other at once leave one admin.
- Write memberships only through the store, or bump `AuthMemberScope.version` in the same transaction as your own write.

Every store passes the conformance suite from `@noctcore/auth/testing` on PostgreSQL in CI.
