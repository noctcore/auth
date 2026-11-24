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

- The user model needs an id, a unique email (stored as the core's `email.normalize` policy spells it: by default trimmed, with ASCII letters lowercased, an address with any non-ASCII character refused and internationalised domains in punycode; under the `unicode` policy stored addresses may be non-ASCII, in NFC and lowercase, so the column must hold UTF-8), a boolean `emailVerified` and a nullable password hash. Soft deletion uses a nullable `deletedAt` unless you set it to `null`.
- Give the email column a binary, or at least case- and accent-sensitive, collation, so a lookup matches the address byte for byte: `utf8mb4_bin` on MySQL and MariaDB (whose default `utf8mb4_0900_ai_ci` treats `zoe`, `zoé` and `Zoë` as one value), a `_CS_AS` collation on SQL Server, PostgreSQL's default (deterministic) collation rather than `citext` or a nondeterministic ICU collation. The core already lowercases and normalises addresses, so the database does not need to fold them. The core also treats a row whose stored email differs from the address it asked for as not found, so an insensitive lookup cannot hand one account to several spellings, each with its own lockout and rate-limit keys; but the unique index still follows the collation, so under an insensitive one a sign-up for another spelling is refused as taken while nobody can sign in with it. `userStoreConformance` checks exact lookups ("different spellings must not match").
- `select`, `toUser` and `createData` let the store return your own user type and fill your required columns on sign-up.
- `writeWhere` (a Prisma `where`, such as `{ closedAt: null }`) is added through `AND` to the password, verified-mark and email-change writes, so an account your app closed on a column of its own refuses a new password even when it was closed after your hooks ran. Reads, login and an email revert are left alone. The store refuses a guard that would match every row in an obvious form (an empty object or an `undefined` anywhere in it, an empty `AND` or `NOT` list) when it is built, and gives each write a fresh copy.
- A taken address on sign-up returns `null`. On PostgreSQL and CockroachDB the insert goes through `createManyAndReturn` with `skipDuplicates`, so a taken address is a skipped insert rather than a failed statement (a failed statement slowed the next query on the pool, which showed in sign-up timing). Everywhere else the store uses `create` and a unique violation (P2002) returns `null`: on MySQL and SQL Server (no `createManyAndReturn`), on SQLite (no `skipDuplicates`), and when `createData` or `select` uses nested writes or relations, which a bulk insert does not take. In the last two cases Prisma refuses the bulk insert in the client, before any statement; the store falls back on that first refusal and remembers it, with one warning to the `logger` option when you pass one. Only the `skipDuplicates` path has the timing benefit. A unique violation on an email change returns `'taken'`; guarded writes (an email change included) are single `updateMany` statements; consuming a token is a delete that returns the row; the attempt cap is enforced in the update's `where`.

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

## Invitation store

For the invitations plugin (`@noctcore/auth/invitations`), copy the `AuthInvitation` model, migrate, and hand the store the client and its delegate:

```ts
import { PrismaInvitationStore } from '@noctcore/auth-prisma';

const store = new PrismaInvitationStore({ client: prisma, invitation: prisma.authInvitation });
```

- `consume` is one delete by the unique hash that returns the row, so of many concurrent accepts exactly one gets the invitation.
- The unique (scope, email) index keeps one invitation per scope and address; an expired one is deleted and replaced in one `$transaction`.
- Expired rows stay until they are replaced, accepted or revoked. Sweep them with `prisma.authInvitation.deleteMany({ where: { expiresAt: { lte: new Date() } } })` if the table grows.

Every store passes the conformance suite from `@noctcore/auth/testing` on PostgreSQL in CI.
