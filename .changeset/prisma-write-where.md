---
'@noctcore/auth-prisma': minor
'@noctcore/auth': minor
---

New `PrismaUserStoreOptions.writeWhere` (also on `prismaStores`): a Prisma `where`, such as `{ closedAt: null }`, that a row must also match to take a new password hash (`setPasswordHash`), a verified mark (`markEmailVerified`) or an email change (`changeEmail`). It is combined with the store's own conditions through `AND`, in the same UPDATE, so an account your app closed on a column of its own refuses the write even when it was closed after your `beforePasswordReset` hook ran; the flows answer that as a refused write (`invalid_token` from a reset). Reads are unchanged, so login and lookups still find the row. An email revert (the `changeEmail` that also clears the password) is not guarded, since it only takes access away. Left out by default, so nothing changes unless you set it. The store checks and copies the value when it is built: anything but a plain, non-empty object, or one with `undefined` inside (Prisma reads that as no filter, so the guard would guard nothing), is refused with `AuthConfigError`. A column name Prisma does not know only shows at the first guarded write, which throws.

The Prisma user store now rethrows a Prisma client error from `setPasswordHash`, `markEmailVerified` or `changeEmail` as a `PrismaUserStoreError` without Prisma's message (keeping its `code`), since that message prints the whole call, the new password hash included, and a failed rehash is logged with it. This applies with or without `writeWhere`.

In `@noctcore/auth`, an invitation sign-up (the invitations plugin's `register`) whose verified mark the store refuses now goes on with the account unverified: `afterRegister`, `onAccept` and the session see `emailVerified: false`, as the store holds it. It used to hand them `emailVerified: true` whatever the store answered.
