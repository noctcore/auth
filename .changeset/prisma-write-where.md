---
'@noctcore/auth-prisma': minor
---

New `PrismaUserStoreOptions.writeWhere` (also on `prismaStores`): a Prisma `where`, such as `{ closedAt: null }`, that a row must also match to take a new password hash (`setPasswordHash`), a verified mark (`markEmailVerified`) or an email change (`changeEmail`). It is combined with the store's own conditions through `AND`, in the same UPDATE, so an account your app closed on a column of its own refuses the write even when it was closed after your `beforePasswordReset` hook ran; the flows answer that as a refused write (`invalid_token` from a reset). Reads are unchanged, so login and lookups still find the row. An email revert (the `changeEmail` that also clears the password) is not guarded, since it only takes access away. Left out by default, so nothing changes unless you set it; a value that is not an object is refused when the store is built.
