---
'@noctcore/auth-prisma': minor
---

`PrismaUserStore` (and `prismaStores`) take an optional `logger`. When Prisma refuses the skipped insert at sign-up (SQLite, a `createData` with nested writes) and the store switches to `create` for good, it warns once through that logger instead of switching silently. The warning carries no error text, because a Prisma validation message prints the whole call, the password hash included.
