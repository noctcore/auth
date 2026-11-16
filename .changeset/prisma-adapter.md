---
'@noctcore/auth-prisma': minor
---

Add `PrismaUserStore`, `PrismaTokenStore` and `prismaStores` for Prisma 7, typed against your client's model delegates, with configurable user columns, soft deletion, extra columns and a richer user type. Ships the `AuthToken` model in `prisma/auth.prisma`. Both stores pass the conformance suite on PostgreSQL.
