---
'@noctcore/auth-redis': minor
'@noctcore/auth-prisma': minor
---

Add stores for the invitations plugin: `RedisInvitationStore` in `@noctcore/auth-redis` (keys under `inv:`, each with a TTL at the invitation's expiry, create and consume each one Lua script) and `PrismaInvitationStore` in `@noctcore/auth-prisma`, which needs the new `AuthInvitation` model in `prisma/auth.prisma` and the client, for the transaction that replaces an expired invitation. Both pass `invitationStoreConformance`, including its concurrent consume and create cases, against Redis and PostgreSQL.
