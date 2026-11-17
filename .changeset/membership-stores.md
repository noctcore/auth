---
'@noctcore/auth-redis': minor
'@noctcore/auth-prisma': minor
---

Add stores for the membership plugin: `RedisMembershipStore` in `@noctcore/auth-redis` (one hash per scope under `ms:<scope>`, guarded writes in one Lua script) and `PrismaMembershipStore` in `@noctcore/auth-prisma`, which needs the two new models in `prisma/auth.prisma` (`AuthMember`, `AuthMemberScope`) and the client, for the version-guarded transaction behind every role change and removal. Both pass `membershipStoreConformance`, including its concurrent last-admin cases, against Redis and PostgreSQL.
