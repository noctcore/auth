---
'@noctcore/auth': minor
'@noctcore/auth-trpc': minor
---

Add the membership plugin, `@noctcore/auth/membership`, with flows under `auth.membership` (`add`, `changeRole`, `remove`): nobody acts on themselves (`self_target`, by user id), the last member holding an admin role in a scope can be neither demoted nor removed (`last_admin`, decided atomically by the store), the actor's right is read from the store on every call (`canManage`, default: the actor holds an admin role), and a role change or a removal revokes every session of the member through the epoch fence (revocation reason `membership-changed`). The guards fail closed. The plugin does not scope data.

- New store port `MembershipStore`, with `membershipStoreConformance` and `MemoryMembershipStore` in `@noctcore/auth/testing`.
- New public error codes `self_target` and `last_admin`. `AUTH_ERROR_TRPC_CODES` in `@noctcore/auth-trpc` maps them to `FORBIDDEN` and `CONFLICT`. Code that switches over every `AuthErrorCode` with a `never` check needs cases for them.
- New audit event types `membership.added`, `membership.role_changed`, `membership.removed` and `membership.refused`. An audit sink that switches over every type with a `never` check needs cases for them.
