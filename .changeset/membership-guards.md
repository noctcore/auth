---
'@noctcore/auth': minor
'@noctcore/auth-trpc': minor
---

Add the membership plugin, `@noctcore/auth/membership`, with flows under `auth.membership` (`add`, `changeRole`, `remove`): nobody acts on themselves (`self_target`, by user id), the last member holding an admin role in a scope can be neither demoted nor removed (`last_admin`, decided atomically by the store), the actor's right is read from the store on every call (`canManage`, default: the actor holds an admin role), and every flow first reads the acting session live from the store. Session revocation is opt-in (`revokeSessionsOnChange`, default false) for apps that copy roles into sessions: then a real role change or a removal revokes every session of the member through the epoch fence (revocation reason `membership-changed`), while adding a member and setting the role a member already holds never revoke. The guards fail closed. The plugin does not scope data.

- New store port `MembershipStore`, with `membershipStoreConformance` and `MemoryMembershipStore` in `@noctcore/auth/testing`.
- New public error codes `self_target` and `last_admin`. `AUTH_ERROR_TRPC_CODES` in `@noctcore/auth-trpc` maps them to `FORBIDDEN` and `CONFLICT`. Code that switches over every `AuthErrorCode` with a `never` check needs cases for them.
- New audit event types `membership.added`, `membership.role_changed`, `membership.removed` and `membership.refused`. An audit sink that switches over every type with a `never` check needs cases for them.
- `SessionAccess` (the plugin context's `sessions`) gains `findActive(id)`, a read of a live session by id, so a plugin can check that the session it was handed is still live. It cannot mint or re-issue anything.
