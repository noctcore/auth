# @noctcore/auth-redis

## 0.7.0

### Patch Changes

- Updated dependencies [[`1a9c977`](https://github.com/noctcore/auth/commit/1a9c977b4db46fbb4d8be774dffad7f0cdbc7950)]:
  - @noctcore/auth@0.7.0

## 0.6.0

### Minor Changes

- [#99](https://github.com/noctcore/auth/pull/99) [`6220dfe`](https://github.com/noctcore/auth/commit/6220dfe270fc94dd4f42fd25d52996f690458d93) Thanks [@Shironex](https://github.com/Shironex)! - Sessions evicted by the per-user cap (`session.maxPerUser`) are now reported exactly once, so apps can close their sockets and drop their caches.
  
  - `IssuedSession` has two new fields: `evictedHandles`, the public handles of the user's older sessions that issuing this one deleted (the names `sessions.list` showed, safe to send to a client), and `evicted`, the same sessions' store keys, for server-side use only. Both are oldest first and empty when nothing was evicted. Every flow that returns an issued session (`login`, `register`, `reauthenticate`, `changePassword`, `sessions.revokeOthers`, email verification and change, the two-factor and invitation flows) carries them. `onSessionsRevoked` fires with reason `evicted`, the store keys as `sessionIds` and the handles as `sessionHandles`, like every other reason; a hook that throws is logged and the sign-in still succeeds.
  - Sign-ins racing at the cap no longer report one evicted session twice, and an eviction racing a sign-out or a revocation of the same session reports it under one reason only: the call whose delete removed a session reports it. `logout`, `sessions.revoke`, `sessions.revokeAll`, revoke-others and the other revoke-all reasons now report (to the hook and in their answer) only the sessions their own delete removed. `onSessionsRevoked` is awaited on the sign-in that evicts: keep it fast.
  - `SessionStore.delete` may now return the ids it removed (`Promise<void | readonly string[]>`). The memory and Redis stores do. A custom store that returns nothing keeps working, and the cap then reports every id it chose, as before. A store whose `delete` returns something else (a count, say) is treated the same way. The store conformance suite has three new cases for the returned ids and the races; a store whose `delete` returns nothing fails them with a message, or passes `deleteReportsRemoved: false` to list them as skipped.

### Patch Changes

- Updated dependencies [[`5ef423f`](https://github.com/noctcore/auth/commit/5ef423f29ac787f97ec06e60e4bbefb672907732), [`89932e2`](https://github.com/noctcore/auth/commit/89932e2e1ee9c903e19db79643a58352263124d8), [`a78835e`](https://github.com/noctcore/auth/commit/a78835e018c59fb82863bcea122cf7d6fb4f6c82), [`1ac8ef2`](https://github.com/noctcore/auth/commit/1ac8ef25814bfed484dd94cd45f55ee107407712), [`bb44bef`](https://github.com/noctcore/auth/commit/bb44bef7700c67859180c2ab2290176daecc024a), [`8dd0bda`](https://github.com/noctcore/auth/commit/8dd0bda06892aa9ecab3ec4f69ee5e7158354cc5), [`e30dfba`](https://github.com/noctcore/auth/commit/e30dfbab3fb5af0f344ec3e70619a9517c8b20c6), [`c2a26b4`](https://github.com/noctcore/auth/commit/c2a26b4af8954f9662bf72ed7ffaed15bbad1f53), [`d66c19f`](https://github.com/noctcore/auth/commit/d66c19fd9445ec8879776e569f63f729e1d2d25f), [`0713d60`](https://github.com/noctcore/auth/commit/0713d60d21052e2d24c9ddd23a59225ec5e5a80e), [`67f1b27`](https://github.com/noctcore/auth/commit/67f1b273529f8612b9addd5ad8fa9f9210c75dd0), [`6e59447`](https://github.com/noctcore/auth/commit/6e59447af177ef851779d051b92044d5866e0d2b), [`6220dfe`](https://github.com/noctcore/auth/commit/6220dfe270fc94dd4f42fd25d52996f690458d93), [`c181c9a`](https://github.com/noctcore/auth/commit/c181c9a7ab5d1c80ab47adcaac5cbcabb1617c89), [`5144b55`](https://github.com/noctcore/auth/commit/5144b55b2e39d1dd82a71c3fdbfbaf184be45046), [`7258600`](https://github.com/noctcore/auth/commit/7258600446e61caaa4b0bcf44d904d4570f62fb1), [`8ca8e82`](https://github.com/noctcore/auth/commit/8ca8e82e4e136d31ccd46048541921ba567fc7bc), [`1c24674`](https://github.com/noctcore/auth/commit/1c246742eea9b734a74b8989c0f83557accb186a), [`324401b`](https://github.com/noctcore/auth/commit/324401b039d245f21b5dd6f9d0595cf4fabecbc6), [`ec705e8`](https://github.com/noctcore/auth/commit/ec705e8715df9d543c2672922de14a0f3547dd8d)]:
  - @noctcore/auth@0.6.0

## 0.5.0

### Minor Changes

- [#71](https://github.com/noctcore/auth/pull/71) [`c09f611`](https://github.com/noctcore/auth/commit/c09f611bc86253f33220e6d6ace54743de5cc1af) Thanks [@Shironex](https://github.com/Shironex)! - Add stores for the invitations plugin: `RedisInvitationStore` in `@noctcore/auth-redis` (keys under `inv:`, each with a TTL at the invitation's expiry, create and consume each one Lua script) and `PrismaInvitationStore` in `@noctcore/auth-prisma`, which needs the new `AuthInvitation` model in `prisma/auth.prisma` and the client, for the transaction that replaces an expired invitation. Both pass `invitationStoreConformance`, including its concurrent consume and create cases, against Redis and PostgreSQL.

- [#64](https://github.com/noctcore/auth/pull/64) [`2ab09b7`](https://github.com/noctcore/auth/commit/2ab09b7b3769e14fbd72259138592df55a8bb3bb) Thanks [@Shironex](https://github.com/Shironex)! - Add stores for the membership plugin: `RedisMembershipStore` in `@noctcore/auth-redis` (one hash per scope under `ms:<scope>`, guarded writes in one Lua script) and `PrismaMembershipStore` in `@noctcore/auth-prisma`, which needs the two new models in `prisma/auth.prisma` (`AuthMember`, `AuthMemberScope`) and the client, for the version-guarded transaction behind every role change and removal. Both pass `membershipStoreConformance`, including its concurrent last-admin cases, against Redis and PostgreSQL.

### Patch Changes

- Updated dependencies [[`fb9f5d8`](https://github.com/noctcore/auth/commit/fb9f5d80dcdc515ff0e09b453c18136adddbd6ca), [`76717de`](https://github.com/noctcore/auth/commit/76717de578fbd4f83973dcf544acafeb1d5c9dad), [`5b79f16`](https://github.com/noctcore/auth/commit/5b79f16f9a597db92131f6684114c9f872cac4f5), [`c09f611`](https://github.com/noctcore/auth/commit/c09f611bc86253f33220e6d6ace54743de5cc1af), [`57440a0`](https://github.com/noctcore/auth/commit/57440a046b8f63cbca56f273ac611a8d6d391ebb), [`2ab09b7`](https://github.com/noctcore/auth/commit/2ab09b7b3769e14fbd72259138592df55a8bb3bb), [`e73f7a0`](https://github.com/noctcore/auth/commit/e73f7a0096808eb2fa9f705fe6c32983fb752e08)]:
  - @noctcore/auth@0.5.0

## 0.4.0

### Minor Changes

- [#59](https://github.com/noctcore/auth/pull/59) [`a78168e`](https://github.com/noctcore/auth/commit/a78168e668f7add8256d44596bd29a6455f61dd1) Thanks [@Shironex](https://github.com/Shironex)! - Add stores for the two-factor plugin: `RedisTwoFactorStore` in `@noctcore/auth-redis` and `PrismaTwoFactorStore` in `@noctcore/auth-prisma`. The Prisma store needs the four new models in `prisma/auth.prisma` (`AuthTwoFactor`, `AuthRecoveryCodes`, `AuthTrustedDevice`, `AuthStepUp`). Both pass `twoFactorStoreConformance`. `redisStores()` is unchanged; construct `RedisTwoFactorStore` yourself.

### Patch Changes

- Updated dependencies [[`a78168e`](https://github.com/noctcore/auth/commit/a78168e668f7add8256d44596bd29a6455f61dd1)]:
  - @noctcore/auth@0.4.0

## 0.3.0

### Patch Changes

- Updated dependencies [[`ceaae4c`](https://github.com/noctcore/auth/commit/ceaae4c11e265c833e34375e829cf34205cb07a5)]:
  - @noctcore/auth@0.3.0

## 0.2.0

### Minor Changes

- [#47](https://github.com/noctcore/auth/pull/47) [`fe2e067`](https://github.com/noctcore/auth/commit/fe2e06730b09f54d2a06ea2d573ebfb977a8f5ae) Thanks [@Shironex](https://github.com/Shironex)! - **Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.
  
  First release of the packages. `@noctcore/auth` is the framework-free core (sessions, flows, throttling, store interfaces and conformance suite), `@noctcore/auth-redis` and `@noctcore/auth-prisma` are the store adapters, and this release includes the first hardening pass: an attack suite, a coverage gate, and property and mutation tests.

- [#1](https://github.com/noctcore/auth/pull/1) [`82bd3c0`](https://github.com/noctcore/auth/commit/82bd3c042c9f36a78944ddac903d3faeadfce993) Thanks [@Shironex](https://github.com/Shironex)! - Add `RedisSessionStore`, `RedisCounterStore` and `redisStores`: sessions as JSON with a TTL at their absolute end, a per-user sorted-set index, `touch` as `SET XX KEEPTTL`, an epoch that outlives every session, and counters whose TTL is armed atomically by the first hit. Both pass the conformance suite on a real Redis.

### Patch Changes

- Updated dependencies [[`e61e894`](https://github.com/noctcore/auth/commit/e61e8945482bd23b4e432ced58145e09acdb973f), [`9305ef5`](https://github.com/noctcore/auth/commit/9305ef5548bc3ca5d10b058ece12795bcc44a89d), [`cdeddbf`](https://github.com/noctcore/auth/commit/cdeddbf146dc664734e8f52a49f53bae614529c1), [`f138781`](https://github.com/noctcore/auth/commit/f138781408c66595004a5ae7e3e8ac3fa5de9c90), [`a222dc2`](https://github.com/noctcore/auth/commit/a222dc29c9134b286d8acb16b13b66da249a7ff6), [`7ca4a52`](https://github.com/noctcore/auth/commit/7ca4a522899e5802058de35e8887c9201b91c378), [`fe2e067`](https://github.com/noctcore/auth/commit/fe2e06730b09f54d2a06ea2d573ebfb977a8f5ae)]:
  - @noctcore/auth@0.2.0
