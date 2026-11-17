# @noctcore/auth-redis

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
