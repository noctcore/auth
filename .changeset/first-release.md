---
'@noctcore/auth': minor
'@noctcore/auth-redis': minor
'@noctcore/auth-prisma': minor
---

**Warning:** early 0.x releases are not meant for production apps yet. The API may have breaking changes between minor versions until 1.0.

First release of the packages. `@noctcore/auth` is the framework-free core (sessions, flows, throttling, store interfaces and conformance suite), `@noctcore/auth-redis` and `@noctcore/auth-prisma` are the store adapters, and this release includes the first hardening pass: an attack suite, a coverage gate, and property and mutation tests.
