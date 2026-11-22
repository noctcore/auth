---
'@noctcore/auth': patch
---

A `secret`, `previousSecret` entry, argon2id pepper or csrf secret made as a `Uint8Array` in another realm (a `vm` context, some test environments) is accepted: the startup checks no longer use `instanceof Uint8Array`, which is false across realms. A `DataView` and a wider typed array such as a `Uint16Array` are still refused.
