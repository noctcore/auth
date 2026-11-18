---
'@noctcore/auth': patch
---

`hexDigestsEqual` and `secretsEqual` compare through Node's `crypto.timingSafeEqual` where the runtime has it (Node 22.3 and later, Bun, Deno), found through `process.getBuiltinModule` so that bundles for other runtimes never import `node:crypto`. Everywhere else they keep the JavaScript loop. The answers are the same as before for equal, unequal and different-length input, and a length mismatch is still refused before any comparison runs.
