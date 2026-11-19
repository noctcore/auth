---
'@noctcore/auth': patch
---

`createAuth` now refuses a fixed `session.cookie.sameSite: 'none'` with `secure: false` when it starts, with the same `AuthConfigError` ('SameSite=None requires a Secure cookie') that a cookie build raised at the first sign-in. A deploy with that setting no longer boots and fails on its first request. A function-valued `sameSite` cannot be checked without a request, so it is still refused when a cookie is built. The other combinations (`'none'` with the default Secure, `'lax'` or `'strict'` with `secure: false`) start as before.
