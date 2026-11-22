---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': patch
'@noctcore/auth-trpc': patch
---

The NestJS and tRPC adapters now run one CSRF implementation, in the core, instead of a copy each: the option checks (`resolveCsrfSettings`), the cookie reading (`readCsrfCookies`), the verdict on an unsafe request (`csrfRequestAllowed`), the token a safe request hands out (`handOutCsrfToken`), the cookies written with a new or ended session (`bindCsrfToSession`, `startCsrfPreSession`) and the Node `Set-Cookie` appender (`appendSetCookie`). The core also exports the `isSafeMethod` its CSRF checks already used. An app that mounts both adapters gets the same answer from each for the same cookies, and a change to the rules lands once. The adapters answer every request exactly as before: same checks, same cookies and attributes, same error codes.

New exports for adapter authors in `@noctcore/auth`: `resolveCsrfSettings`, `readCsrfCookies`, `csrfRequestAllowed`, `handOutCsrfToken`, `bindCsrfToSession`, `startCsrfPreSession`, `appendSetCookie` and `isSafeMethod`, with the types `CsrfSettings`, `CsrfSettingsInput`, `CsrfContext`, `CsrfCookies`, `CsrfSessionRef`, `CsrfHandout` and `SetCookieTarget`.
