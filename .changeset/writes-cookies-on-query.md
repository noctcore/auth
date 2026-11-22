---
'@noctcore/auth-trpc': minor
---

`writesCookies`, and `WritesCookiesMiddleware` on nestjs-trpc, now refuse a query, as they already refused a subscription and a streamed batch. A query skips the CSRF check and runs on a GET, which a link on another site can send with the `SameSite=Lax` session cookie, so a cookie-writing query let that site sign the user out or make any other session write the query did. `assertProceduresGuarded` now also names a query or subscription marked `writesCookies`, and `describeProcedures` reports `writesCookies` for each procedure.

Behaviour change: a procedure that is not a mutation and carries `writesCookies` used to run; it is now refused on every call with an `AuthConfigError` before it runs (the client sees `internal`), and `assertProceduresGuarded` fails on it. Make it a mutation.
