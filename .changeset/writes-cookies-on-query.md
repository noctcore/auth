---
'@noctcore/auth-trpc': minor
---

`writesCookies`, and `WritesCookiesMiddleware` on nestjs-trpc, now refuse a query, as they already refused a subscription and a streamed batch. A query skips the CSRF check and runs on a GET, which a link on another site can send with the `SameSite=Lax` session cookie, so a cookie-writing query let that site sign the user out or make any other session write the query did. They also run the CSRF check on the mutation themselves, so a cookie writer built on a bare `t.procedure` (no `publicProcedure` or session check in front) is refused when forged instead of running. `assertProceduresGuarded` now also names a query or subscription marked `writesCookies`.

`ProcedureAccess`, the item type `describeProcedures` returns, gains a required `writesCookies: boolean` field. Code that builds `ProcedureAccess` literals, or deep-equals the output of `describeProcedures`, needs the new field.

Behaviour change: a procedure that is not a mutation and carries `writesCookies` used to run; it is now refused on every call with an `AuthConfigError` before it runs (the client sees `internal`), and `assertProceduresGuarded` fails on it. Make it a mutation. A mutation marked `writesCookies` without any other CSRF check in its chain used to run on a forged request; it is now refused with `forbidden` (403). A request from your own page with the CSRF token passes as before.
