---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': patch
'@noctcore/auth-trpc': patch
---

A request that loses the race to adopt a legacy session (`adoptLegacySessions`) no longer signs the user out. Its refusal now carries the reason `session_adopting` (the new `adopting` session refusal) instead of `session_unknown`, and the new `clearsSessionCookie(result)` is false for it, so the NestJS CSRF middleware and the tRPC context keep the cookie and the next request finds the session the winning request wrote. Both adapters now decide whether to clear the session cookie through `clearsSessionCookie`. While the wrapper is installed, every token neither store knows is refused this way, so its cookie is kept until the user signs in again or the wrapper is removed; a malformed token and an old record the wrapper drops still clear it.
