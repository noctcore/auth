---
'@noctcore/auth-trpc': patch
---

`createAuthContext(...).node` now refuses tRPC's WebSocket adapter (`applyWSSHandler`) with an `AuthConfigError` naming the reason, before it reads a cookie or validates a session. The adapter passes its socket as `res` and builds the context once per connection, so a first visit failed with `internal` and a signed-in connection kept answering as the user after a sign-out, a password change or a revocation. WebSocket is not supported yet. The check refuses any response that cannot set headers, so tRPC's Fastify adapter (whose reply has no `setHeader`) is refused too: Fastify is not supported yet, as on the Nest adapter. The fetch adapter and the standalone, Express and nestjs-trpc (Express) adapters are unchanged.
