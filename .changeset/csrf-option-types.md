---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

The CSRF options are now checked for their type at startup, in `resolveCsrfSettings` and so in both adapters (`AuthModule.forRoot` and `createAuthContext`), with an `AuthConfigError` naming the option. `csrf.allowSameSite` must be `true` or `false` (or left out): it was read by truthiness, so the string `"false"` from the environment turned the weaker same-site mode on. `csrf.secrets` must be a list of strings or bytes, `csrf.allowedOrigins` and `csrf.crossSiteOrigins` lists of strings, and `csrf.headerName` a string. In the NestJS adapter, `csrf.exempt` must be a list of paths and RegExps.

**Behaviour change:** a configuration that started before can now refuse to start. `allowSameSite` given as a string or a number (it ran in same-site mode for any truthy value, `"false"` included), `allowedOrigins` given as one string (it was read character by character, so every unsafe request was refused), and an `exempt` given as one string (read character by character, it exempted the path `/` from CSRF), or holding an entry that is neither a string nor a RegExp (the first unsafe request then threw), are refused at boot. Pass real booleans and lists, for example `allowSameSite: process.env.CSRF_ALLOW_SAME_SITE === 'true'`.
