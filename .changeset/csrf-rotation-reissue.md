---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': minor
'@noctcore/auth-trpc': minor
---

During a CSRF secret rollover (`csrf.secrets: [NEW, OLD]`) a safe request now replaces a token signed by the previous secret with one under the current secret, in `handOutCsrfToken` and so in both adapters. Before, any token that verified under any listed secret was kept, so no client moved to the new secret while the old one was listed: removing the old secret answered every client's next unsafe request with a 403, and a leaked old secret could not be retired early. The old secret can go once clients have made a safe request since the rollover; the NestJS guide and the CSRF learn page say so. The unsafe-request check is unchanged: the header must equal the cookie.

**Behaviour change:** during a rotation, a page that kept the old token in memory (a single page app or desktop shell that read `csrfToken()` once, or a second tab) gets one 403 after another request reissued the cookie, because its header no longer equals the cookie. It should read the token again from the cookie or the token route, or retry once after a safe request. Before, such a page kept working until the old secret was removed, and then failed the same way.
