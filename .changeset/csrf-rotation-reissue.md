---
'@noctcore/auth': patch
'@noctcore/auth-nestjs': patch
'@noctcore/auth-trpc': patch
---

During a CSRF secret rollover (`csrf.secrets: [NEW, OLD]`) a safe request now replaces a token signed by the previous secret with one under the current secret, in `handOutCsrfToken` and so in both adapters. Before, any token that verified under any listed secret was kept, so no client moved to the new secret while the old one was listed: removing the old secret answered every client's next unsafe request with a 403, and a leaked old secret could not be retired early. A page that read the old token before its cookie was replaced still passes (`csrfRequestAllowed` accepts a previous-secret header token over the current-secret cookie for the same binding) until the old secret is removed. The old secret can go once clients have made a safe request since the rollover; the NestJS guide and the CSRF learn page say so.
