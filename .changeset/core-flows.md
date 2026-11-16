---
'@noctcore/auth': minor
---

Add `createAuth` and the flows: registration with a uniform answer, password login (captcha, door limit, capped lockout answered like a wrong password, rehash on login, second-factor challenge seam), email verification by 8-digit code (default) or link, password reset by link or by code exchanged for a ticket, password change, fresh authentication, and session management (list, revoke one with fresh auth, revoke others, revoke all, logout). Hooks (`sessionAttributes`, `beforeSessionCreate`, `onSessionValidate`, `loginChallenge`, `beforePasswordResetRequest`, `beforePasswordReset`, `beforePasswordChange`, `afterRegister`, `onSessionsRevoked`) and `definePlugin` let apps and plugins add refusals, attributes and namespaced flows; every session goes through one `issueSession` seam.
