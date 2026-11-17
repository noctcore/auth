---
'@noctcore/auth': minor
---

Add the two-factor plugin, `@noctcore/auth/two-factor`: TOTP (RFC 6238) with replay protection, ten single-use recovery codes, trusted devices, step-up for sensitive actions, and enforcement on every session the library issues. A password reset of an account with a factor asks for a code or a recovery code. Secrets are encrypted through a `SecretCipher` the app provides.

- New store port `TwoFactorStore`, with `twoFactorStoreConformance` and `MemoryTwoFactorStore` in `@noctcore/auth/testing`.
- Plugin seam: `PluginContext` gains `keyedHash`, `requireFreshAuth` and `cookie`; `Throttle` gains `gateFactor` and `factorSucceeded`.
- New mail events `two-factor-enabled`, `two-factor-disabled` and `recovery-code-used`, and new `two_factor.*` audit event types. A mailer or audit sink that switches over every type with a `never` check needs cases for them.
- `issueSession` accepts the re-issue vias (`password-change`, `reauthenticate`, `revoke-others`, `email-verified`) only with an `inherit` the core read live from the store, for the same user, through the new `AuthCore.confirmLiveSession`, before the flow revoked anything. A revoked, expired, idle or hand-built session is refused, and `reauthenticate`, `changePassword` and `sessions.revokeOthers` answer `session_expired` (`session_not_active`) for one. `SessionManager` gains `findActive`.
- A lock no longer resets the attempt counter: it holds the counter above the limit for as long as the lock lasts, and further failures under it renew the lock every `limit + 1`. A request that read "no lock" just before another one set it is now refused, so a parallel burst over many connections gets no more than the budget, for the password lockout and the second factor alike.
- **Rotating `secret` voids every recovery code** of the two-factor plugin, whose HMAC key is derived from it. After a rotation, have every user with a factor regenerate their recovery codes.
- `twoFactor` checks `attempts` and `perIp` at creation: the limit must be a positive integer and the window positive.
- `resetPassword` and `changePassword` check the new password against the policy before running the `beforePasswordReset` and `beforePasswordChange` hooks, so a refused password spends nothing a hook asked for.
