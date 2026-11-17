---
'@noctcore/auth': minor
---

Add the two-factor plugin, `@noctcore/auth/two-factor`: TOTP (RFC 6238) with replay protection, ten single-use recovery codes, trusted devices, step-up for sensitive actions, and enforcement on every session the library issues. A password reset of an account with a factor asks for a code or a recovery code. Secrets are encrypted through a `SecretCipher` the app provides.

- New store port `TwoFactorStore`, with `twoFactorStoreConformance` and `MemoryTwoFactorStore` in `@noctcore/auth/testing`.
- Plugin seam: `PluginContext` gains `keyedHash`, `requireFreshAuth` and `cookie`; `Throttle` gains `gateFactor` and `factorSucceeded`.
- New mail events `two-factor-enabled`, `two-factor-disabled` and `recovery-code-used`, and new `two_factor.*` audit event types. A mailer or audit sink that switches over every type with a `never` check needs cases for them.
- `issueSession` refuses the re-issue vias (`password-change`, `reauthenticate`, `revoke-others`, `email-verified`) unless `inherit` is a session of the same user.
- `resetPassword` and `changePassword` check the new password against the policy before running the `beforePasswordReset` and `beforePasswordChange` hooks, so a refused password spends nothing a hook asked for.
