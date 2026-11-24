---
'@noctcore/auth': patch
---

The two-factor plugin has three new flows for apps that run part of a sign-in themselves.

- `auth.twoFactor.challenge({ userId, rememberMe?, epoch?, meta })` starts the second-factor challenge for a sign-in your app authenticated itself (an identity provider, a magic link of its own). It answers `null` when no factor is due (issue your own session then), or the same `{ challenge, methods }` a password login gives, finished with `verifyChallenge`. Each call counts on the plugin's `perIp` limit.
- `auth.twoFactor.verifyProof({ userId, proof?, action, meta })` checks a second factor for a user your flow identified without a session (an app-owned reset, an invitation that overwrites an account). It uses the challenge's attempt budget, lockout, per-IP limit, replay guard and recovery-code spend, so it is never a faster way to guess codes. With a proof, a user with no confirmed factor, or no such user, answers `invalid_second_factor` like a wrong code. Without one it answers `{ proved: false }` when nothing is needed and `second_factor_required` when the user has a factor. It never issues or touches a session.
- `auth.twoFactor.reset({ userId, actor?, meta })` is an admin's reset of another user's factor: it deletes the factor, the recovery codes and the trusted devices, writes the new `two_factor.reset` audit event (with `data.actor`), and mails the owner the existing `two-factor-disabled` mail, now with `reset: true`. It trusts its caller: call it only after your own checks.

A login whose `sessionAttributes` fail your session attribute schema after a correct password now answers `invalid_credentials` (reason `invalid_session_attributes`) with a `login.failure` row, like a wrong password, instead of `forbidden`, so the answer no longer tells a caller the password was right. The schema error is still logged for you. Other ways of issuing a session still answer `forbidden`.
