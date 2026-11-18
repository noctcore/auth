---
'@noctcore/auth': minor
---

Add `emailVerification.linkWithoutSession`, an opt-in that also accepts a valid verification link opened without a session (on another device, or after the session expired). The link stays single-use, expiring and bound to the address it was sent to; it verifies the address and revokes every session of the account, but never signs anyone in. A session of another account is still refused. The default is unchanged: a link counts only in a signed-in session of the same account. Setting the option with code verification, or to anything but `true` or `false`, is refused at startup. With the option on, keep the token in the URL fragment and verify only on a POST from a click, so a mail scanner that fetches the link verifies nothing; the docs cover the trade-off.
