---
title: Design choices
description: Where the package follows Pilcrow's auth guide, where it is stricter, and the few places it deliberately does something else.
---

The package's behaviour comes from an auth implementation that already runs in production; its explanations and many of its defaults follow [Pilcrow's auth guide](https://auth.pilcrowonpaper.com/). Where the two disagreed, the stricter one won. This page lists every disagreement in one place.

| Topic | Auth guide | Package | Why |
|---|---|---|---|
| Argon2id cost | 16 MiB, t=3, p=1 | 19 MiB, t=3, p=1 | Memory from OWASP's floor, passes from the guide: the stricter of each. |
| Password length | 8 to 10 minimum, 50 to 100 maximum | 12 minimum, 256 maximum | 12 from the production implementation; 256 fits passphrases, and hashing cost is bounded by rate limits. |
| Password characters | printable ASCII is fine | any Unicode, NFC-normalised | Follows the guide's rule for apps that allow Unicode. |
| Account existence | explicit errors are acceptable | uniform answers by default, `revealExisting` to opt out | Owner decision: email is the login identifier. See [Enumeration](/auth/learn/enumeration/). |
| Lockout | avoid lockouts and exponential backoff | capped lockout: per (account, IP) and per account, 1 h cap, backoff reset after a quiet day, no permanent tier, owner mailed, trusted devices bypass it with their own budget | Owner decision, shaped to remove victim lockout. See [Brute force and lockout](/auth/learn/brute-force-and-lockout/). |
| Verification codes | 8 digits; hashing and attempt counting optional | 8 digits, HMAC at rest, 5 attempts, bound to account and address | Stricter at no cost. See [Email verification](/auth/learn/email-verification/). |
| Sessions after a password change | ask the user | always revoke all, re-issue the current one, mail the owner | Production behaviour, stricter. |
| Granular session revocation | requires identity verification | revoking another device, or every other device, requires fresh authentication (10 min) | Follows the guide. |
| Action-specific sessions for sensitive actions | recommended | fresh-auth window on the session plus `reauthenticate`; second factors through hooks | A step-up plugin can add single-use action sessions on the same seams. |
| Session token | id plus separate hashed secret | random token; the store key is its SHA-256 | Keeps sessions issued by existing deployments valid on adoption; the id an app sees is a hash, never a credential. |
| Activity refresh | e.g. hourly or daily | at most once a minute, update-only-if-exists | Idle timeouts of 30 minutes need a finer refresh; the write can never resurrect a session. |
| Email normalisation | do not silently change input | trim, lowercase ASCII letters, refuse any non-ASCII character | Prevents duplicate accounts that differ only in case. Unicode case folding is refused rather than applied, because it maps distinct characters onto ASCII ones (KELVIN SIGN to `k`); internationalised domains go in as punycode. |
| CSRF | `Sec-Fetch-Site`, then `Origin`, then tokens | Origin allowlist plus `Sec-Fetch-Site` when present plus signed token | Apps with a desktop shell send cross-site requests by design. See [CSRF](/auth/learn/csrf/). |
