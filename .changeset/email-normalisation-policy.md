---
'@noctcore/auth': minor
'@noctcore/auth-trpc': minor
---

Email normalisation is now configurable with `email.normalize`. The default (`'standard'`) is unchanged and stores byte-identical spellings, so existing data keeps matching.

- `'ascii'`: the same spelling as the default, but an address with a non-ASCII character is answered with the new public code `email_not_ascii` (sign-in still answers `invalid_credentials`, with `email_not_ascii` as the audited reason). The tRPC adapter maps it to `BAD_REQUEST`.
- `'unicode'`: keeps Unicode addresses. NFC, then lowercase of the domain and the local part (the Greek final sigma folded to the plain one, so case variants of a Greek address stay one account). Refuses invisible, bidi, control, unassigned and compatibility characters, punycode labels and any part that mixes scripts (the Chinese, Japanese and Korean mixes with Latin are allowed), so a homoglyph or an invisible character cannot make a lookalike account.
- A function `(email) => string | null`: your own policy. It must be pure, deterministic and idempotent. `createAuth` runs it over a sample at startup and refuses one that throws, returns something unusable, answers differently twice or is not idempotent; on each call an address whose result is not a fixed point is refused and logged.

One resolved normaliser now serves every flow (register, login, password reset, email verification, email change, invitations), every stored address and every counter key. It is exposed as `auth.normalizeEmail(email)` for your own code and as `normalizeEmail` and `parseEmail` on the plugin context; the exported `normalizeEmail` stays the `standard` policy. An unknown policy name fails at startup.

Changing the policy on a live database needs a data migration first: rows stored under the old policy no longer match. The package does not migrate data; see the configuration reference.
