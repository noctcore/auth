---
title: Entropy and tokens
description: How many random bits a secret needs, where they come from, why Math.random and UUIDs are not tokens, and the sizes the package uses.
---

## What goes wrong

A token is only as strong as the number of values it could have been. If an attacker can predict how it was made, or can try every value it could take, the token is a password they can guess. Three shortcuts make that easy:

- `Math.random` is built for speed, not secrecy. Its output comes from a small internal state, and someone who sees a few outputs can work out that state and every value that follows.
- A UUID is an identifier format, not a secret. The time-based versions are partly a timestamp (and, in some, the machine's network address), for the random version, a secure source is a recommendation to implementations, not a guarantee, and the UUID specification itself says not to use UUIDs as security capabilities.
- A timestamp, a counter or a short random value, hashed or not, has so few possible values that an attacker can try them all.

## The rule

**Every bearer secret is 32 bytes from the platform's secure random source.** `generateToken` fills 32 bytes with `crypto.getRandomValues` and writes them as 64 lowercase hex characters: 256 bits, far beyond what any online or offline search can cover. Session tokens, email verification and password reset links, the ticket a reset code is exchanged for, email change and revert links, the two-factor plugin's login challenges and trusted-device tokens, and invitation tokens are all made this way. `Math.random` is never used. A token encodes nothing: no user id, no expiry, no counter.

**Anything else is turned away before the store sees it.** A value that is not exactly 64 lowercase hex characters is treated as unknown without a lookup (`isTokenShape`), so junk never becomes a store key. That is a filter, not a check: only the store lookup grants anything.

**A code a person types is short, so it is rationed.** Verification, reset and email change codes have 8 digits by default (6 to 9 allowed). They are drawn by rejection sampling, so every code is equally likely: taking a random number modulo a power of ten would make low codes slightly more common. No length a person can type resists a search on its own, so each code gets 5 attempts, counted atomically before the comparison, lives 15 minutes by default, and is deleted when its attempts run out. [Password reset](/auth/learn/password-reset/) and [Email verification](/auth/learn/email-verification/) cover the per-address budgets on top.

**Second-factor secrets follow the same rule.** TOTP secrets are 20 bytes (160 bits), the size the HOTP standard recommends. Recovery codes are 10 codes of 10 characters each from a 32-symbol alphabet, 50 bits per code, and every guess spends the account's second-factor budget. See [Second factors](/auth/learn/second-factors/).

**The server secret is at least 32 bytes.** `createAuth` refuses a shorter `secret`. The check counts bytes, not randomness: a 32-character sentence passes it and is still guessable. Generate the secret from a secure source, for example with `openssl rand -hex 32`, and keep it out of the repository.

## Where the package and the guide differ

The guide recommends a 32-byte session secret from a cryptographically secure source, kept beside a separate session id. The package uses the same size and source for every bearer secret it mints, as a single token without the separate id (see [Sessions and expiry](/auth/learn/sessions-and-expiry/)). For codes a person types, which the sessions page does not cover, the package relies on the attempt cap and the expiry above, not on length.

## Further reading

- [Sessions](https://auth.pilcrowonpaper.com/sessions) in Pilcrow's auth guide.
- [Why tokens are hashed](/auth/learn/why-tokens-are-hashed/) for what is stored instead of the token.
- Attack tests: [A013, guessing a short code](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A013-code-guessing.test.ts) and [A042, brute forcing a recovery code](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A042-recovery-code-brute-force.test.ts).
