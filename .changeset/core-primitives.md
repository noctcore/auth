---
'@noctcore/auth': minor
---

Add the core primitives: secure random tokens and numeric codes, SHA-256 and HMAC helpers with constant-time comparison, email normalisation, durations, `AuthResult` and the closed `AuthErrorCode` set, the password policy (length only, NFC), the `PasswordHasher` contract with a self-made dummy hash for timing parity, the Have I Been Pwned range check (fails open), session cookie helpers (`__Host-`, SameSite per origin), the CSRF Sec-Fetch-Site and Origin checks and the signed double-submit token, a Turnstile verifier that checks hostname and action, and trust-proxy and client IP helpers. Argon2id (19 MiB, t=3, p=1 by default, never below the OWASP floor) with `needsRehash` is in `@noctcore/auth/argon2`.
