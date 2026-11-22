---
'@noctcore/auth-trpc': minor
---

`assertNoSecretQueries` now catches plural and run-together secret names in a query's input: `recoveryCodes`, `backupCodes`, `passwords`, `apiTokens`, `accessTokens`, `resettoken`, `otpcode`, `verificationcode` and `apiKey` (and its plural). It used to match whole words only, so a secret named that way travelled in the request URL without failing the check. A key is split into words (camelCase, snake_case, kebab-case), and a word matches when it is a secret word, its plural, or ends in a long secret word (`token`, `password`, `secret`); `code`, `pin` and `otp` match alone or behind a known lead such as `otp`, `verification` or `reset`. Names such as `postcode`, `barcode`, `pinned` and `spinner` still pass.

Behaviour change: a router whose queries take one of these names in their input now fails `assertNoSecretQueries` where it used to pass. Make the procedure a mutation, or list its path in `allow` once checked by hand.
