---
'@noctcore/auth': patch
---

The two-factor plugin can accept recovery codes carried over from an app's earlier scheme. A migration script stores each user's unused hashes with the new `importedRecoveryCodeHashes` helper (it marks them as imported), and the new `importedRecoveryCodes: { hash }` option tells the plugin how a typed code was hashed (any deterministic hash, such as an unsalted SHA-256). An imported code is spent once, by the same atomic delete and in the same factor budget as the plugin's own codes, and its audit row carries `imported: true`. When one passes the login challenge, the user's whole set is replaced with new codes, which `verifyChallenge` returns in `recoveryCodes` to show once. Without the option nothing imported is accepted, and nothing changes for apps that do not use it. Codes hashed with a per-code salt cannot be looked up; the Build guide describes re-enrolling those users.
