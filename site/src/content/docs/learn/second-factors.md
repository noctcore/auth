---
title: Second factors
description: What a second factor has to resist to be worth having, and how the two-factor plugin keeps the password, the mailbox and the recovery path from going around it.
---

## What goes wrong

A second factor is meant to stop someone who has the password. It only does if every way into the account asks for it. The usual failures are not in the code math but around it:

- a six-digit code that stays valid for a minute can be **replayed**, by whoever watched it typed or read it from a log, and two requests carrying it at once can both pass a check-then-write guard;
- a million codes, three of them valid at any moment, are **guessed** in hours by a botnet when the only limit is per IP;
- the **mailbox beats the phone**: a password reset that writes the new password on the link alone, or turns the factor off, hands the account to whoever controls the email;
- **another flow forgets it**: sign-up with auto-login, a magic link, a re-issued session after a password change, any path that mints a session without asking;
- a **stolen session turns it off**, or prints new recovery codes, because the settings page only asks for the password;
- the **recovery codes** are the weakest part: they skip the phone, they live on paper or in a password manager, and they are what an attacker with the password goes after.

## The rule

**TOTP, by the RFC, on the server clock.** Codes are RFC 6238 (HMAC-SHA-1, 30-second steps, six digits), so every authenticator app works; the test suite checks the RFC test vectors. One step of drift is accepted either side, never more. The secret is 160 random bits from the CSPRNG, and it is stored only as the ciphertext your `SecretCipher` returns: the plugin never holds a key, and the user id is passed to the cipher so it can bind each ciphertext to its row.

**A code works once.** The store keeps the last accepted time step, and a code is accepted only if its step moves that value forward, by a compare-and-set in the store. A replayed code, an older code after a newer one, and the slower of two simultaneous requests with the same code are all refused (attacks A036, A037). The spent step is shared by every door: a code used at login cannot then step up a session or reset a password.

**Guesses are counted per account, before the comparison.** Every code check, TOTP or recovery code, at login, step-up, enrollment, reset, password change or email change, first reserves an attempt in one budget per user, from every IP together: 5 per 15 minutes. Spending it locks the factor with the same capped backoff as the password lockout (5 minutes, then 15, then 45, at most an hour). A locked factor refuses even the right code, and answers exactly like a wrong one. A login challenge also dies after 5 codes, so every new batch of guesses costs a correct password first (A038).

**Enrollment is confirmed by a code.** Starting it needs a fresh password proof. The new secret stays pending until a code from it is typed, within 10 minutes, and confirming it is a compare-and-set on that very secret, so a code for a secret that was replaced meanwhile never activates the new one (A046). Turning the factor on mails the owner.

**Recovery codes are the weak link, so they get the same care as passwords.** Ten codes of 50 bits each from the CSPRNG, shown once, stored only as an HMAC keyed by the server secret and bound to the user. A code is spent by one atomic delete: of many simultaneous uses, exactly one gets it (A041). Generating a new set replaces the old one in one write, and needs a step-up. Every guess spends the factor budget, so at about 2^47 guesses per hit there is nothing to brute force (A042). Each use mails the owner how many codes are left. The HMAC key is derived from the auth `secret`, so **rotating the secret voids every recovery code**: after a rotation, ask every user with a factor to generate a new set (their `status` still counts the old rows, which no longer match anything).

**The mailbox is not a second factor.** A password reset of an account with a factor demands a TOTP code or a recovery code before the new password is written, and counts it in the same budget. The new password is checked against the policy first, so a refused password spends no code. The reset never touches the factor: the next login is still challenged (A044).

**Every session goes through the check.** The core mints sessions in one place, `issueSession`, and runs the plugin's hook on every call. The hook refuses a session for any user with a confirmed factor (or one the app requires a factor of) unless the session comes from the plugin's own challenge, or is one of the core's re-issues after a password change, a re-authentication, an email verification, a confirmed email change or "sign out other sessions". A re-issue goes through only with a session the core itself read from the store just before the flow revoked anything: live (not revoked, not expired or idle, on the current epoch) and the same user's. A revoked, expired, hand-built or copied session object is refused. A plain password login and sign-up with auto-login are refused (A048), and so is any other `via` a plugin or app code names. What the check cannot judge is code that claims the factor was checked: plugins and callers of `auth.context` are trusted code, and one that issues with the plugin's own label, `second-factor`, gets a session. A user the app requires a factor of who has none yet gets an enrollment challenge instead of a session.

**Sensitive actions need a recent proof in this session.** A step-up is a code proved in one session, stored under that session's id with an expiry on the server clock (10 minutes by default). Turning the factor off, new recovery codes, and a password change or an email change request without a code all need one, together with fresh authentication. Without the email change rule, a password alone could move the account to a new address and reset the factor's protection from there (A052). A session re-issued by a password re-entry starts without one, another session of the same user has none, and a password alone never makes one (A045, A049).

**A trusted device skips the code, never the password.** "Remember this device" sets an opaque random token in a cookie and stores only its SHA-256, with an expiry (30 days by default) and the user's revocation epoch. It counts only after a correct password, at the challenge. A password change, a reset, an email change or its revert, and "sign out everywhere" bump the epoch, which voids every device trusted before, and also delete the rows (A043). A device never records a step-up.

**A revert takes back a factor added since the change.** When the owner reverts an email change, the plugin removes a factor (pending or confirmed) enrolled at or after the moment of the change, with its recovery codes, so the owner's password reset is not gated by a factor the intruder added. A factor from before the change stays.

**Refusals look alike.** The factor is only looked at after a correct password, so a wrong password answers and works the same for accounts with and without one. Behind a challenge, an unknown, spent or foreign challenge, a wrong code, a replayed code and a locked factor all answer `invalid_second_factor`; the reason goes to the audit row only (A050). An unknown challenge and a user without a factor still decrypt a stand-in secret and compute every code in the window, so they cost what a wrong code costs; the test suite checks this by counting store and cipher calls, not by timing (A047).

## What it does not do

- It does not stop real-time phishing. A page that relays the password and the code to the real site as the user types them gets a session. Only origin-bound factors (WebAuthn and passkeys) stop that, and they are not part of this plugin yet.
- It does not protect a session that was already stolen. The cookie is the credential once issued; the step-up only guards the actions that need it.
- A challenge is bound to the browser by its user agent, which an attacker who steals the challenge can copy. The binding stops a challenge from being used by accident elsewhere; the real limits are the five-minute lifetime and the five codes.
- It cannot keep the TOTP secret safe from a server that is fully compromised: whoever runs code with your cipher's key can decrypt it.
- It does not stop someone with the password from enrolling a factor for a user you require one of who has not enrolled yet: for that user the password is the only credential, so the enrollment challenge accepts it. The owner is mailed when the factor goes on. Enroll required users early, or require a factor only of users who have one.
- It does not stop a stolen session from locking the owner's factor. Step-up checks a code from inside a signed-in session, and wrong codes spend the same per-account budget as the login challenge, so whoever holds a session can lock the factor, and with it the owner's challenge, for up to an hour at a time (the password lockout's cap), again and again while the session lives. Revoking that session ends it.
- Two proofs sent at once on one challenge, a TOTP code and a recovery code say, can both be checked before either spends the challenge. Only one gets the session; if the other was a recovery code, that code is spent anyway.

## Where the package and the guide differ

The guide's MFA page asks for RFC 6238 codes from a 160-bit random secret, a confirmation code before the secret is active, a new secret invalidating the old one, throttling after about 5 failures, and one or more single-use recovery codes. The plugin does all of that, and differs in a few places:

- **Replay.** The guide validates a code by generating one and comparing; it does not ask that a code be refused the second time. The plugin stores the last accepted step and refuses anything at or before it, atomically.
- **How recovery codes are stored.** The guide suggests a password hash such as Argon2id. The plugin uses an HMAC keyed by the server secret: the codes are 50 random bits, not something a person chose, so a slow hash adds little, and with the key outside the database a leaked table cannot be used to test guesses at all. The plugin issues ten codes, where the guide says one or more.
- **Telling the owner.** The guide suggests telling the user to change their password after the throttle trips. The plugin does not mail on a factor lock (it writes an audit row); it mails when the factor is turned on or off and when a recovery code is used.
- **Resets.** The guide leaves resets to the app. The plugin makes a reset of a two-factor account demand the factor, because otherwise the mailbox alone would beat it.

## Further reading

- [Multi-factor authentication](https://auth.pilcrowonpaper.com/mfa) in Pilcrow's auth guide.
- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238) and [RFC 4226: HOTP](https://www.rfc-editor.org/rfc/rfc4226).
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html).
