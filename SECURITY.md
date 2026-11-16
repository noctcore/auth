# Security

This is authentication code, so most bugs in it are security bugs. Please report privately.

## Reporting

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/noctcore/auth/security/advisories/new>. It opens a draft advisory that only the
maintainer can see.

If that page says reporting is not enabled, open a regular issue whose entire body is "security
report, need a private channel", with no details, and the maintainer will reply with one.

Include the package and version, what an attacker needs, and what they get. There is no bounty. You
get a reply, a fix released as a patch with a changelog entry that credits you unless you ask
otherwise, and the details published once consumers have had the fix for a day.

## What counts

- A way to authenticate as someone else, keep a session alive past its revocation or expiry, or
  replay a token, code or session.
- A way to learn whether an email address has an account through a flow's response, its timing, or
  its lockout behaviour, where the package claims to hide that.
- A way to lock a legitimate user out for longer than the documented cap.
- A store adapter that fails the conformance suite's guarantees (single-use consumption, no session
  resurrection, every counter key expiring) in a reachable way.
- The published artefacts: a tarball on npm that does not match the tagged source, or a way to make
  the release workflow publish something else.

## What does not count

- Weak configuration chosen by the app (a short session TTL turned into a long one, captcha turned
  off). The defaults are the package's responsibility; overrides are the app's.
- Advisories in the dev toolchain that never ship in a published `dist/`.

## Versioning policy

All `@noctcore/auth*` packages share one version. Weakening a default or removing a check is a
major change. Strengthening a default in a way that may log users out or refuse old input is a
minor change with a "Behaviour change" note. Fixes are patches. During 0.x, pin exact versions.
