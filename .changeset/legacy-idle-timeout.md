---
'@noctcore/auth': minor
---

`adoptLegacySessions` now drops a legacy session whose `idleTimeoutMs` is no longer than `session.touchInterval`, by the rule a sign-in applies to an `idleTimeout` function. Before, it was adopted as written: under steady use it was never touched and was refused as idle while its user was active. The drop is reported to `logger` with the user id only, like a malformed record. The check runs on the session manager's lookups; a direct `get` on the wrapper has no touch interval to check against and adopts as before.

**Behaviour change:** a legacy cookie whose record has such an idle timeout is now refused as `session_unknown` on its first request after the upgrade and its cookie is cleared, so that user signs in once more, instead of being signed out within the short idle timeout. The idle timeout is never raised to fit: that would let a legacy session outlive its own record. Records with a longer idle timeout are adopted as before.
