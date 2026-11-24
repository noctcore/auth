---
'@noctcore/auth': patch
---

With a second-factor plugin, the `beforeSessionCreate` hooks now also run after a correct password, before the challenge is handed out (`via: 'password'`, `beforeChallenge: true`). An account a hook refuses gets the refusal's code (`invalid_credentials` by default) and a `login.failure` row with the hook's reason, and no challenge, so it never learns its password was right. The hooks run again for the session (`via: 'second-factor'`), as before. Logins that get no challenge are unchanged.

An app's own re-issue of a session can now pass the two-factor plugin. Issue it with your own `via` and the caller's session as `inherit`: the core checks that the session is live and the same user's (or takes the object the new `PluginContext.confirmLiveSession` returned before your flow ended sessions) and refuses it as `session_expired` otherwise; that check is new for every `via` of your own that passes an `inherit`. The `beforeSessionCreate` hooks see it as `reissueOf`. For a user with a confirmed factor, the plugin lets it through only when that session began after the factor's enrollment window closed, or holds an open step-up; without `inherit` it is refused as before. The core's own re-issues behave as before.
