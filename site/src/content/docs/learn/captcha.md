---
title: Captcha
description: Where the captcha check sits, why the verifier checks the hostname and the action, and why a provider outage counts as a failure.
---

## What goes wrong

Rate limits count requests per IP, per account and per address. A bot farm with many addresses can stay under all of them: credential stuffing at login, mass sign-ups, floods of reset mail. A captcha makes each request cost a solved challenge, but the token it produces is just a string the client sends, and the checks around it decide whether it costs anything. A token solved on the attacker's own page that embeds your public sitekey, or on a cheap form of your own app, still verifies at the provider. And a server that lets requests through whenever the provider does not answer has no captcha during an outage, which an attacker can wait for or try to cause.

## The rule

**Checked first, on the doors bots target.** When `captcha` is configured, login, sign-up and the password reset request check it before anything else: before the door's rate limit, before any store call and before any password hash. Plugins can call the same check through their context. Every verdict is counted in the `auth_captcha` metric by door and verdict, and a refused login is audited as a `login.failure`.

**Three verdicts, two refusals.** A verifier answers `pass`, `reject` or `unavailable`. Both refusals stop the request; they differ only in the code the client sees. `captcha_failed` means the challenge was not solved; `captcha_unavailable` means the provider could not answer, so the app can tell the user to try again later instead of telling them they failed.

**The Turnstile verifier checks where and for what the token was solved.** `turnstile(options)` sends the token, and the client IP when there is one, to Cloudflare's siteverify endpoint. With `expectedHostnames`, a token solved on any other hostname is rejected. With `checkAction: true`, the widget's `action` must equal the door name (`login`, `register` or `password-reset`), so a token solved on the sign-up form cannot be spent at login. **Both checks are off unless you set them, and without them any successful token for your sitekey passes: set both.** The IP sent along is the one [Trust proxy and client IPs](/auth/learn/trust-proxy-and-client-ips/) describes, so get the hop count right first.

**An outage is a failure.** A network error, no answer within 5000 ms (the default `timeoutMs`), an answer whose status is not a success, a body without a boolean `success`, and Cloudflare's own `internal-error` all count as `unavailable`. Any other failure Cloudflare reports, such as a token that expired or was already used, is `reject`. A missing token, or one longer than 2048 characters, is rejected without calling the provider.

**Every verdict says why.** `turnstile()` returns a verifier with a second method, `check(token, context)`, that verifies exactly like `verify` and returns the verdict with its cause, and the optional `onResult` option gets the same outcome for every call: a pass, a refusal and an outage. Use it to log or count, so an outage shows apart from a misconfiguration such as a wrong secret. An outcome holds the `verdict`, the `door`, the `errorCodes` siteverify answered with (empty when it was not called) and a `reason`:

| Verdict | `reason` | When |
| --- | --- | --- |
| `unavailable` | `timeout` | No answer within `timeoutMs`, while connecting or reading the body |
| `unavailable` | `network-error` | The request or the body read failed (DNS, TLS, a reset connection) |
| `unavailable` | `http-status` | An answer whose status is not a success; `status` holds the code |
| `unavailable` | `unparsable-body` | A success status with a body that is not JSON or has no boolean `success` |
| `unavailable` | `provider-error` | Cloudflare reported `internal-error` |
| `reject` | `missing-token` | No token; the provider was not called |
| `reject` | `token-too-long` | Longer than the limit above; the provider was not called |
| `reject` | `provider-refused` | Any other failure siteverify reported: see `errorCodes` (`timeout-or-duplicate` for an expired or reused token, `invalid-input-secret` for a wrong secret) |
| `reject` | `hostname-mismatch` | Solved on a hostname outside `expectedHostnames` |
| `reject` | `action-mismatch` | Solved for another door, with `checkAction` |

An outcome never carries the token or the secret. The hook is not awaited and cannot change the verdict: the outcome it gets is frozen, and a hook that throws or rejects is reported to the verifier's `logger` option (silent by default) with the error message only. The `unavailable` reasons are a shared type, `UnavailableReason`, meant for every provider check the package makes.

**Why the captcha fails closed when the breach check fails open.** The [breach check](/auth/learn/passwords/) judges a password the user chose; skipping it during an outage accepts one password that might have leaked, and the outage is logged. The captcha is a gate against automated traffic; skipping it during an outage opens the gate to exactly that traffic, at a moment an attacker can choose. The cost is real and the package accepts it: while the provider is down, nobody can sign in, sign up or request a reset on an app with a captcha configured.

**What it does not do.** A captcha raises the price of a request; it does not stop people or paid solving services from solving challenges, so the rate limits and the lockout still do the counting. The verifier does not track tokens itself: it relies on siteverify to refuse a token that expired or was already used.

## Where the package and the guide differ

The guide has no page on captchas. Its passwords page warns against strict IP-based rate limits, which block people on shared networks and are bypassed through proxy networks. The package agrees: its per-IP door limits are generous (see [Brute force and lockout](/auth/learn/brute-force-and-lockout/)), and a captcha is the optional per-request cost for the doors where proxy networks are the problem.

## Further reading

- [Server-side validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/) in Cloudflare's Turnstile documentation.
- [Passwords](https://auth.pilcrowonpaper.com/passwords) in Pilcrow's auth guide.
- Attack test: [A077, passing a captcha with a token solved elsewhere, or while the provider is down](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A077-captcha-token-from-elsewhere-or-an-outage.test.ts).
