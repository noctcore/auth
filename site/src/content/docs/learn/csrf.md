---
title: CSRF
description: Why a cookie session needs a defence against other sites, and the three layers the package offers.
---

## What goes wrong

Browsers attach cookies to every request for a site, including requests another site triggers: a hidden form that posts to your `/logout` or `/change-email`, or a link to a URL that changes state. The browser's same-origin policy stops the other site from reading the response, but some requests (a `GET`, a form `POST`) are sent anyway, and the harm is in the request, not the response.

## The rule

**Never change state on `GET`.** A redirect or an image tag can trigger a `GET` from anywhere. Every flow that changes something is meant for `POST` or another unsafe method.

**`SameSite=Lax` on the session cookie.** The browser leaves the cookie off cross-site subrequests and cross-site form posts, while still sending it when a user follows a link to your site. This is the default and stops most attacks on its own, but not all: sibling subdomains count as the same site, and very old browsers ignore the attribute.

**Check where the request came from.** For an app served from one origin, `verifyFetchSite` refuses any unsafe request whose `Sec-Fetch-Site` header is missing or not `same-origin`. Browsers set that header themselves and page scripts cannot change it. Apps that also serve a desktop shell (an `app://` origin) or trusted sibling subdomains use `verifyRequestOrigin` with an explicit allowlist instead, refusing requests without an `Origin`.

**Let in only the cross-site origins you name.** A shell's requests say `Sec-Fetch-Site: cross-site`, like an attack's. The NestJS and tRPC adapters accept them only from origins listed in `csrf.crossSiteOrigins` (empty by default), matched exactly with no wildcards; the core's `verifyFetchSite` takes the same list with the request's `origin`. A listed origin is trusted as much as your own: a page that can run script there can send requests the fetch-metadata check no longer stops, and only the double-submit token, which stays on, still stands in its way. List a custom scheme only the shell serves, never a web origin you do not control, and give the cookies the shell needs `SameSite=None` through `session.cookie.sameSite` (see [Cookies and desktop shells](/auth/learn/cookies-and-desktop-shells/)); the adapters' CSRF cookies follow it.

**A signed double-submit token.** `createCsrfToken` mints a random nonce with an HMAC over it and a binding, which the page reads from a cookie and echoes in a header. `verifyCsrfToken` checks that cookie and header match, that the nonce is 32 hex characters and that the HMAC is valid for the current binding. The MAC input is length-prefixed (`csrf:<binding length>:<binding>:<nonce>`), so no binding and nonce pair can be read as another. The HMAC stops a sibling origin that can write cookies from planting a pair of its own; the binding stops a token minted for one session from working in another. Secrets must be at least 32 bytes, should be used for CSRF only (not the auth secret), and can be rotated with a list of accepted previous secrets.

**A binding before sign-in too.** Signed in, bind to the session. Signed out, do not bind every visitor to one shared value, or a token pair minted in the attacker's browser works in the victim's. Give each logged-out browser its own random pre-session id in an HttpOnly cookie and bind to that; the example app issues it with the first token and renews it on logout.

The example app combines all three; see `examples/basic` in the repository.

## Where the package and the guide differ

The guide's first recommendation is the `Sec-Fetch-Site` check, then `Origin`, then tokens for legacy browsers. The package offers all three, and its example app applies the stricter combination: the Origin allowlist always, `Sec-Fetch-Site` whenever the browser sends it, and the token on top, because apps that serve a desktop shell send requests that are cross-site by definition and need the allowlist anyway.

## Further reading

- [Cross-site request forgery](https://auth.pilcrowonpaper.com/csrf) in Pilcrow's auth guide.
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Attack tests for the cross-site origin allowlist: [A078, through the Nest adapter](https://github.com/noctcore/auth/blob/main/packages/auth-nestjs/tests/attacks/A078-cross-site-origin-allowlist-through-nest.test.ts) and [A079, through the tRPC adapter](https://github.com/noctcore/auth/blob/main/packages/auth-trpc/tests/attacks/A079-cross-site-origin-allowlist-through-trpc.test.ts).
