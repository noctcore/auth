---
title: Cookies and desktop shells
description: The __Host- prefix, Secure, HttpOnly and SameSite on the session cookie, and what changes for Electron and other clients outside your own origin.
---

## What goes wrong

The session cookie is the credential, and browsers hand cookies around more freely than people expect. A sibling subdomain, such as a marketing site or a host for user content, can set a cookie for the parent domain that the browser then sends to your app, shadowing or overwriting the real one (cookie tossing). Script injected into a page can read a cookie and send it away. A cookie sent over plain HTTP can be read on the network. And another site can make the browser send requests with your cookie attached (see [CSRF](/auth/learn/csrf/)).

Desktop shells add a twist. An Electron app that serves its pages from its own scheme (`app://`) talks to your API from an origin that is not yours, so its requests are cross-site, and the defaults that protect the web app also keep the cookie away from the shell.

## The rule

**`__Host-` whenever the cookie is Secure.** The session cookie is named `__Host-session` by default. A browser accepts a `__Host-` cookie only if it is `Secure`, has `Path=/` and has no `Domain`, so no subdomain can set or overwrite it. The trusted-device cookies follow the same rule (`__Host-device`, and `__Host-two-factor-device` with the two-factor plugin), and so do the NestJS and tRPC adapters' CSRF cookies (`__Host-csrf` and `__Host-presession`).

**`Secure` by default, `HttpOnly` always.** `session.cookie.secure` is on by default. Turn it off only for plain-HTTP local development; that also drops the prefix. The session cookie is always `HttpOnly`, so page script cannot read it. That keeps the token out of an injected script's hands; it does not stop that script from sending requests as the user while the page is open.

**`SameSite=Lax` by default.** Cross-site subrequests and form posts carry no session cookie, while a link into the site still does. With the defaults, the session cookie is written as:

```http
Set-Cookie: __Host-session=<token>; Path=/; HttpOnly; Secure; SameSite=Lax
```

A session without "remember me" gets no `Max-Age`, so the browser drops it when it closes, and the server ends it after 24 hours by default however active it is. With "remember me", `Max-Age` is the session's remaining life, 30 days by default.

**Desktop shells: `SameSite` per origin, and `None` only with `Secure`.** `session.cookie.sameSite` also takes a function of the request's `Origin`, so the web app keeps `Lax` while a shell on its own scheme gets `None`:

```ts
session: {
  cookie: {
    sameSite: (origin) => (origin === 'app://desktop' ? 'none' : 'lax'),
  },
},
```

The trusted-device cookies get the same answer, and so do the NestJS and tRPC adapters' CSRF and pre-session cookies and the blank cookie they write to clear a refused session: every cookie that has to travel with the session cookie takes its `SameSite` from the same function, through the core's `resolveSameSite`. `None` on a cookie that is not `Secure` is refused with a configuration error when a cookie is built (usually at the first sign-in), not when `createAuth` starts. The origin comes from the request's `Origin` header, which a client that is not a browser can set to anything; that only changes the attributes of its own cookie.

**`None` needs the rest of the CSRF defence.** A cookie with `SameSite=None` is sent on requests other sites start too, so the origin it is meant for has to be checked. A shell's requests arrive as `cross-site`, which `verifyFetchSite` refuses by default. List the shell's exact origin in the adapter's `csrf.crossSiteOrigins` (or pass `origin` and `crossSiteOrigins` to `verifyFetchSite` yourself): that origin then passes the `Origin` check, and its `cross-site` requests pass the `Sec-Fetch-Site` check, while every other cross-site request is still refused. The signed double-submit token is still required. [CSRF](/auth/learn/csrf/) covers the trade-off.

```ts
createAuthContext({
  auth,
  trustedHops,
  csrf: {
    secrets: [csrfSecret],
    allowedOrigins: ['https://app.example'],
    crossSiteOrigins: ['app://desktop'],
  },
});
```

`AuthModule.forRoot` takes the same `csrf.crossSiteOrigins`. Entries are matched exactly, scheme, host and port; a wildcard, `null` or anything that is not an origin stops the app at boot. The list is empty by default, so nothing changes until you name an origin.

**Limits for shells and other clients.**

- Whether a shell's engine keeps and sends `SameSite=None` cookies to your API depends on the engine and its settings. Test the shell against the adapter before relying on it, or load your web origin in the shell, where it is an ordinary same-site browser page and needs neither `None` nor `crossSiteOrigins`.
- `__Host-`, `Secure`, `HttpOnly` and `SameSite` are instructions to a browser. A client that is not a browser, such as a native HTTP library or a command-line tool, keeps cookies wherever its library does and enforces none of them. It must also send an `Origin` the allowlist names, because `verifyRequestOrigin` refuses an unsafe request without one.

## Where the package and the guide differ

The guide asks for `HttpOnly` and `Secure`, and says `SameSite` mitigates many cross-site attacks but is not a complete solution on its own. The package sets all three by default and adds the `__Host-` prefix, which the guide does not mention, and pairs `SameSite` with the CSRF checks for the same reason the guide gives. The guide does not cover desktop shells; the per-origin `SameSite` and the `Origin` allowlist exist for them.

## Further reading

- [Browser client-side storage](https://auth.pilcrowonpaper.com/browser-client-side-storage) in Pilcrow's auth guide.
- [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie) on MDN, including the cookie prefixes.
- Attack tests: [A018, cookie tossing and reading the session cookie from script](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A018-cookie-tossing-and-script-theft.test.ts), [A008, cross-site request forgery](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A008-csrf-cross-site-post.test.ts), [A026, through the Nest adapter](https://github.com/noctcore/auth/blob/main/packages/auth-nestjs/tests/attacks/A026-csrf-origin-through-nest.test.ts), [A033, through the tRPC adapter](https://github.com/noctcore/auth/blob/main/packages/auth-trpc/tests/attacks/A033-csrf-through-trpc.test.ts), and the cross-site origin allowlist in [A079, through the Nest adapter](https://github.com/noctcore/auth/blob/main/packages/auth-nestjs/tests/attacks/A079-cross-site-origin-allowlist-through-nest.test.ts) and [A080, through the tRPC adapter](https://github.com/noctcore/auth/blob/main/packages/auth-trpc/tests/attacks/A080-cross-site-origin-allowlist-through-trpc.test.ts).
