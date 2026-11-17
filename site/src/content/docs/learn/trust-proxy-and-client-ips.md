---
title: Trust proxy and client IPs
description: Counting proxy hops from the right, what X-Forwarded-For spoofing does to rate limits, and how to find your own hop count.
---

## What goes wrong

Every per-IP limit and every audit row depends on the client's IP. Behind a reverse proxy, a load balancer or a CDN, the socket address is the proxy's, and the client's address arrives in `X-Forwarded-For`, a header each proxy appends to. The client can send that header too, with any entries it likes, and the proxies keep them. Read the header from the wrong end and the client picks its own IP: a fresh rate-limit bucket on every request, and any address it likes in your audit trail. Ignore the header behind a proxy and every client has the proxy's address: one bucket for everyone, so one attacker who uses up the login limit blocks everyone's login.

## The rule

**Count hops from the right.** `clientIp` takes the socket address, the header and the number of proxies in front of the app (`trustedHops`). It puts the socket address after the header's entries and steps back that many entries from the right. Entries to the left of the ones your proxies wrote are the client's own words and are never picked. With 0 trusted hops the header is ignored and the socket address is the client IP.

An example, with one proxy in front of the app:

```text
X-Forwarded-For: 192.0.2.66, 198.51.100.23
socket address:  203.0.113.9
```

The client wrote `192.0.2.66` itself. The proxy, at `203.0.113.9`, appended `198.51.100.23`, the address it saw the request come from. With 1 trusted hop the client IP is `198.51.100.23`, which is right. With 0 trusted hops it is `203.0.113.9`, the proxy, shared by every client. With 2 trusted hops it is `192.0.2.66`, the address the client chose.

**Too many hops is as bad as none.** A count higher than the proxies you run reaches into the entries the client wrote, as the last case shows. When the chain is shorter than the count, the leftmost entry is used, and that is the client's too.

**`true` is refused.** `parseTrustProxy` reads a `TRUST_PROXY`-style setting: an all-digit value is a hop count, `false` or an empty value means none, and `true`, which trusts every hop and so lets the client choose its IP, throws a configuration error. Other values, such as an address list, are passed through for frameworks that understand them; `clientIp` itself only counts hops.

**The adapters make the count impossible to forget.** The NestJS and tRPC adapters require `trustedHops` as a whole number from 0 to 16, and read the IP only through `clientIp`, never from the framework's own `req.ip`. In NestJS, `trustedHopsFromEnv(process.env)` reads `TRUST_PROXY`: unset is 0 in development and refused when `NODE_ENV` is `production`, so a deploy that forgot it fails at boot. `configureTrustProxy` sets Express's `trust proxy` to the same count, so `req.ip` in your own code agrees with the flows. A request with no address at all gets the IP `unknown`, a single bucket shared by all such requests.

**What spoofing buys, and what still holds.** The per-IP door limits (login allows 10 attempts per minute from one IP by default) and the per-account-and-IP lockout budget (5 attempts per 15 minutes) are keyed on the IP, so a client that can choose its IP gets fresh ones on every request. The per-account budget (10 attempts per 15 minutes from all sources) is keyed on the address alone, so guessing at one account stays bounded either way. What a spoofed IP buys is the rest: sign-ups and reset requests from one machine past their per-IP limits, password guessing spread thinly over many accounts, and any address it likes in your audit trail and session lists.

**Finding your own hop count.** Count the proxies between the internet and the app that append to `X-Forwarded-For`: a CDN in front of a load balancer in front of the app is two. Then check it rather than trust the diagram. From outside your network, send a request with a made-up `X-Forwarded-For: 192.0.2.1`, log the raw header and the socket address on the server, and confirm that the IP `clientIp` returns is your own public address: not `192.0.2.1`, and not one of your proxies. A proxy that replaces the header instead of appending to it, or one that adds nothing, changes the count, which is why the check matters more than the count of boxes. Run it again after any change to your hosting.

## Where the package and the guide differ

The guide has no page on proxies or `X-Forwarded-For`. Its passwords page warns against strict IP-based rate limits, which block people on shared networks and are bypassed through proxy networks; the package agrees, keeps its per-IP door limits generous and limits guessing per account (see [Brute force and lockout](/auth/learn/brute-force-and-lockout/)). Its sessions page advises against binding a session to an IP, because addresses change on mobile networks and VPNs; the package records the IP with a session for the session list but never refuses a session because the IP changed.

## Further reading

- [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For) on MDN.
- [The trust-proxy rule](/auth/build/nestjs/#the-trust-proxy-rule) in the NestJS guide.
- Attack tests: [A011, spoofing the client IP](https://github.com/noctcore/auth/blob/main/packages/auth/tests/attacks/A011-spoofed-forwarded-ip.test.ts) and [A025, choosing your own client IP through the Nest adapter](https://github.com/noctcore/auth/blob/main/packages/auth-nestjs/tests/attacks/A025-forged-forwarded-for-through-nest.test.ts).
