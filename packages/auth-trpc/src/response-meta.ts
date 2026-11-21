/**
 * Keeps a handed-out CSRF token out of the HTTP caches the app's
 * `responseMeta` could otherwise send it to.
 *
 * `ctx.auth.csrfToken()` marks its response `Cache-Control: no-store`, but
 * tRPC applies the app's `responseMeta` after the procedures ran and lets its
 * headers replace or join that one (the Node adapters write them with
 * `setHeader`, the fetch adapter sets a plain-object header and appends a
 * `Headers` one). A CDN may also read `CDN-Cache-Control` or
 * `Surrogate-Control` instead of `Cache-Control`. An app that caches its
 * public queries there (tRPC's `s-maxage` recipe) would then let a shared
 * cache hand one caller's token to the next. The token is bound to its own
 * session or pre-session, so the next caller cannot use it, but it has
 * leaked all the same.
 *
 * `authResponseMeta(responseMeta)` wraps the app's function: on a response
 * that handed out a token it drops every `Cache-Control`,
 * `Surrogate-Control`, `CDN-Cache-Control` and `*-CDN-Cache-Control` header
 * the app returned (both header forms), so the `no-store` the call set is
 * the only cache rule that goes out, on the Node and fetch adapters. Any
 * other response gets the app's answer unchanged.
 */
import type { ResponseMeta } from '@trpc/server/http';
import { internalsOf } from './context';

type MetaHeaders = NonNullable<ResponseMeta['headers']>;

/**
 * True for a header that tells a cache how long to keep the response:
 * `Cache-Control`, `Surrogate-Control`, `CDN-Cache-Control` (RFC 9213) and
 * the vendor forms ending in `-CDN-Cache-Control` (such as
 * `Cloudflare-CDN-Cache-Control`), which a CDN reads instead of
 * `Cache-Control`.
 */
function isCacheHeader(name: string): boolean {
  const lower = name.toLowerCase();

  return (
    lower === 'cache-control' ||
    lower === 'surrogate-control' ||
    lower === 'cdn-cache-control' ||
    lower.endsWith('-cdn-cache-control')
  );
}

/** True when a procedure of this request returned `ctx.auth.csrfToken()`. */
function handedOut(ctx: unknown): boolean {
  const auth = (ctx as { auth?: unknown } | null | undefined)?.auth;

  return internalsOf(auth)?.tokenHandedOut.value === true;
}

/** The headers without any cache header (`isCacheHeader`), in the form they came in. */
function withoutCacheHeaders(headers: MetaHeaders): MetaHeaders {
  if (headers instanceof Headers) {
    const copy = new Headers(headers);

    const names: string[] = [];

    copy.forEach((_value, name) => {
      if (isCacheHeader(name)) names.push(name);
    });

    for (const name of names) copy.delete(name);

    return copy;
  }

  return Object.fromEntries(Object.entries(headers).filter(([name]) => !isCacheHeader(name)));
}

/**
 * The `responseMeta` to pass to tRPC's handler: yours (or none), with
 * `Cache-Control: no-store` kept on every response that handed out a CSRF
 * token and the `Surrogate-Control`, `CDN-Cache-Control` and
 * `*-CDN-Cache-Control` headers yours returns dropped from it.
 *
 * ```ts
 * createHTTPHandler({ router, createContext, responseMeta: authResponseMeta(myResponseMeta) });
 * ```
 */
export function authResponseMeta<
  TOpts extends { readonly ctx?: unknown },
  TMeta extends ResponseMeta = ResponseMeta,
>(responseMeta?: (opts: TOpts) => TMeta): (opts: TOpts) => TMeta {
  return (opts) => {
    const meta = responseMeta?.(opts) ?? ({} as TMeta);

    if (!handedOut(opts.ctx) || meta.headers === undefined) return meta;

    return { ...meta, headers: withoutCacheHeaders(meta.headers) };
  };
}
