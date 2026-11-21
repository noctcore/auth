/**
 * Keeps the cache headers of the app's `responseMeta` off a response that
 * handed out a CSRF token.
 *
 * `ctx.auth.csrfToken()` marks its response `Cache-Control: no-store`, but
 * tRPC applies the app's `responseMeta` after the procedures ran and lets its
 * headers replace or join that one (the Node adapters write them with
 * `setHeader`, the fetch adapter sets a plain-object header and appends a
 * `Headers` one). A CDN or proxy may also read its own header instead of
 * `Cache-Control`. An app that caches its
 * public queries there (tRPC's `s-maxage` recipe) would then let a shared
 * cache hand one caller's token to the next. The token is bound to its own
 * session or pre-session, so the next caller cannot use it, but it has
 * leaked all the same.
 *
 * `authResponseMeta(responseMeta)` wraps the app's function: on a response
 * that handed out a token it drops these headers the app returned, in either
 * form and any case: `Cache-Control`, `Surrogate-Control`,
 * `CDN-Cache-Control` and every `*-CDN-Cache-Control`, `X-Accel-Expires`
 * and `Edge-Control`. The `no-store` the call set stays. A proxy-specific
 * cache header outside this list is not touched; keep such rules off the
 * token route. Any other response gets the app's answer unchanged.
 */
import type { ResponseMeta } from '@trpc/server/http';
import { internalsOf } from './context';

type MetaHeaders = NonNullable<ResponseMeta['headers']>;

/**
 * The cache headers `authResponseMeta` drops: `Cache-Control`,
 * `Surrogate-Control`, `CDN-Cache-Control` (RFC 9213), `X-Accel-Expires`
 * (nginx `proxy_cache`, which reads it before `Cache-Control`) and
 * `Edge-Control` (Akamai). The vendor forms ending in `-CDN-Cache-Control`
 * (such as `Cloudflare-CDN-Cache-Control`) go too.
 */
const CACHE_HEADERS = new Set([
  'cache-control',
  'surrogate-control',
  'cdn-cache-control',
  'x-accel-expires',
  'edge-control',
]);

function isCacheHeader(name: string): boolean {
  const lower = name.toLowerCase();

  return CACHE_HEADERS.has(lower) || lower.endsWith('-cdn-cache-control');
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
 * The `responseMeta` to pass to tRPC's handler: yours (or none). On every
 * response that handed out a CSRF token it drops these headers yours
 * returns: `Cache-Control`, `Surrogate-Control`, `CDN-Cache-Control` and
 * every `*-CDN-Cache-Control`, `X-Accel-Expires` and `Edge-Control`, so the
 * call's `Cache-Control: no-store` stays. A proxy-specific cache header
 * outside this list is not touched; keep such rules off the token route.
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
