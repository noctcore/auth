/**
 * Keeps a handed-out CSRF token out of every HTTP cache.
 *
 * `ctx.auth.csrfToken()` marks its response `Cache-Control: no-store`, but
 * tRPC applies the app's `responseMeta` after the procedures ran and lets its
 * headers replace that one (the Node adapters write them with `setHeader`,
 * the fetch adapter sets a plain-object header). An app that caches its
 * public queries there (tRPC's `s-maxage` recipe) would then let a shared
 * cache hand one caller's token to the next. The token is bound to its own
 * session or pre-session, so the next caller cannot use it, but it has
 * leaked all the same.
 *
 * `authResponseMeta(responseMeta)` wraps the app's function: on a response
 * that handed out a token it drops every `Cache-Control` the app returned,
 * so the `no-store` the call set is what goes out, on every adapter. Any
 * other response gets the app's answer unchanged.
 */
import type { ResponseMeta } from '@trpc/server/http';
import { internalsOf } from './context';

type MetaHeaders = NonNullable<ResponseMeta['headers']>;

const CACHE_CONTROL = 'cache-control';

/** True when a procedure of this request returned `ctx.auth.csrfToken()`. */
function handedOut(ctx: unknown): boolean {
  const auth = (ctx as { auth?: unknown } | null | undefined)?.auth;

  return internalsOf(auth)?.tokenHandedOut.value === true;
}

/** The headers without any `Cache-Control`, in the form they came in. */
function withoutCacheControl(headers: MetaHeaders): MetaHeaders {
  if (headers instanceof Headers) {
    const copy = new Headers(headers);

    copy.delete(CACHE_CONTROL);

    return copy;
  }

  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => name.toLowerCase() !== CACHE_CONTROL),
  );
}

/**
 * The `responseMeta` to pass to tRPC's handler: yours (or none), with
 * `Cache-Control: no-store` kept on every response that handed out a CSRF
 * token, whatever yours returns.
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

    return { ...meta, headers: withoutCacheControl(meta.headers) };
  };
}
