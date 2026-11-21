/**
 * One request and its response, as the adapter reads and writes them,
 * whichever tRPC adapter the server runs on.
 *
 * - The fetch adapter (`fetchRequestHandler`: Bun, Deno, edge runtimes, Next
 *   route handlers) hands over a `Request` and the `Headers` of the response.
 * - The Node adapters (standalone, Express, nestjs-trpc on Express) hand over
 *   the Node request and response.
 *
 * The client IP always comes from the core's `clientIp`, through the
 * configured trusted proxies (and the trusted client IP header, when one is
 * set); no framework's own IP guess (`req.ip` and its trust-proxy setting) is
 * read. A fetch `Request` has
 * no socket, so on that adapter the server passes the peer address itself.
 */
import type { IncomingHttpHeaders } from 'node:http';
import { clientIp, serializeCookie, type CookieSpec, type RequestMeta } from '@noctcore/auth';
import type { ResolvedOptions } from './options';

/** What the adapter reads from a request. */
export interface HttpRequest {
  readonly method: string;
  header(name: string): string | undefined;
  readonly forwardedFor: string | readonly string[] | undefined;
  readonly remoteAddress: string | undefined;
  /** The procedure calls tRPC parsed, or none when the adapter did not say. */
  readonly calls: RequestCalls['calls'];
  /** True when tRPC said the request calls a subscription (its response is a stream). */
  readonly subscription: boolean;
}

/** Where the adapter writes `Set-Cookie` headers. */
export type CookieWriter = (spec: CookieSpec) => void;

/**
 * What tRPC parsed from the request before it built the context (its
 * `info`), as far as the adapter reads it: the path of each procedure called
 * and, when tRPC found it, the procedure with its meta.
 */
export interface RequestCalls {
  readonly calls: readonly {
    readonly path: string;
    readonly procedure?: { readonly _def?: { readonly meta?: unknown } } | null | undefined;
  }[];
  /** The type of the procedures called: `query`, `mutation`, `subscription` or `unknown`. */
  readonly type?: string | undefined;
}

/** Sets one response header (`Cache-Control`), replacing any value it had. */
export type HeaderWriter = (name: string, value: string) => void;

/** The fetch adapter's context options, as far as the adapter reads them. */
export interface FetchContextInput {
  readonly req: {
    readonly method: string;
    readonly headers: { get(name: string): string | null };
  };
  readonly resHeaders: {
    append(name: string, value: string): void;
    /** Present on a real `Headers`; used so a header is set once, not appended. */
    set?(name: string, value: string): void;
  };
  readonly info?: RequestCalls | undefined;
}

/** The Node adapters' context options, as far as the adapter reads them. */
export interface NodeContextInput {
  readonly req: {
    readonly method?: string | undefined;
    readonly headers: IncomingHttpHeaders;
    readonly socket?: { readonly remoteAddress?: string | undefined } | undefined;
  };
  readonly res: {
    getHeader(name: string): number | string | string[] | undefined;
    setHeader(name: string, value: number | string | readonly string[]): unknown;
  };
  readonly info?: RequestCalls | undefined;
}

export function fromFetch(
  input: FetchContextInput,
  remoteAddress: string | undefined,
): { request: HttpRequest; write: CookieWriter; setHeader: HeaderWriter } {
  const header = (name: string): string | undefined => input.req.headers.get(name) ?? undefined;

  return {
    request: {
      method: input.req.method,
      header,
      forwardedFor: header('x-forwarded-for'),
      remoteAddress,
      calls: input.info?.calls ?? [],
      subscription: input.info?.type === 'subscription',
    },
    write: (spec) => input.resHeaders.append('set-cookie', serializeCookie(spec)),
    setHeader: (name, value) => {
      const { resHeaders } = input;

      if (resHeaders.set) resHeaders.set(name, value);
      else resHeaders.append(name, value);
    },
  };
}

export function fromNode(input: NodeContextInput): {
  request: HttpRequest;
  write: CookieWriter;
  setHeader: HeaderWriter;
} {
  const { req, res } = input;

  return {
    request: {
      method: req.method ?? 'GET',
      header: (name) => {
        const value = req.headers[name];

        return Array.isArray(value) ? value[0] : value;
      },
      forwardedFor: req.headers['x-forwarded-for'],
      remoteAddress: req.socket?.remoteAddress,
      calls: input.info?.calls ?? [],
      subscription: input.info?.type === 'subscription',
    },
    // Adds a header, keeping the cookies already set on the response.
    write: (spec) => {
      const previous = res.getHeader('set-cookie');

      const list =
        previous === undefined ? [] : Array.isArray(previous) ? previous : [String(previous)];

      res.setHeader('set-cookie', [...list, serializeCookie(spec)]);
    },
    setHeader: (name, value) => res.setHeader(name, value),
  };
}

export function requestMeta(
  request: HttpRequest,
  trust: Pick<ResolvedOptions, 'trustedHops' | 'clientIpHeader'>,
): RequestMeta {
  const origin = request.header('origin');

  return {
    ip:
      clientIp({
        remoteAddress: request.remoteAddress,
        forwardedFor: request.forwardedFor,
        trustedHops: trust.trustedHops,
        trustedHeader:
          trust.clientIpHeader === undefined ? undefined : request.header(trust.clientIpHeader),
      }) ?? 'unknown',
    userAgent: request.header('user-agent') ?? '',
    ...(origin === undefined ? {} : { origin }),
  };
}
