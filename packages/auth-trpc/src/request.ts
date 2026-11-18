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
}

/** Where the adapter writes `Set-Cookie` headers. */
export type CookieWriter = (spec: CookieSpec) => void;

/** The fetch adapter's context options, as far as the adapter reads them. */
export interface FetchContextInput {
  readonly req: {
    readonly method: string;
    readonly headers: { get(name: string): string | null };
  };
  readonly resHeaders: { append(name: string, value: string): void };
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
}

export function fromFetch(
  input: FetchContextInput,
  remoteAddress: string | undefined,
): { request: HttpRequest; write: CookieWriter } {
  const header = (name: string): string | undefined => input.req.headers.get(name) ?? undefined;

  return {
    request: {
      method: input.req.method,
      header,
      forwardedFor: header('x-forwarded-for'),
      remoteAddress,
    },
    write: (spec) => input.resHeaders.append('set-cookie', serializeCookie(spec)),
  };
}

export function fromNode(input: NodeContextInput): { request: HttpRequest; write: CookieWriter } {
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
    },
    // Adds a header, keeping the cookies already set on the response.
    write: (spec) => {
      const previous = res.getHeader('set-cookie');

      const list =
        previous === undefined ? [] : Array.isArray(previous) ? previous : [String(previous)];

      res.setHeader('set-cookie', [...list, serializeCookie(spec)]);
    },
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
