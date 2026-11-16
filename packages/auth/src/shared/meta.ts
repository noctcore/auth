/**
 * What a flow knows about the request that triggered it. Frameworks fill it in
 * (the client IP after trust-proxy resolution, see `http/ip.ts`); flows never read
 * a request object themselves.
 */
export interface RequestMeta {
  /** The client IP, already resolved through the trusted proxy hops. */
  readonly ip: string;
  readonly userAgent?: string | undefined;
  /** The request's `Origin` header, used to pick the cookie's SameSite. */
  readonly origin?: string | undefined;
}
