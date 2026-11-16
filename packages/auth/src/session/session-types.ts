/** The session manager's options and the answers it gives. */
import type { StoredSession } from '../ports/stores';
import type { Duration } from '../shared/duration';
import type { RequestMeta } from '../shared/meta';

/** Anything with a zod-style `parse`: validates attributes read back from the store. */
export interface AttributeSchema<A> {
  parse(value: unknown): A;
}

export interface SessionOptions<A> {
  /** Lifetime of a session without "remember me". Default 24 h. */
  readonly absoluteTtl?: Duration;
  /** Lifetime with "remember me". Default 30 d. */
  readonly rememberMeTtl?: Duration;
  /** Idle limit, fixed or per session. Default 30 min, or 7 d with "remember me". */
  readonly idleTimeout?: Duration | ((context: { rememberMe: boolean; attributes: A }) => Duration);
  /** Minimum time between two `lastActiveAt` writes. Default 60 s. */
  readonly touchInterval?: Duration;
  /** Oldest sessions beyond this are evicted on mint. Default 10; null for no cap. */
  readonly maxPerUser?: number | null;
  /** Validates the attributes on every read. Required when attributes are declared. */
  readonly attributes?: AttributeSchema<A>;
}

export type SessionRefusal =
  'malformed' | 'unknown' | 'expired' | 'idle' | 'epoch' | 'corrupt' | 'revoked';

export interface MintInput<A> {
  readonly userId: string;
  readonly attributes: A;
  readonly rememberMe: boolean;
  readonly persistentCookie: boolean;
  readonly authenticatedAt: number;
  /** The epoch read before the credential. Omit only when nothing was read that a revocation could race. */
  readonly epoch?: number;
  readonly meta: RequestMeta;
}

export type MintResult<A> =
  | {
      readonly ok: true;
      readonly token: string;
      readonly session: StoredSession<A>;
      readonly evicted: readonly string[];
    }
  | { readonly ok: false; readonly reason: 'epoch_fence' };

export type ValidateResult<A> =
  | { readonly ok: true; readonly session: StoredSession<A> }
  | { readonly ok: false; readonly reason: SessionRefusal };
