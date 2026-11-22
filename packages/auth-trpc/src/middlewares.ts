/**
 * The middleware bodies, written once and shared by plain tRPC
 * (`createAuthMiddlewares(t)`) and nestjs-trpc (the classes in `nestjs.ts`),
 * so the two can never drift apart.
 *
 * Every check fails closed:
 *
 * - `csrf` refuses a mutation unless the request passed all three CSRF checks
 *   when the context was built. Queries skip it: they must not change state,
 *   and none may carry a secret (`assertNoSecretQueries`).
 * - `authed` refuses unless the core accepted the session and its user still
 *   exists in the store, loaded on this request, so a deleted user is signed
 *   out at once and nothing is read from a cookie or a token. It runs the
 *   CSRF check itself first, so a mutation behind it is checked even where
 *   the `csrf` step was left out of the chain. It refuses an
 *   `enrollment-only` session (the two-factor plugin's `enforcement`, past
 *   the grace window) with `two_factor_enrollment_required`, unless the
 *   procedure's meta says `twoFactorEnrollment: true`.
 * - `freshAuth` and `role` run the `authed` check themselves, so either one
 *   alone still refuses a caller without a session or a forged mutation.
 * - `guard` is the nestjs-trpc default: CSRF on mutations, and a session for
 *   every procedure whose meta does not say `auth: 'public'`. A public
 *   procedure that also asks for a role or a fresh proof is a configuration
 *   error, refused on every call rather than read one way or the other.
 *
 * Each body is tagged with what it checks, so `describeProcedures` can list a
 * plain tRPC router's procedures with their access rule.
 * - `rateLimited` counts with the core's throttle by the client IP the core
 *   resolved (or, opted in, by the signed-in user), and refuses when the
 *   counter store cannot answer.
 *
 * A refusal is an `AuthTRPCError` naming only the public code.
 */
import {
  AuthConfigError,
  fail,
  toMilliseconds,
  type AuthUser,
  type Duration,
  type RateLimitRule,
  type ValidatedSession,
} from '@noctcore/auth';
import {
  claimCookieWriter,
  internalsOf,
  refuseStreamedWrite,
  writerView,
  type AuthState,
  type Internals,
} from './context';
import { internalError, toTRPCError } from './errors';

/** The options of a tRPC middleware call, as far as these bodies read them. */
export interface MiddlewareCall<TResult> {
  readonly ctx: unknown;
  readonly type: string;
  // `ctx` is optional, as both tRPC and nestjs-trpc type it, so the
  // nestjs-trpc options (`NestTrpcMiddlewareOptions`) pass as a call too.
  next(opts?: { ctx?: object }): Promise<TResult>;
}

type MetaCall<TResult> = MiddlewareCall<TResult> & { readonly meta?: unknown };

/** What a middleware body checks, for `describeProcedures`. */
export type BodyKind = 'csrf' | 'public' | 'session' | 'rate' | 'cookies';

const kinds = new WeakMap<object, BodyKind>();

function tagged<T extends object>(kind: BodyKind, body: T): T {
  kinds.set(body, kind);

  return body;
}

// A WeakMap answers undefined for a key that is not an object, so any value may be asked.
export const kindOf = (body: unknown): BodyKind | undefined => kinds.get(body as object);

/** What `authed` adds to the context. */
export interface Principal<U extends AuthUser = AuthUser, A = unknown> {
  readonly user: U;
  /** The validated session, with its two-factor standing on this request when enforcement is on. */
  readonly session: ValidatedSession<A>;
}

function stateOf(ctx: unknown): { state: AuthState; internals: Internals } {
  const state = (ctx as { auth?: unknown } | null | undefined)?.auth;
  const found = internalsOf(state);

  if (!found) {
    throw new AuthConfigError(
      'ctx.auth must be the value createAuthContext(...) returned, passed through unchanged',
    );
  }

  return { state: state as AuthState, internals: found };
}

function checkCsrf(call: { readonly ctx: unknown; readonly type: string }): void {
  if (call.type === 'mutation' && !stateOf(call.ctx).internals.csrfOk) {
    throw toTRPCError(fail('forbidden', 'csrf'));
  }
}

/**
 * The meta keys the adapter reads. Pass it to `initTRPC.meta<...>()` (or
 * intersect it with your own meta type) to have them checked.
 */
export interface AuthProcedureMeta extends RateLimitMeta {
  /** The nestjs-trpc guard: no session needed. CSRF still applies. */
  readonly auth?: 'public';
  /**
   * An `enrollment-only` session (the two-factor plugin's `enforcement`,
   * past the grace window) may call this procedure: mark the enrollment
   * procedures and what a user needs on the way (status, re-authentication,
   * sign out). Every other procedure refuses such a session with
   * `two_factor_enrollment_required`. It opens nothing else.
   */
  readonly twoFactorEnrollment?: boolean;
  /**
   * `false`: a call to this procedure does not count as activity for the
   * session's idle timeout (a poll the page makes on a timer). The session
   * is still validated and the procedure's guards still apply. A batch
   * touches when any of its procedures does.
   */
  readonly touch?: false;
}

const allowsEnrollmentOnly = (meta: unknown): boolean =>
  (meta as AuthProcedureMeta | null | undefined)?.twoFactorEnrollment === true;

/**
 * The CSRF check on a mutation, then the session and its user, then an
 * enrollment-only session only on a procedure whose meta allows it.
 */
export async function principalOf(call: {
  readonly ctx: unknown;
  readonly type: string;
  readonly meta?: unknown;
}): Promise<Principal> {
  checkCsrf(call);

  const { state } = stateOf(call.ctx);
  const user = state.session ? await state.user() : null;

  if (!state.session || !user) throw toTRPCError(fail('session_expired', 'no_session'));

  if (state.session.twoFactor?.state === 'enrollment-only' && !allowsEnrollmentOnly(call.meta))
    throw toTRPCError(fail('two_factor_enrollment_required', 'enrollment_only'));

  return { user, session: state.session };
}

export const csrfBody = tagged(
  'csrf',
  async <TResult>(call: MiddlewareCall<TResult>): Promise<TResult> => {
    checkCsrf(call);

    return call.next();
  },
);

/** Marks a procedure as open without a session, for `describeProcedures`. CSRF still applies. */
export const publicBody = tagged(
  'public',
  async <TResult>(call: MiddlewareCall<TResult>): Promise<TResult> => {
    checkCsrf(call);

    return call.next();
  },
);

export const authedBody = tagged(
  'session',
  async <TResult>(call: MiddlewareCall<TResult>): Promise<TResult> =>
    call.next({ ctx: await principalOf(call) }),
);

/**
 * Why `writesCookies` refuses each procedure type that is not a mutation. A
 * query skips the CSRF check (it must not change state) and runs on a GET a
 * top-level navigation from another site can send with the `SameSite=Lax`
 * session cookie; a subscription's response is a stream, sent before any
 * cookie could be written.
 */
const NOT_A_MUTATION: ReadonlyMap<string, string> = new Map([
  [
    'query',
    'a query skips the CSRF check and runs on a GET, so a link on another site could make ' +
      'the browser run it with its session cookie',
  ],
  ['subscription', 'its response is a stream, sent before any cookie could be written'],
]);

/**
 * Refuses `writesCookies` on any call that is not a mutation: only a mutation
 * passes the CSRF check, and only its response is sent after the procedure
 * ran. The type comes from tRPC on each call (a middleware is attached before
 * the procedure has a type), so this runs before the procedure, every call.
 */
function refuseNonMutation(type: string): void {
  if (type === 'mutation') return;

  const why = NOT_A_MUTATION.get(type) ?? 'only a mutation passes the CSRF check';

  throw new AuthConfigError(
    `writesCookies cannot mark a ${type}: ${why}. Write cookies from a mutation.`,
  );
}

/**
 * The only way to the cookie writers: hands the procedure `ctx.auth` with
 * `setSession`, `signOut` and `clearSession`. On a query, a subscription and
 * a streamed batch it refuses first, so the core flow (a sign-in, a rotation,
 * a sign-out) never runs without the CSRF check or when its cookie cannot be
 * set. It also claims the request's one cookie-writer slot: a second marked
 * procedure in the same batch is refused before it runs, so a batch cannot
 * mint a session no browser holds.
 */
export const writesCookiesBody = tagged(
  'cookies',
  async <TResult>(call: MiddlewareCall<TResult>): Promise<TResult> => {
    refuseNonMutation(call.type);

    const { state, internals } = stateOf(call.ctx);

    refuseStreamedWrite(internals.streamed);
    claimCookieWriter(internals);

    return call.next({ ctx: { auth: writerView(state, internals) } });
  },
);

const isPublicMeta = (meta: unknown): boolean =>
  (meta as { auth?: unknown } | null | undefined)?.auth === 'public';

function refusePublic(meta: unknown, what: string): void {
  if (isPublicMeta(meta)) {
    throw new AuthConfigError(
      `A procedure with meta auth: 'public' cannot also require ${what}: drop one of the two`,
    );
  }
}

/**
 * The nestjs-trpc default, for `globalMiddlewares`: CSRF on every mutation,
 * and a session on every procedure unless its meta says `auth: 'public'`.
 */
export async function guardBody<TResult>(
  call: MiddlewareCall<TResult> & { readonly meta?: unknown },
): Promise<TResult> {
  if (isPublicMeta(call.meta)) {
    checkCsrf(call);

    return call.next();
  }

  return call.next({ ctx: await principalOf(call) });
}

/**
 * Requires a recent credential proof (`auth.requireFreshAuth`, `freshAuthAge`
 * in the core's config). `maxAge` can only make it stricter.
 */
export function freshAuthBody(maxAge?: Duration) {
  const maxAgeMs = maxAge === undefined ? undefined : toMilliseconds(maxAge);

  return tagged('session', async <TResult>(call: MetaCall<TResult>): Promise<TResult> => {
    refusePublic(call.meta, 'a fresh credential proof');

    const principal = await principalOf(call);
    const { auth } = stateOf(call.ctx).internals.options;
    const fresh = auth.requireFreshAuth(principal.session);

    const withinMaxAge =
      maxAgeMs === undefined ||
      auth.context.clock.now() - principal.session.authenticatedAt <= maxAgeMs;

    if (!fresh.ok || !withinMaxAge) throw toTRPCError(fail('fresh_auth_required', 'stale'));

    return call.next({ ctx: principal });
  });
}

/** Requires at least one of `roles`, read through the `roles` option on every call. */
export function roleBody(roles: readonly string[]) {
  if (roles.length === 0) throw new AuthConfigError('role() needs at least one role');

  return tagged('session', async <TResult>(call: MetaCall<TResult>): Promise<TResult> => {
    refusePublic(call.meta, 'a role');

    const principal = await principalOf(call);
    const { options } = stateOf(call.ctx).internals;

    if (!options.roles) {
      throw new AuthConfigError('role() needs the `roles` option of createAuthContext');
    }

    const held = await options.roles(principal.user);

    if (!roles.some((role) => held.includes(role))) throw toTRPCError(fail('forbidden', 'role'));

    return call.next({ ctx: principal });
  });
}

const NAME = /^[a-z0-9][a-z0-9_.-]*$/iu;

export const DEFAULT_RATE_LIMIT: RateLimitRule = { limit: 10, window: '1m' };

/**
 * Who a rate limit counts: `ip`, the client IP the core resolved; `user`, the
 * signed-in user (the stored session's user id), with the client IP for a
 * call that has no session the core accepted.
 */
export type RateLimitKeyBy = 'ip' | 'user';

/** A fixed-window rule for `rateLimited`, keyed by the client IP unless `keyBy` says `user`. */
export interface TrpcRateLimitRule extends RateLimitRule {
  /** Default `ip`. */
  readonly keyBy?: RateLimitKeyBy;
}

/**
 * The procedure meta `rateLimited` reads: `rateLimit: 'exempt'` skips every
 * `rateLimited` on the procedure, including one on the base procedure it was
 * built from. Add it to your meta type: `initTRPC.meta<RateLimitMeta>()`.
 */
export interface RateLimitMeta {
  readonly rateLimit?: 'exempt';
}

const KEY_BY: ReadonlySet<unknown> = new Set<RateLimitKeyBy>(['ip', 'user']);

/** Checks a rule's window and `keyBy` when the middleware is made, rather than on the first call. */
function checkRule<R extends TrpcRateLimitRule>(rule: R, what: string): R {
  toMilliseconds(rule.window);

  if (rule.keyBy !== undefined && !KEY_BY.has(rule.keyBy)) {
    throw new AuthConfigError(`${what}: keyBy must be 'ip' or 'user'`);
  }

  return rule;
}

/**
 * The named tiers of `createAuthMiddlewares(t, { rateLimits })`, checked at
 * boot. A Map, so a name such as `constructor` never reads the prototype.
 */
export function resolveRateLimitTiers(
  tiers: Readonly<Record<string, TrpcRateLimitRule>> = {},
): ReadonlyMap<string, TrpcRateLimitRule> {
  const resolved = new Map<string, TrpcRateLimitRule>();

  for (const [tier, rule] of Object.entries(tiers)) {
    if (!NAME.test(tier)) throw new AuthConfigError(`Invalid rate limit tier name: ${tier}`);

    resolved.set(tier, checkRule(rule, `Rate limit tier ${tier}`));
  }

  return resolved;
}

/**
 * The rule a `rateLimited(name, pick)` call counts with: a tier named by
 * `pick` (unknown: refused when the middleware is made), the rule `pick` is,
 * else the tier named `name`, else the `default` tier, else 10 a minute.
 */
export function pickRateLimitRule(
  tiers: ReadonlyMap<string, TrpcRateLimitRule>,
  name: string,
  pick: TrpcRateLimitRule | string | undefined,
): TrpcRateLimitRule {
  if (typeof pick === 'string') {
    const found = tiers.get(pick);

    if (!found) throw new AuthConfigError(`Unknown rate limit tier: ${pick}`);

    return found;
  }

  return pick ?? tiers.get(name) ?? tiers.get('default') ?? DEFAULT_RATE_LIMIT;
}

const isExemptMeta = (meta: unknown): boolean =>
  (meta as RateLimitMeta | null | undefined)?.rateLimit === 'exempt';

/** The core's `keyedHash` purpose for the user part of a counter key. */
const USER_KEY_PURPOSE = 'auth-trpc/rate-limit-user';

/**
 * The caller part of a counter key. A user is named by the core's keyed hash
 * (an HMAC under a key derived from the server secret) of the user id the
 * core stored with the session, never anything the client sent, under
 * `user:`, which no client IP (an address or `unknown`) can start with. So
 * the user and IP buckets never collide, a reader of the counter store cannot
 * link a key to a guessable user id without the secret, and a cookie the core
 * refused counts by IP like any anonymous call.
 */
function callerOf(
  state: AuthState,
  internals: Internals,
  keyBy: RateLimitKeyBy | undefined,
): string {
  const userId = keyBy === 'user' ? state.session?.userId : undefined;

  if (!userId) return state.meta.ip;

  return `user:${internals.options.auth.context.keyedHash(USER_KEY_PURPOSE, userId)}`;
}

/**
 * Counts each call in a fixed window under a key of its own, so it never
 * shares a budget with a core door: `trpc:<name>:<ip>` by default, and
 * `trpc:<name>:user:<hmac>` for a signed-in caller when `keyBy` is `user`.
 * A procedure whose meta says `rateLimit: 'exempt'` is not counted. The core
 * flows already limit their own doors; use this on your procedures.
 */
export function rateLimitedBody(name: string, rule: TrpcRateLimitRule = DEFAULT_RATE_LIMIT) {
  if (!NAME.test(name)) throw new AuthConfigError(`Invalid rate limit name: ${name}`);

  checkRule(rule, `Rate limit ${name}`);

  return tagged('rate', async <TResult>(call: MetaCall<TResult>): Promise<TResult> => {
    if (isExemptMeta(call.meta)) return call.next();

    const { state, internals } = stateOf(call.ctx);
    const { auth } = internals.options;
    const { limit, window } = rule;
    let hit;

    try {
      hit = await auth.context.throttle.hit(
        `trpc:${name}:${callerOf(state, internals, rule.keyBy)}`,
        {
          limit,
          window,
        },
      );
    } catch (error) {
      // Fail closed: no answer from the counter store is not a pass.
      auth.context.logger.error('auth-trpc rate limit could not count the call', {
        limit: name,
        error: error instanceof Error ? error.name : typeof error,
      });

      throw internalError();
    }

    if (!hit.allowed) {
      if (hit.firstRefusal) {
        await auth.context.emit(
          { type: 'rate_limit.exceeded', reason: `trpc:${name}` },
          state.meta,
        );
      }

      throw toTRPCError(
        fail('rate_limited', `rate_limited:trpc:${name}`, {
          retryAfterSeconds: hit.retryAfterSeconds,
        }),
      );
    }

    return call.next();
  });
}
