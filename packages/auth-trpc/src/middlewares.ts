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
 *   the `csrf` step was left out of the chain.
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
 *   resolved, and refuses when the counter store cannot answer.
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
  type StoredSession,
} from '@noctcore/auth';
import {
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
  next(opts?: { ctx: object }): Promise<TResult>;
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
  readonly session: StoredSession<A>;
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

/** The CSRF check on a mutation, then the session and its user. */
export async function principalOf(call: {
  readonly ctx: unknown;
  readonly type: string;
}): Promise<Principal> {
  checkCsrf(call);

  const { state } = stateOf(call.ctx);
  const user = state.session ? await state.user() : null;

  if (!state.session || !user) throw toTRPCError(fail('session_expired', 'no_session'));

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
 * The only way to the cookie writers: hands the procedure `ctx.auth` with
 * `setSession`, `signOut` and `clearSession`. On a streamed batch it refuses
 * first, so the core flow (a sign-in, a rotation) never runs when its cookie
 * cannot be set.
 */
export const writesCookiesBody = tagged(
  'cookies',
  async <TResult>(call: MiddlewareCall<TResult>): Promise<TResult> => {
    const { state, internals } = stateOf(call.ctx);

    refuseStreamedWrite(internals.streamed);

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
 * Counts each call in a fixed window per client IP, under a key of its own
 * (`trpc:<name>:<ip>`), so it never shares a budget with a core door. The
 * core flows already limit their own doors; use this on your procedures.
 */
export function rateLimitedBody(name: string, rule: RateLimitRule = DEFAULT_RATE_LIMIT) {
  if (!NAME.test(name)) throw new AuthConfigError(`Invalid rate limit name: ${name}`);

  // Checks the window now rather than on the first call.
  toMilliseconds(rule.window);

  return tagged('rate', async <TResult>(call: MiddlewareCall<TResult>): Promise<TResult> => {
    const { state, internals } = stateOf(call.ctx);
    const { auth } = internals.options;
    let hit;

    try {
      hit = await auth.context.throttle.hit(`trpc:${name}:${state.meta.ip}`, rule);
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
