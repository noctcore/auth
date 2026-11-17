/**
 * From the core's refusals to tRPC errors, without leaking account state.
 *
 * - The mapping is total, with a safe default: a code it does not know (a
 *   newer core, a plugin, a value that is not a code at all) becomes a
 *   generic `INTERNAL_SERVER_ERROR` named `internal`, never the raw message.
 * - A refusal crosses the wire as its public code only (`toPublicError`):
 *   the internal `reason` (`unknown_email`, `locked`, ...) is never the
 *   message, the cause or any field, so "no such account", "wrong password"
 *   and "locked" stay one answer.
 * - `authErrorFormatter` also covers what tRPC builds itself: an input that
 *   fails validation is answered with the paths and issue codes only (never
 *   the submitted value or a message that could quote it), and any other
 *   internal error with `internal` and no stack, since a store error can carry
 *   a session key or an address.
 *
 * Guide: Learn, "Enumeration".
 */
import { toPublicError, type AuthErrorCode, type AuthFailure } from '@noctcore/auth';
import { TRPCError, type TRPC_ERROR_CODE_KEY } from '@trpc/server';

/** The tRPC code each public auth code is sent with. */
export const AUTH_ERROR_TRPC_CODES: Readonly<Record<AuthErrorCode, TRPC_ERROR_CODE_KEY>> = {
  invalid_credentials: 'UNAUTHORIZED',
  invalid_token: 'BAD_REQUEST',
  invalid_email: 'BAD_REQUEST',
  weak_password: 'BAD_REQUEST',
  password_too_long: 'BAD_REQUEST',
  breached_password: 'BAD_REQUEST',
  password_not_set: 'BAD_REQUEST',
  email_in_use: 'CONFLICT',
  captcha_failed: 'BAD_REQUEST',
  captcha_unavailable: 'SERVICE_UNAVAILABLE',
  rate_limited: 'TOO_MANY_REQUESTS',
  session_expired: 'UNAUTHORIZED',
  fresh_auth_required: 'FORBIDDEN',
  second_factor_required: 'FORBIDDEN',
  invalid_second_factor: 'UNAUTHORIZED',
  forbidden: 'FORBIDDEN',
};

/** What the client may learn about an auth refusal. */
export interface PublicAuthError {
  /** A public auth code, or `internal` for anything the mapping does not know. */
  readonly code: AuthErrorCode | 'internal';
  /** Set on `rate_limited`: when the window that refused ends. */
  readonly retryAfterSeconds?: number;
}

function isAuthErrorCode(code: unknown): code is AuthErrorCode {
  return typeof code === 'string' && Object.hasOwn(AUTH_ERROR_TRPC_CODES, code);
}

/**
 * A `TRPCError` built from an auth refusal. Its message is the public code
 * and it has no cause, so even a formatter that sends the message and the
 * cause as they are leaks nothing.
 */
export class AuthTRPCError extends TRPCError {
  // The name stays `TRPCError`: tRPC recognises an error by its class or, when
  // a CommonJS and an ESM copy of @trpc/server meet in one app (nestjs-trpc is
  // CommonJS), by that name. Renaming it would turn every refusal into a 500.
  readonly auth: PublicAuthError;

  constructor(auth: PublicAuthError) {
    super({
      code: auth.code === 'internal' ? 'INTERNAL_SERVER_ERROR' : AUTH_ERROR_TRPC_CODES[auth.code],
      message: auth.code,
    });

    this.auth = auth;
  }
}

/**
 * The tRPC error for a flow's refusal: throw it from a procedure when a flow
 * returns `{ ok: false }`. Total: an unknown code becomes `internal`.
 */
export function toTRPCError(
  failure: Pick<AuthFailure, 'code' | 'retryAfterSeconds'>,
): AuthTRPCError {
  if (!isAuthErrorCode(failure.code)) return new AuthTRPCError({ code: 'internal' });

  return new AuthTRPCError(toPublicError(failure as AuthFailure));
}

/** A generic failure, for errors whose details must stay on the server. */
export const internalError = (): AuthTRPCError => new AuthTRPCError({ code: 'internal' });

/** One input problem, as the client sees it: where, and what kind, never the value. */
export interface PublicInputIssue {
  readonly path: readonly (string | number)[];
  readonly code: string;
}

interface IssueLike {
  readonly path?: readonly PropertyKey[];
  readonly code?: unknown;
}

function inputIssues(cause: unknown): PublicInputIssue[] | null {
  const issues = (cause as { issues?: unknown } | undefined)?.issues;

  if (!Array.isArray(issues)) return null;

  return (issues as IssueLike[]).map((issue) => ({
    path: (issue.path ?? []).map((key) => (typeof key === 'number' ? key : String(key))),
    code: typeof issue.code === 'string' ? issue.code : 'invalid',
  }));
}

/** The shape tRPC hands a formatter, as far as this one reads it. */
interface ShapeLike {
  readonly message: string;
  readonly data: { readonly stack?: string | undefined };
}

export type AuthErrorShape<TShape extends ShapeLike> = Omit<TShape, 'data' | 'message'> & {
  readonly message: string;
  readonly data: Omit<TShape['data'], 'stack'> & {
    readonly stack?: string | undefined;
    /** Set on an auth refusal: the public code, and when to retry on `rate_limited`. */
    readonly auth: PublicAuthError | null;
    /** Set when the input failed validation: where and what kind, never the value. */
    readonly input: readonly PublicInputIssue[] | null;
  };
};

/**
 * An error formatter for `initTRPC.create({ errorFormatter })` (or
 * `trpc.errorFormatter` in nestjs-trpc). From an app formatter of your own,
 * call it first and add to what it returns.
 */
export function authErrorFormatter<TShape extends ShapeLike>(opts: {
  shape: TShape;
  error: TRPCError;
}): AuthErrorShape<TShape> {
  const { shape, error } = opts;
  const { stack, ...rest } = shape.data;
  const data = rest as Omit<TShape['data'], 'stack'>;

  if (error instanceof AuthTRPCError) {
    return { ...shape, message: error.auth.code, data: { ...data, auth: error.auth, input: null } };
  }

  if (error.code === 'INTERNAL_SERVER_ERROR') {
    return {
      ...shape,
      message: 'internal',
      data: { ...data, auth: { code: 'internal' }, input: null },
    };
  }

  const issues = error.code === 'BAD_REQUEST' ? inputIssues(error.cause) : null;

  if (issues) {
    return { ...shape, message: 'invalid_input', data: { ...data, auth: null, input: issues } };
  }

  return {
    ...shape,
    data: { ...data, ...(stack === undefined ? {} : { stack }), auth: null, input: null },
  };
}
