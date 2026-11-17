/**
 * @noctcore/auth-trpc: tRPC middlewares for @noctcore/auth.
 *
 * - `createAuthContext` checks the options once and returns the context
 *   creators for the fetch and Node adapters: `ctx.auth` holds the session the
 *   core accepted, the request meta and the cookie writers.
 * - `createAuthMiddlewares(t)` returns `csrf`, `authed`, `freshAuth`, `role`
 *   and `rateLimited`, plus `publicProcedure` (CSRF on mutations) and
 *   `protectedProcedure` (CSRF and a valid session).
 * - `assertProceduresGuarded(router)` fails on a procedure built with neither.
 * - The nestjs-trpc classes run the same bodies; `AuthGuardMiddleware` is the
 *   closed-by-default global for nestjs-trpc.
 * - `toTRPCError` and `authErrorFormatter` map refusals to tRPC errors
 *   without leaking account state, input values or internal messages.
 * - Zod input and output schemas for the auth procedures, and
 *   `assertNoSecretQueries` to keep secrets out of URLs.
 */
export { createAuthContext, type AuthContextFactory, type AuthState } from './context';
export {
  createAuthMiddlewares,
  type AuthContext,
  type AuthContextOf,
  type AuthMiddlewares,
  type AuthProcedureBuilder,
  type AuthRoot,
} from './create-middlewares';
export {
  assertProceduresGuarded,
  describeProcedures,
  type ProcedureAccess,
} from './describe-procedures';
export {
  AUTH_ERROR_TRPC_CODES,
  AuthTRPCError,
  authErrorFormatter,
  toTRPCError,
  type AuthErrorShape,
  type PublicAuthError,
  type PublicInputIssue,
} from './errors';
export { DEFAULT_RATE_LIMIT, type Principal } from './middlewares';
export {
  AuthGuardMiddleware,
  AuthedMiddleware,
  CsrfMiddleware,
  FreshAuthMiddleware,
  RateLimitMiddleware,
  RoleMiddleware,
  type NestTrpcMiddleware,
  type NestTrpcMiddlewareClass,
} from './nestjs';
export {
  MAX_TRUSTED_HOPS,
  type AuthContextOptions,
  type CsrfOptions,
  type TrpcAuth,
} from './options';
export type { FetchContextInput, NodeContextInput } from './request';
export {
  acceptedOutput,
  changePasswordInput,
  csrfTokenOutput,
  loginInput,
  loginOutput,
  reauthenticateInput,
  registerInput,
  requestPasswordResetInput,
  resetPasswordInput,
  resetTicketOutput,
  revokedOutput,
  revokeSessionInput,
  sessionListOutput,
  sessionSummaryOutput,
  userOutput,
  verificationRequestOutput,
  verifyEmailCodeInput,
  verifyEmailLinkInput,
  verifyPasswordResetCodeInput,
} from './schemas';
export {
  assertNoSecretQueries,
  findSecretQueries,
  type SecretQueryFinding,
} from './secret-queries';
