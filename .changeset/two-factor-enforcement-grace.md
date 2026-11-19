---
'@noctcore/auth': minor
'@noctcore/auth-nestjs': patch
'@noctcore/auth-trpc': patch
---

The two-factor plugin takes an `enforcement` option: a per-user policy, `({ user }) => { required, graceEndsAt? }`, so an app can require a factor of a tenant's existing users with a grace window. It is checked on every validated request, never stored, so a policy change or a closing window applies without a new sign-in. In the window the session carries `twoFactor: { state: 'grace', graceEndsAt }`; after it the user still signs in, but the session is `twoFactor: { state: 'enrollment-only' }` and the adapters let it reach only the routes marked for enrollment. A policy that throws reads as enrollment-only. `auth.twoFactor.sweepUnenrolled({ userIds })` revokes the sessions of users past their window without a factor (reason `two-factor-required`), and `status` reports the standing as `enforcement`. `enforcement` replaces `required`: pass one or the other.

The core adds the `sessionStanding` hook, the `ValidatedSession`, `SessionStanding` and `TwoFactorStanding` types (`validateRequest` now returns a `ValidatedSession`), and the `two_factor_enrollment_required` error code. An app with an exhaustive map over `AuthErrorCode` needs an entry for it.

`@noctcore/auth-nestjs`: `@TwoFactorEnrollment()` marks a route or controller an enrollment-only session may reach; the guard refuses it elsewhere with 403 `two_factor_enrollment_required`. `describeRoutes` reports `twoFactorEnrollment`.

`@noctcore/auth-trpc`: `authed` (and `role`, `freshAuth` and `AuthGuardMiddleware`) refuse an enrollment-only session with `FORBIDDEN` `two_factor_enrollment_required` unless the procedure's meta says `twoFactorEnrollment: true`; the new `AuthProcedureMeta` type names the meta keys the adapter reads.
