/**
 * @noctcore/auth/two-factor: a second factor that a stolen password cannot get
 * past, including through the recovery and reset paths. TOTP (RFC 6238),
 * recovery codes, trusted devices, step-up for sensitive actions, and
 * enforcement the app decides per user (with a grace period and a sweep,
 * re-checked on every request, through `enforcement`).
 *
 * It is a plugin: hooks on the core seams and flows under `auth.twoFactor`,
 * never HTTP endpoints. Every session it issues goes through the core's
 * `issueSession`.
 *
 * ```ts
 * const auth = createAuth({ ...config, plugins: [twoFactor({ store, cipher, issuer: 'Acme' })] });
 * const login = await auth.login({ email, password, meta });
 * if (login.ok && login.value.kind === 'challenge') {
 *   await auth.twoFactor.verifyChallenge({ challenge: login.value.challenge, proof: { kind: 'totp', code }, meta });
 * }
 * ```
 *
 * Guide: Learn, "Second factors"; Build, "Two-factor".
 */
import { verifyChallenge, type VerifyChallengeInput } from './challenge';
import {
  confirmEnrollment,
  enroll,
  type ConfirmEnrollmentInput,
  type EnrollInput,
} from './enrollment';
import { sweepUnenrolled, type SweepInput } from './enforcement';
import { twoFactorHooks } from './hooks';
import { disable, regenerateRecoveryCodes, revokeTrustedDevices, status } from './management';
import { resolveSettings, type TwoFactorOptions } from './options';
import type { SecondFactorProof } from './proofs';
import { createRuntime, type Context, type Runtime } from './runtime';
import { requireStepUp, stepUp } from './step-up';
import { TRUSTED_DEVICE_COOKIE } from './trusted-devices';
import { definePlugin } from '../../core/plugins';
import { parseCookieHeader, prefixedCookieName } from '../../http/cookie';
import type { StoredSession } from '../../ports/stores';
import { AuthConfigError } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

export type {
  ChallengeMethod,
  ChallengeProof,
  PassedChallenge,
  VerifyChallengeInput,
} from './challenge';
export type {
  ConfirmedEnrollment,
  ConfirmEnrollmentInput,
  EnrollInput,
  Enrollment,
} from './enrollment';
export type { SweepInput, SweepResult } from './enforcement';
export { TWO_FACTOR_REQUIRED_REVOCATION } from './enforcement';
export type { TwoFactorStatus } from './management';
export type {
  AttemptRule,
  TwoFactorEnforcement,
  TwoFactorOptions,
  TwoFactorPolicy,
} from './options';
export type { TwoFactorStanding } from '../../core/hooks';
export type { SecondFactorProof } from './proofs';
export type { TrustedDevice } from './trusted-devices';
export { RECOVERY_CODE_COUNT } from './recovery-codes';
export { TOTP_DIGITS, TOTP_PERIOD_SECONDS, totpCode } from './totp';
export type {
  SecretCipher,
  StoredStepUp,
  StoredTotpFactor,
  StoredTrustedDevice,
  TwoFactorStore,
} from '../../ports/two-factor';

/**
 * The two-factor plugin. `A` is the app's session attribute type, so the
 * sessions the flows return are typed like the core's.
 */
export function twoFactor<A = Record<string, never>>(options: TwoFactorOptions) {
  const settings = resolveSettings(options);
  let bound: Runtime | null = null;

  // The hooks run only inside flows, and `createAuth` builds the flows (and so
  // binds the context) before it returns, so a hook always finds it.
  const runtime = (): Runtime => {
    if (!bound) throw new AuthConfigError('twoFactor: pass the plugin to createAuth before use');

    return bound;
  };

  return definePlugin({
    id: 'twoFactor',
    hooks: twoFactorHooks(runtime, { enforced: settings.enforcement !== null }),
    flows: (context) => {
      if (bound) throw new AuthConfigError('twoFactor: one plugin instance per createAuth');

      const r = createRuntime(context as Context, options.store, options.cipher, settings);
      const cookieName = prefixedCookieName(context.cookie, TRUSTED_DEVICE_COOKIE);

      bound = r;

      return {
        /** Starts enrollment: a pending secret for a fresh session or an `enroll` challenge. */
        enroll: (input: EnrollInput<A>) => enroll(r, input),
        /** Activates the pending secret with a code from it; returns the recovery codes. */
        confirmEnrollment: (input: ConfirmEnrollmentInput<A>) => confirmEnrollment<A>(r, input),
        /** Finishes a challenged login with a code, a recovery code or a trusted device. */
        verifyChallenge: (input: VerifyChallengeInput) => verifyChallenge<A>(r, input),
        /** Proves the second factor in this session, for the step-up window. */
        stepUp: (input: {
          session: StoredSession<A>;
          proof: SecondFactorProof;
          meta: RequestMeta;
        }) => stepUp(r, input),
        /** Guard for the app's sensitive actions: fresh authentication plus a recent proof. */
        requireStepUp: (session: StoredSession<A>) => requireStepUp(r, session),
        /** Turns the factor off: needs a step-up, refused when the factor is required. */
        disable: (input: { session: StoredSession<A>; meta: RequestMeta }) => disable(r, input),
        /** A new set of recovery codes; every old one dies. Needs a step-up. */
        regenerateRecoveryCodes: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
          regenerateRecoveryCodes(r, input),
        /** Whether the factor is on, pending or required, and how many recovery codes are left. */
        status: (session: StoredSession<A>) => status(r, session),
        /** Forgets every trusted device of the user. */
        revokeTrustedDevices: (input: { session: StoredSession<A>; meta: RequestMeta }) =>
          revokeTrustedDevices(r, input),
        /**
         * With `enforcement`: revokes the sessions of the listed users who
         * must have a factor, have none and are past their grace window
         * (reason `two-factor-required`). Call it from your scheduler.
         */
        sweepUnenrolled: (input: SweepInput) => sweepUnenrolled(r, input),
        /** The name of the trusted-device cookie (`__Host-two-factor-device` when secure). */
        trustedDeviceCookieName: cookieName,
        /** Reads the trusted-device token out of a `Cookie` header. */
        readTrustedDeviceToken: (cookieHeader: string | null | undefined) =>
          parseCookieHeader(cookieHeader).get(cookieName) ?? null,
      };
    },
  });
}
