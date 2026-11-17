/**
 * Registration with a uniform answer: a new address and a taken one get the
 * same response after the same work, and the owner of a taken address gets an
 * "account exists" mail instead of a verification mail. Apps that would rather
 * say "this email is in use" opt in with `registration.revealExisting`.
 *
 * The password is checked and hashed BEFORE the address is looked up, so the
 * expensive step happens on both paths. The answer then waits on one insert,
 * which succeeds for a new address and fails or is skipped for a taken one.
 * Everything after it that differs between the paths runs off the response
 * path through `background`: the owner lookup, the "account exists" mail and
 * the `register.existing` event for a taken address; the `register.created`
 * event, the verification token and its mail for a new one. On real stores
 * the two sequences cost different times (a read against a write), so
 * awaiting them showed in the answer. A failure there is logged, not answered.
 *
 * What still differs on the response path, and so can show in the response
 * time: the insert itself (a stored row against a failed or skipped one), and
 * only a new address runs the `afterRegister` hooks (awaited, so keep them fast
 * and queue slow work) and, with `autoLogin`, issues a session. `autoLogin`
 * requires `revealExisting`, whose answer already names a taken address.
 */
import { sendVerification } from './email-verification';
import type { FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { IssuedSession } from '../core/plugin-context';
import type { AuthUser } from '../ports/stores';
import { normalizeEmail } from '../shared/email';
import { fail, ok, type AuthFailure, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';

export interface RegisterInput {
  readonly email: string;
  readonly password: string;
  readonly captchaToken?: string;
  readonly meta: RequestMeta;
}

export interface RegisterOutcome<A> {
  /** Set only with `autoLogin` (which requires `revealExisting`). */
  readonly session: IssuedSession<A> | null;
}

export async function register<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: RegisterInput,
): Promise<AuthResult<RegisterOutcome<A>>> {
  const { meta } = input;
  const captcha = await core.checkCaptcha('register', input.captchaToken, meta);

  if (captcha) return refused(core, captcha, meta);

  const limited = await core.rateLimit('register', meta.ip, meta);

  if (limited) return limited;

  const email = normalizeEmail(input.email);

  if (!email) return refused(core, fail('invalid_email', 'invalid_email'), meta);

  const hashed = await core.hashNewPassword(input.password, meta);

  if (!hashed.ok) return refused(core, hashed, meta);

  const user = await core.users.create({ email, passwordHash: hashed.value });

  if (!user) {
    if (settings.revealExisting) {
      const existing = await core.users.findCredentialByEmail(email);

      await core.emit(
        {
          type: 'register.refused',
          ...(existing ? { userId: existing.id } : {}),
          reason: 'email_in_use',
        },
        meta,
      );

      return fail('email_in_use', 'email_in_use');
    }

    // Everything after the insert that differs from a new address runs off
    // the response path, like the new address's verification below.
    core.background('existing address notice', async () => {
      const existing = await core.users.findCredentialByEmail(email);

      if (existing) core.mail({ type: 'account-exists', to: existing.email, userId: existing.id });

      await core.emit(
        { type: 'register.existing', ...(existing ? { userId: existing.id } : {}) },
        meta,
      );
    });

    return ok({ session: null });
  }

  for (const hook of core.hooks.afterRegister) await hook({ user, meta });

  core.background('verification mail', async () => {
    await core.emit({ type: 'register.created', userId: user.id }, meta);
    await sendVerification(core, settings, user, meta);
  });

  if (!settings.autoLogin) return ok({ session: null });

  const issued = await core.issueSession(user, { via: 'register', meta });

  return issued.ok ? ok({ session: issued.value }) : issued;
}

async function refused<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  failure: AuthFailure,
  meta: RequestMeta,
): Promise<AuthFailure> {
  await core.emit({ type: 'register.refused', reason: failure.reason }, meta);

  return failure;
}
