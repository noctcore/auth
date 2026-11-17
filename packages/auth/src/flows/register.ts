/**
 * Registration with a uniform answer: a new address and a taken one get the
 * same response after the same work, and the owner of a taken address gets an
 * "account exists" mail instead of a verification mail. Apps that would rather
 * say "this email is in use" opt in with `registration.revealExisting`.
 *
 * The password is checked and hashed BEFORE the address is looked up, so the
 * expensive step happens on both paths. Both paths hand one mail to the mailer
 * without waiting for it, so delivery time never reaches the answer.
 *
 * What still differs between the paths, and so can show in the response time:
 * the taken path's insert fails where the new one succeeds, the store calls
 * differ by one round trip (pinned by attack A004), and only a new address
 * runs the `afterRegister` hooks (awaited, so keep them fast and queue slow
 * work) and, with `autoLogin`, issues a session. `autoLogin` requires
 * `revealExisting`, whose answer already names a taken address.
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
    const existing = await core.users.findCredentialByEmail(email);

    if (settings.revealExisting) {
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

    if (existing) core.mail({ type: 'account-exists', to: existing.email, userId: existing.id });

    await core.emit(
      { type: 'register.existing', ...(existing ? { userId: existing.id } : {}) },
      meta,
    );

    return ok({ session: null });
  }

  for (const hook of core.hooks.afterRegister) await hook({ user, meta });

  await sendVerification(core, settings, user, meta);
  await core.emit({ type: 'register.created', userId: user.id }, meta);

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
