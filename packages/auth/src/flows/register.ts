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
 *
 * An address held for its old owner while an email change away from it can
 * still be reverted (email-reservation.ts) counts as taken: the same answer,
 * the same mail (to the address, for its owner) and the same number of store
 * round trips on the response path, a read of the holder in the insert's
 * place. Not the same timing: a read costs less than an insert. Otherwise
 * whoever made the change could register the old address and leave the
 * revert nowhere to go back to. Every path looks for a hold first, before the
 * insert, so a race between that check and the insert can still slip
 * through. Paths of the app that create users must ask `auth.isAddressHeld`
 * themselves.
 */
import { addressHolder } from './email-reservation';
import { sendVerification } from './email-verification';
import type { FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import type { IssuedSession } from '../core/plugin-context';
import type { AuthUser } from '../ports/stores';
import { normalizeEmail, type NormalizedEmail } from '../shared/email';
import { fail, ok, type AuthFailure, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/counter-keys';

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

  const held = await heldAddress(core, email);
  const user = held ? null : await core.users.create({ email, passwordHash: hashed.value });

  // A permanent lock the address took while it had no account does not pass
  // to its new owner. Run for a taken address too, so both do the same work.
  await core.throttle.addressSignedUp(accountKey(email));

  if (!user) {
    if (settings.revealExisting) {
      const existing = (await core.users.findCredentialByEmail(email)) ?? held;

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
    // The lookup feeds the audit row, so it runs outside `maxPending` with
    // it; only the mail it starts can be dropped under the cap.
    core.background(
      'existing address notice',
      async () => {
        const existing = (await core.users.findCredentialByEmail(email)) ?? held;

        if (existing)
          core.mail({ type: 'account-exists', to: existing.email, userId: existing.id });

        await core.emit(
          { type: 'register.existing', ...(existing ? { userId: existing.id } : {}) },
          meta,
        );
      },
      undefined,
      { uncapped: true },
    );

    return ok({ session: null });
  }

  for (const hook of core.hooks.afterRegister) await hook({ user, meta });

  // The audit row and the mail are separate tasks: a slow or hung audit sink
  // cannot hold back the mail, and `maxPending` can drop the mail but never
  // the audit row.
  core.auditInBackground({ type: 'register.created', userId: user.id }, meta);

  core.background('verification mail', () => sendVerification(core, settings, user, meta, true), {
    userId: user.id,
  });

  if (!settings.autoLogin) return ok({ session: null });

  const issued = await core.issueSession(user, { via: 'register', meta });

  return issued.ok ? ok({ session: issued.value }) : issued;
}

/**
 * The account an address is held for while an email change away from it can
 * still be reverted, read where a free or taken address does its insert (one
 * round trip each). A holder that is gone can never revert, so its address is
 * free. Only a store that can change emails can have held addresses, so other
 * apps skip the lookup.
 */
async function heldAddress<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  email: NormalizedEmail,
): Promise<{ id: string; email: string } | undefined> {
  if (typeof core.users.changeEmail !== 'function') return undefined;

  const holderId = await addressHolder(core, email);

  if (holderId === null) return undefined;

  const holder = await core.users.findById(holderId);

  return holder ? { id: holder.id, email } : undefined;
}

async function refused<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  failure: AuthFailure,
  meta: RequestMeta,
): Promise<AuthFailure> {
  await core.emit({ type: 'register.refused', reason: failure.reason }, meta);

  return failure;
}
