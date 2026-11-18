/**
 * What happens when a failure locks an account: an audit row and a mail to the
 * owner, so they learn someone is guessing their password. On the response
 * path the mail is handed to the mailer, not awaited; inside a background
 * task (`inline`) it is sent beside the audit write and awaited, so a hung
 * audit sink cannot hold it back and the task's slot covers the send.
 *
 * A lock in the opt-in permanent tier also runs the `onPermanentLock` hooks,
 * always off the response path, so a known account answers no slower.
 */
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
import { describeError } from '../shared/describe-error';
import type { RequestMeta } from '../shared/meta';
import type { NewLock } from '../throttle/rules';

export async function sendLockNotice<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  owner: { readonly id: string; readonly email: string },
  lock: NewLock,
  meta: RequestMeta,
  inline = false,
): Promise<void> {
  const permanent = lock.permanent === true;

  const event = {
    type: 'lockout',
    to: owner.email,
    userId: owner.id,
    until: new Date(lock.until),
    ...(permanent ? { permanent: true as const } : {}),
  } as const;

  const audited = permanent
    ? ({ type: 'account.locked_permanently', userId: owner.id } as const)
    : ({ type: 'account.locked', userId: owner.id, data: { until: lock.until } } as const);

  if (permanent) runPermanentLockHooks(core, owner, meta);

  // Off the response path (`inline`): the audit row and the mail are separate
  // tasks, so a hung audit sink cannot hold the mail back and `maxPending`
  // can drop the mail but never the audit row.
  if (inline) {
    core.auditInBackground(audited, meta);
    core.mail(event);

    return;
  }

  await core.emit(audited, meta);
  core.mail(event);
}

function runPermanentLockHooks<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  owner: { readonly id: string; readonly email: string },
  meta: RequestMeta,
): void {
  const hooks = core.hooks.onPermanentLock;

  if (hooks.length === 0) return;

  core.background(
    'onPermanentLock hooks',
    async () => {
      for (const hook of hooks) {
        try {
          await hook({ userId: owner.id, email: owner.email, meta });
        } catch (error) {
          core.logger.error('onPermanentLock hook failed', {
            userId: owner.id,
            error: describeError(error),
          });
        }
      }
    },
    { userId: owner.id },
    { uncapped: true },
  );
}
