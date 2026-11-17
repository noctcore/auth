/**
 * What happens when a failure locks an account: an audit row and a mail to the
 * owner, so they learn someone is guessing their password. On the response
 * path the mail is handed to the mailer, not awaited; inside a background
 * task (`inline`) it is sent beside the audit write and awaited, so a hung
 * audit sink cannot hold it back and the task's slot covers the send.
 */
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
import type { RequestMeta } from '../shared/meta';

export async function sendLockNotice<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  owner: { readonly id: string; readonly email: string },
  until: number,
  meta: RequestMeta,
  inline = false,
): Promise<void> {
  const event = {
    type: 'lockout',
    to: owner.email,
    userId: owner.id,
    until: new Date(until),
  } as const;

  const audit = core.emit({ type: 'account.locked', userId: owner.id, data: { until } }, meta);

  if (inline) {
    await Promise.all([audit, core.deliver(event)]);

    return;
  }

  await audit;
  core.mail(event);
}
