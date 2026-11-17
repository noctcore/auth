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

  const audited = { type: 'account.locked', userId: owner.id, data: { until } } as const;

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
