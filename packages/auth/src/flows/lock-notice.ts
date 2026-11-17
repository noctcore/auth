/**
 * What happens when a failure locks an account: an audit row, then a mail to
 * the owner (handed to the mailer, not awaited), so they learn someone is
 * guessing their password.
 */
import type { AuthCore } from '../core/auth-core';
import type { AuthUser } from '../ports/stores';
import type { RequestMeta } from '../shared/meta';

export async function sendLockNotice<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  owner: { readonly id: string; readonly email: string },
  until: number,
  meta: RequestMeta,
): Promise<void> {
  await core.emit({ type: 'account.locked', userId: owner.id, data: { until } }, meta);

  core.mail({ type: 'lockout', to: owner.email, userId: owner.id, until: new Date(until) });
}
