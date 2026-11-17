/**
 * The invitee's side: accept into an existing account, or create the account
 * by accepting.
 *
 * - `accept` needs a session. The signed-in account's address must be verified
 *   and equal the invited one (both normalised); otherwise nothing is spent.
 *   An unverified account is never attached, which stops an attacker who
 *   registered the address first (pre-hijacking) from collecting the invitation.
 *   It issues no session, so a second factor is never skipped.
 * - `register` is for an address with no account. It creates the account with
 *   the address verified (the token proves the mailbox), then issues a session
 *   through `issueSession` with `via: 'invitation'`, where the hooks (two-factor
 *   included) decide as for any other session.
 *
 * Both spend the invitation with the store's atomic `consume`, so two clicks
 * or two browsers cannot both accept, and both check the inviter again first
 * (unless `recheckInviter` is off).
 */
import type { IssuedSession } from '../../core/plugin-context';
import { isTokenShape } from '../../crypto/random';
import type { StoredInvitation } from '../../ports/invitations';
import type { AuthUser, StoredSession } from '../../ports/stores';
import { normalizeEmail, type NormalizedEmail } from '../../shared/email';
import { ok, type AuthResult } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';
import {
  allowed,
  limit,
  refused,
  view,
  TOKEN_PURPOSE,
  type InvitationView,
  type Runtime,
} from './runtime';

export interface AcceptInvitationInput<A> {
  readonly session: StoredSession<A>;
  readonly token: string;
  readonly meta: RequestMeta;
}

export interface RegisterByInvitationInput {
  readonly token: string;
  readonly password: string;
  readonly meta: RequestMeta;
}

export interface RegisteredByInvitation<A> {
  readonly invitation: InvitationView;
  readonly session: IssuedSession<A>;
}

export async function acceptInvitation<A>(
  r: Runtime,
  input: AcceptInvitationInput<A>,
): Promise<AuthResult<InvitationView>> {
  const { session, meta } = input;
  const found = await pending(r, input.token, meta);

  if (!found.ok) return found;

  const invitation = found.value;
  const user = await r.core.users.findById(session.userId);

  if (!user) return refused(r, 'forbidden', 'user_missing', session.userId, meta);

  if (normalizeEmail(user.email) !== normalizeEmail(invitation.email))
    return refused(r, 'forbidden', 'email_mismatch', user.id, meta);

  if (!user.emailVerified) return refused(r, 'forbidden', 'email_unverified', user.id, meta);

  const spent = await spend(r, invitation, user.id, meta);

  if (!spent.ok) return spent;

  await accepted(r, user, spent.value, false, meta);

  return ok(view(spent.value));
}

export async function registerByInvitation<A>(
  r: Runtime,
  input: RegisterByInvitationInput,
): Promise<AuthResult<RegisteredByInvitation<A>>> {
  const { meta } = input;
  const found = await pending(r, input.token, meta);

  if (!found.ok) return found;

  const invitation = found.value;
  const email = normalizeEmail(invitation.email);

  if (!email) return refused(r, 'invalid_token', 'invitation_email_invalid', null, meta);

  // Before the lookup, so a taken address and a free one both pay for the hash.
  const hashed = await r.core.hashNewPassword(input.password, meta);

  if (!hashed.ok) return refused(r, hashed.code, hashed.reason, null, meta);

  // Not spent: the owner of the address signs in and calls `accept`.
  if (await r.core.users.findCredentialByEmail(email))
    return refused(r, 'email_in_use', 'email_in_use', null, meta);

  const spent = await spend(r, invitation, null, meta);

  if (!spent.ok) return spent;

  const created = await r.core.users.create({ email, passwordHash: hashed.value });

  // An account appeared for the address between the lookup and here: the invitation is spent.
  if (!created) return refused(r, 'email_in_use', 'email_in_use', null, meta);

  await r.core.users.markEmailVerified(created.id, email);

  const user: AuthUser = { ...created, emailVerified: true };

  for (const hook of r.core.hooks.afterRegister) await hook({ user, meta });

  await r.core.emit({ type: 'register.created', userId: user.id }, meta);
  await accepted(r, user, spent.value, true, meta);

  const issued = await r.core.issueSession(user, { via: 'invitation', meta });

  return issued.ok ? ok({ invitation: view(spent.value), session: issued.value }) : issued;
}

/**
 * The live invitation a token names. Every way of not finding one (junk,
 * unknown, expired) is the same `invalid_token`, after one per-IP hit.
 */
async function pending(
  r: Runtime,
  token: string,
  meta: RequestMeta,
): Promise<AuthResult<StoredInvitation>> {
  const limited = await limit(r, 'ip', meta.ip, r.settings.perIp, meta);

  if (limited) return limited;

  if (!isTokenShape(token)) return refused(r, 'invalid_token', 'malformed_token', null, meta);

  const invitation = await r.store.findByHash(r.core.keyedHash(TOKEN_PURPOSE, token));

  if (!invitation) return refused(r, 'invalid_token', 'unknown_token', null, meta);

  if (invitation.expiresAt <= r.core.clock.now())
    return refused(r, 'invalid_token', 'expired_token', null, meta);

  return ok(invitation);
}

/** Checks the inviter again, then spends the invitation atomically. */
async function spend(
  r: Runtime,
  invitation: StoredInvitation,
  userId: string | null,
  meta: RequestMeta,
): Promise<AuthResult<StoredInvitation>> {
  if (r.settings.recheckInviter && !(await inviterStillAllowed(r, invitation))) {
    await r.store.revoke(invitation.scope, invitation.id);

    return refused(r, 'invalid_token', 'inviter_not_allowed', userId, meta);
  }

  const consumed = await r.store.consume(invitation.hash);

  // Accepted, revoked or replaced meanwhile.
  if (!consumed) return refused(r, 'invalid_token', 'already_spent', userId, meta);

  return ok(consumed);
}

async function inviterStillAllowed(r: Runtime, invitation: StoredInvitation): Promise<boolean> {
  const inviter = await r.core.users.findById(invitation.inviterId);

  if (!inviter) return false;

  return allowed(r, {
    user: inviter,
    scope: invitation.scope,
    action: 'create',
    // Stored normalised by `create`.
    email: invitation.email as NormalizedEmail,
    payload: invitation.payload,
  });
}

/** Runs the app's `onAccept`, then writes the audit row. A throw reaches the caller. */
async function accepted(
  r: Runtime,
  user: AuthUser,
  invitation: StoredInvitation,
  created: boolean,
  meta: RequestMeta,
): Promise<void> {
  await r.settings.onAccept({ user, invitation, created, meta });

  await r.core.emit(
    {
      type: 'invitation.accepted',
      userId: user.id,
      data: { scope: invitation.scope, invitation: invitation.id, created },
    },
    meta,
  );
}
