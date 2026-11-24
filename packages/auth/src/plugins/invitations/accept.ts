/**
 * The invitee's side: accept into an existing account, or create the account
 * by accepting.
 *
 * - `accept` needs a session, unless `acceptWithoutSession` is on and the
 *   caller passes `session: null`: then the account is the one holding the
 *   invited address. Either way that account's address must be verified and
 *   equal the invited one (both normalised); otherwise nothing is spent. An
 *   unverified account is never attached, which stops an attacker who
 *   registered the address first (pre-hijacking) from collecting the
 *   invitation. It issues no session, so a second factor is never skipped
 *   and a link alone never signs anyone in.
 * - `register` is for an address with no account that is not held for the
 *   owner of an email change that can still be reverted (either answers
 *   `email_in_use` and spends nothing). It creates the account with the
 *   address verified (the token proves the mailbox), then issues a session
 *   through `issueSession` with `via: 'invitation'`, where the hooks
 *   (two-factor included) decide as for any other session.
 *
 * Both spend the invitation with the store's atomic `consume`, so two clicks
 * or two browsers cannot both accept, and both check the inviter again first
 * (unless `recheckInviter` is off).
 */
import type { IssuedSession } from '../../core/plugin-context';
import { isTokenShape } from '../../crypto/random';
import type { StoredInvitation } from '../../ports/invitations';
import type { AuthUser, StoredSession } from '../../ports/stores';
import type { NormalizedEmail } from '../../shared/email';
import { ok, type AuthResult } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';
import {
  allowed,
  limit,
  refused,
  view,
  tokenHash,
  LEGACY_TOKEN_PURPOSE,
  type InvitationView,
  type Runtime,
} from './runtime';

export interface AcceptInvitationInput<A> {
  /**
   * The signed-in session. `null` only with `acceptWithoutSession` on (it is
   * refused otherwise): then the account holding the invited address accepts.
   */
  readonly session: StoredSession<A> | null;
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

  // Refused before the token is looked up: with the option off, a link alone does nothing.
  if (!session && !r.settings.acceptWithoutSession)
    return refused(r, 'forbidden', 'session_required', null, meta);

  const found = await pending(r, input.token, meta);

  if (!found.ok) return found;

  const invitation = found.value;

  const user = session
    ? await r.core.users.findById(session.userId)
    : await holderOf(r, invitation);

  if (!user)
    return session
      ? refused(r, 'forbidden', 'user_missing', session.userId, meta)
      : refused(r, 'forbidden', 'account_missing', null, meta);

  // core.normalizeEmail answers null for an invalid address; two nulls are no match.
  const userEmail = r.core.normalizeEmail(user.email);

  if (!userEmail || userEmail !== r.core.normalizeEmail(invitation.email))
    return refused(r, 'forbidden', 'email_mismatch', user.id, meta);

  if (!user.emailVerified) return refused(r, 'forbidden', 'email_unverified', user.id, meta);

  const spent = await spend(r, invitation, user.id, meta);

  if (!spent.ok) return spent;

  await accepted(r, user, spent.value, false, meta, session === null);

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
  const email = r.core.normalizeEmail(invitation.email);

  if (!email) return refused(r, 'invalid_token', 'invitation_email_invalid', null, meta);

  // Before the lookup, so a taken address and a free one both pay for the hash.
  const hashed = await r.core.hashNewPassword(input.password, meta);

  if (!hashed.ok) return refused(r, hashed.code, hashed.reason, null, meta);

  // Not spent: the owner of the address signs in and calls `accept`. An
  // address held for its old owner while an email change away from it can
  // still be reverted answers the same, or the revert would have nowhere to
  // go back to. The account first, then the hold: a confirm writes the hold
  // before it moves the address, so a confirm that lands between the two
  // reads is seen by one of them.
  if ((await r.core.findCredentialByEmail(email)) || (await r.core.isAddressHeld(email)))
    return refused(r, 'email_in_use', 'email_in_use', null, meta);

  const spent = await spend(r, invitation, null, meta);

  if (!spent.ok) return spent;

  const created = await r.core.users.create({ email, passwordHash: hashed.value });

  // An account appeared for the address between the lookup and here: the invitation is spent.
  if (!created) return refused(r, 'email_in_use', 'email_in_use', null, meta);

  // The invitation proved the address, but the store may refuse the mark (an
  // app's write guard, such as the Prisma store's `writeWhere`): then the
  // account goes on unverified, as the store holds it, never as verified.
  const verified = await r.core.users.markEmailVerified(created.id, email);

  const user: AuthUser = { ...created, emailVerified: verified };

  for (const hook of r.core.hooks.afterRegister) await hook({ user, meta });

  await r.core.emit({ type: 'register.created', userId: user.id }, meta);
  await accepted(r, user, spent.value, true, meta);

  const issued = await r.core.issueSession(user, { via: 'invitation', meta });

  return issued.ok ? ok({ invitation: view(spent.value), session: issued.value }) : issued;
}

/**
 * A row stored before 0.6 under the server secret's keyed hash: under the
 * current secret, or a previous one of a rotation (`previousSecret`).
 */
async function findLegacy(r: Runtime, token: string): Promise<StoredInvitation | null> {
  for (const hash of r.core.keyedHashes(LEGACY_TOKEN_PURPOSE, token)) {
    const found = await r.store.findByHash(hash);

    if (found) return found;
  }

  return null;
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

  const invitation =
    (await r.store.findByHash(tokenHash(token))) ??
    // Created before 0.6, under the server secret. Remove once those have expired.
    (await findLegacy(r, token));

  if (!invitation) return refused(r, 'invalid_token', 'unknown_token', null, meta);

  if (invitation.expiresAt <= r.core.clock.now())
    return refused(r, 'invalid_token', 'expired_token', null, meta);

  return ok(invitation);
}

/**
 * The account holding the invited address, for an accept with no session.
 * Read again by id, so `onAccept` never sees the password hash.
 */
async function holderOf(r: Runtime, invitation: StoredInvitation): Promise<AuthUser | null> {
  const email = r.core.normalizeEmail(invitation.email);
  const credential = email ? await r.core.findCredentialByEmail(email) : null;

  return credential ? r.core.users.findById(credential.id) : null;
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
  withoutSession = false,
): Promise<void> {
  await r.settings.onAccept({ user, invitation, created, meta });

  await r.core.emit(
    {
      type: 'invitation.accepted',
      userId: user.id,
      data: {
        scope: invitation.scope,
        invitation: invitation.id,
        created,
        ...(withoutSession ? { withoutSession } : {}),
      },
    },
    meta,
  );
}
