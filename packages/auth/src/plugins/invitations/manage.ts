/**
 * The inviter's side: create, list and revoke invitations.
 *
 * `create` never reads the invited address from the user store, so its answer
 * and its mail are the same for an address with an account and one without.
 * Creating needs a session, the app's `authorize`, and room in three windows
 * (per IP, per inviter, per address); a second live invitation for the same
 * scope and address sends no mail.
 */
import {
  allowed,
  limit,
  refused,
  view,
  TOKEN_PURPOSE,
  type InvitationView,
  type Runtime,
} from './runtime';
import { generateToken } from '../../crypto/random';
import type { StoredInvitation } from '../../ports/invitations';
import type { StoredSession } from '../../ports/stores';
import { normalizeEmail } from '../../shared/email';
import { ok, type AuthResult } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

export interface CreateInvitationInput<A> {
  readonly session: StoredSession<A>;
  readonly scope: string;
  readonly email: string;
  /** What `onAccept` should know: a role, say. Stored as given. */
  readonly payload?: Readonly<Record<string, string>>;
  readonly meta: RequestMeta;
}

export interface CreatedInvitation {
  /**
   * The new invitation, or null when a live one already exists for this scope
   * and address: then nothing was written and no mail was sent.
   */
  readonly invitation: InvitationView | null;
}

export interface ListInvitationsInput<A> {
  readonly session: StoredSession<A>;
  readonly scope: string;
  readonly meta: RequestMeta;
}

export interface RevokeInvitationInput<A> {
  readonly session: StoredSession<A>;
  readonly scope: string;
  /** The invitation's id (from `create` or `list`). */
  readonly id: string;
  readonly meta: RequestMeta;
}

export async function createInvitation<A>(
  r: Runtime,
  input: CreateInvitationInput<A>,
): Promise<AuthResult<CreatedInvitation>> {
  const { session, scope, meta } = input;
  const email = normalizeEmail(input.email);

  if (!email) return refused(r, 'invalid_email', 'invalid_email', session.userId, meta);

  const payload = { ...input.payload };
  const inviter = await r.core.users.findById(session.userId);

  if (!inviter) return refused(r, 'forbidden', 'inviter_missing', session.userId, meta);

  const limited =
    (await limit(r, 'ip', meta.ip, r.settings.perIp, meta)) ??
    (await limit(r, 'inviter', inviter.id, r.settings.perInviter, meta));

  if (limited) return limited;

  if (!(await allowed(r, { user: inviter, scope, action: 'create', email, payload })))
    return refused(r, 'forbidden', 'not_allowed', inviter.id, meta);

  const perAddress = await limit(r, 'address', email, r.settings.perAddress, meta);

  if (perAddress) return perAddress;

  const token = generateToken(r.core.random);
  const now = r.core.clock.now();

  const invitation: StoredInvitation = {
    // 128 random bits: an id to show and revoke by, never a credential.
    id: generateToken(r.core.random).slice(0, 32),
    hash: r.core.keyedHash(TOKEN_PURPOSE, token),
    scope,
    email,
    inviterId: inviter.id,
    payload,
    createdAt: now,
    expiresAt: now + r.settings.ttlMs,
  };

  if (!(await r.store.create(invitation, now))) {
    await r.core.emit(
      { type: 'invitation.deduplicated', userId: inviter.id, data: { scope } },
      meta,
    );

    return ok({ invitation: null });
  }

  r.core.mail({
    type: 'invitation',
    to: email,
    scope,
    inviterId: inviter.id,
    url: r.settings.url(token),
    expiresAt: new Date(invitation.expiresAt),
  });

  await r.core.emit(
    { type: 'invitation.created', userId: inviter.id, data: { scope, invitation: invitation.id } },
    meta,
  );

  return ok({ invitation: view(invitation) });
}

export async function listInvitations<A>(
  r: Runtime,
  input: ListInvitationsInput<A>,
): Promise<AuthResult<InvitationView[]>> {
  const permitted = await permit(r, input, 'list');

  if (!permitted.ok) return permitted;

  const pending = await r.store.listByScope(input.scope, r.core.clock.now());

  return ok(pending.map(view));
}

export async function revokeInvitation<A>(
  r: Runtime,
  input: RevokeInvitationInput<A>,
): Promise<AuthResult<void>> {
  const permitted = await permit(r, input, 'revoke');

  if (!permitted.ok) return permitted;

  if (!(await r.store.revoke(input.scope, input.id)))
    return refused(r, 'forbidden', 'invitation_missing', input.session.userId, input.meta);

  await r.core.emit(
    {
      type: 'invitation.revoked',
      userId: input.session.userId,
      data: { scope: input.scope, invitation: input.id },
    },
    input.meta,
  );

  return ok(undefined);
}

/** The session's user, read from the store, must pass `authorize` for this action. */
async function permit<A>(
  r: Runtime,
  input: ListInvitationsInput<A>,
  action: 'list' | 'revoke',
): Promise<AuthResult<void>> {
  const { session, scope, meta } = input;
  const user = await r.core.users.findById(session.userId);

  if (!user) return refused(r, 'forbidden', 'inviter_missing', session.userId, meta);

  if (!(await allowed(r, { user, scope, action })))
    return refused(r, 'forbidden', 'not_allowed', user.id, meta);

  return ok(undefined);
}
