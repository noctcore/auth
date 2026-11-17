/**
 * Changing the account's email, built so that someone who briefly holds a
 * session cannot keep the account: the old address can undo the change.
 *
 * - Request: a live session with a credential proof inside `freshAuthAge`
 *   (10 minutes by default), then the `beforeEmailChange` hooks (the
 *   two-factor plugin asks for its step-up or a code there). A code (or link)
 *   goes to the new address; nothing changes yet. A new request replaces the
 *   pending one; a password change or reset, or signing out of other devices
 *   or everywhere, voids it. While the revert link of an earlier change lives,
 *   no new change can start. A new address that already has an account, or is
 *   held for another account (email-reservation.ts), gets the same answer
 *   after the same store calls, and its owner gets an "in use" mail instead of
 *   a code, so the response never says whether it is taken.
 * - Confirm: the code, typed in a live signed-in session of the same account
 *   (a link works only in such a session too), is single use and bound to the
 *   user, the address it was sent to and the address it replaces. Reset and
 *   verification tokens die and the revert link is written (with a hold on the
 *   old address) BEFORE the address moves, so no failure leaves the address
 *   moved without its revert link. The store moves the address as a
 *   compare-and-set that keeps it unique, so of two accounts racing for one
 *   address exactly one gets it. Every session of the account is then revoked
 *   (the epoch fence), the caller's is re-issued, and the old address is
 *   mailed the revert link.
 * - Revert: the link (32 random bytes, SHA-256 at rest, 7 days by default)
 *   restores the old address and removes the password in one write (the next
 *   sign-in needs a reset), revokes every session (and with them the
 *   two-factor plugin's trusted devices), voids every outstanding reset,
 *   verification and change token, runs the `onEmailReverted` hooks (the
 *   two-factor plugin removes a factor enrolled since the change), blocks the
 *   lost address for this account for a while, and writes an audit row flagged
 *   for review. The link is spent only once the address is back: if the old
 *   address was taken meanwhile, the account is still locked out the same way
 *   and the link stays usable. A password change or a reset does not void it.
 *
 * Guide: Learn, "Email change"; Build, "Email change".
 */
import { addressHolder, releaseAddress, reserveAddress } from './email-reservation';
import { PURPOSE, RESET_PURPOSES, type FlowSettings } from './settings';
import type { AuthCore } from '../core/auth-core';
import { firstRefusal } from '../core/hooks';
import type { IssuedSession } from '../core/plugin-context';
import type { AuthUser, EmailChangeResult, StoredSession, UserStore } from '../ports/stores';
import { normalizeEmail, type NormalizedEmail } from '../shared/email';
import { AuthConfigError, fail, ok, type AuthFailure, type AuthResult } from '../shared/errors';
import type { RequestMeta } from '../shared/meta';
import { accountKey } from '../throttle/counter-keys';
import type { TokenRedemption } from '../tokens/one-time-tokens';

/** Tokens a confirmed change or a revert voids: each was mailed to an address the account no longer has. */
const VOIDED_BY_CHANGE: readonly string[] = [PURPOSE.emailVerification, ...RESET_PURPOSES];

const VOIDED_BY_REVERT: readonly string[] = [PURPOSE.emailChange, ...VOIDED_BY_CHANGE];

type ChangeEmail = NonNullable<UserStore['changeEmail']>;

/** The store's `changeEmail` and the revert URL, or a configuration error: the flows cannot run without them. */
function requireSupport<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
): { changeEmail: ChangeEmail; revertUrl: (token: string) => string } {
  const store = core.users;

  if (typeof store.changeEmail !== 'function')
    throw new AuthConfigError('The email change flows need a user store with changeEmail');
  if (!settings.urls.revertEmailChange)
    throw new AuthConfigError('urls.revertEmailChange is required for the email change flows');

  return {
    changeEmail: (id, change) => (store.changeEmail as ChangeEmail).call(store, id, change),
    revertUrl: settings.urls.revertEmailChange,
  };
}

export interface RequestEmailChangeInput<A> {
  readonly session: StoredSession<A>;
  readonly newEmail: string;
  /** A second-factor code, for a user with a factor whose session holds no step-up. */
  readonly secondFactor?: string;
  readonly meta: RequestMeta;
}

export interface EmailChangeRequested {
  /** When the code or link expires. The same whether or not the address is taken. */
  readonly expiresAt: number;
}

/** Starts a change: mails a code or link to the new address. The old address stays the login. */
export async function requestEmailChange<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: RequestEmailChangeInput<A>,
): Promise<AuthResult<EmailChangeRequested>> {
  requireSupport(core, settings);

  const { meta } = input;
  const session = await core.confirmLiveSession(input.session);

  if (!session) return fail('session_expired', 'session_not_active');

  const limited = await core.rateLimit('email-change-request', session.userId, meta);

  if (limited) return limited;

  const fresh = core.requireFreshAuth(session);

  if (!fresh.ok) return changeFailed(core, session.userId, fresh, meta);

  const newEmail = normalizeEmail(input.newEmail);

  if (!newEmail)
    return changeFailed(core, session.userId, fail('invalid_email', 'invalid_email'), meta);

  const user = await core.users.findById(session.userId);

  if (!user) return fail('session_expired', 'user_missing');
  if (user.email === newEmail)
    return changeFailed(core, user.id, fail('invalid_email', 'email_unchanged'), meta);
  if (await pendingRevert(core, user))
    return changeFailed(core, user.id, fail('forbidden', 'email_change_pending_revert'), meta);

  const perAddress = await core.rateLimit('email-change-address', accountKey(newEmail), meta);

  if (perAddress) return perAddress;

  const block = await core.tokens.findLive(PURPOSE.emailChangeBlock, user.id);

  if (block?.data['email'] === newEmail)
    return changeFailed(core, user.id, fail('forbidden', 'email_change_blocked'), meta);

  const refusal = await firstRefusal(core.hooks.beforeEmailChange, {
    user,
    session,
    newEmail,
    secondFactor: input.secondFactor,
    meta,
  });

  if (refusal) return changeFailed(core, user.id, fail(refusal.code, refusal.reason), meta);

  // Every path looks the address up (account, then hold) and issues
  // (replacing any pending request) before they part, so the store calls and
  // the answer are the same. A taken or held address gets a token nobody is
  // ever shown, and the "in use" mail goes to its owner instead of a code to
  // the requester.
  const account = await core.users.findCredentialByEmail(newEmail);
  const heldBy = await addressHolder(core, newEmail);
  const holder = account ?? heldFor(heldBy, user.id, newEmail);
  const issued = await issueConfirmation(core, settings, user.id, user.email, newEmail);

  if (holder) {
    core.mail({ type: 'email-change-in-use', to: holder.email, userId: holder.id });
  } else {
    core.mail({
      type: 'email-change-confirm',
      to: newEmail,
      userId: user.id,
      ...issued.secret,
      expiresAt: new Date(issued.expiresAt),
    });
  }

  await core.emit(
    { type: 'email.change_requested', userId: user.id, data: { kind: settings.emailChange.kind } },
    meta,
  );

  return ok({ expiresAt: issued.expiresAt });
}

async function issueConfirmation<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  userId: string,
  from: string,
  to: NormalizedEmail,
): Promise<{ secret: { code: string } | { url: string }; expiresAt: number }> {
  const { emailChange } = settings;
  const data = { email: to, from };

  if (emailChange.kind === 'code') {
    const { code, expiresAt } = await core.tokens.issueCode(
      PURPOSE.emailChange,
      userId,
      emailChange.ttlMs,
      emailChange.digits,
      data,
    );

    return { secret: { code }, expiresAt };
  }

  // resolveSettings refuses link mode without this URL.
  const url = settings.urls.confirmEmailChange as (token: string) => string;

  const { token, expiresAt } = await core.tokens.issueLink(
    PURPOSE.emailChange,
    userId,
    emailChange.ttlMs,
    data,
  );

  return { secret: { url: url(token) }, expiresAt };
}

export interface ChangedEmail<A> {
  /** The caller's session, re-issued after every session of the account was revoked. */
  readonly session: IssuedSession<A>;
}

/** Confirms a change with the code from the new address, typed by the signed-in user. */
export async function confirmEmailChangeCode<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { session: StoredSession<A>; code: string; meta: RequestMeta },
): Promise<AuthResult<ChangedEmail<A>>> {
  const support = requireSupport(core, settings);
  const limited = await core.rateLimit('email-change', input.meta.ip, input.meta);

  if (limited) return limited;

  // A session revoked since the request (signed out everywhere, say) cannot
  // finish it, and the code is left unspent.
  const live = await core.confirmLiveSession(input.session);

  if (!live)
    return changeFailed(
      core,
      input.session.userId,
      fail('session_expired', 'session_not_active'),
      input.meta,
    );

  const redemption = await core.tokens.redeemCode(
    PURPOSE.emailChange,
    live.userId,
    input.code,
    settings.emailChange.maxAttempts,
  );

  return finishChange(core, settings, support, redemption, live, input.meta);
}

/**
 * Confirms a change with the link from the new address. Like a verification
 * link it works only in a live signed-in session of the same account; opened
 * anywhere else, or in a revoked session, it is refused and left unspent.
 */
export async function confirmEmailChangeLink<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { token: string; session: StoredSession<A> | null; meta: RequestMeta },
): Promise<AuthResult<ChangedEmail<A>>> {
  const support = requireSupport(core, settings);
  const limited = await core.rateLimit('email-change', input.meta.ip, input.meta);

  if (limited) return limited;

  const live = input.session ? await core.confirmLiveSession(input.session) : null;
  const peek = await core.tokens.peekLink(PURPOSE.emailChange, input.token);

  if (peek.status !== 'valid')
    return changeFailed(
      core,
      namedUserOf(peek),
      fail('invalid_token', `email_change_${peek.status}`),
      input.meta,
    );

  if (live?.userId !== peek.userId) {
    await core.emit(
      { type: 'email.change_failed', userId: peek.userId, reason: 'session_required' },
      input.meta,
    );

    return fail('session_expired', 'email_change_session_required');
  }

  const redemption = await core.tokens.redeemLink(PURPOSE.emailChange, input.token);

  return finishChange(core, settings, support, redemption, live, input.meta);
}

async function finishChange<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  support: ReturnType<typeof requireSupport>,
  redemption: TokenRedemption,
  live: StoredSession<A>,
  meta: RequestMeta,
): Promise<AuthResult<ChangedEmail<A>>> {
  if (redemption.status !== 'valid')
    return changeFailed(
      core,
      namedUserOf(redemption),
      fail('invalid_token', `email_change_${redemption.status}`),
      meta,
    );

  const user = await core.users.findById(redemption.userId);
  const to = normalizeEmail(redemption.data['email']);
  const from = normalizeEmail(redemption.data['from']);

  // The proof is for a change from an address the account does not have now.
  if (!user || !to || !from || user.email !== from)
    return changeFailed(
      core,
      redemption.userId,
      fail('invalid_token', 'email_change_address_changed'),
      meta,
    );

  if (await pendingRevert(core, user))
    return changeFailed(core, user.id, fail('forbidden', 'email_change_pending_revert'), meta);
  if (heldFor(await addressHolder(core, to), user.id, to))
    return changeFailed(core, user.id, writeRefusal('taken'), meta);

  // Fail safe: what must exist once the address moves is written first. A
  // store error after this point leaves at worst a revert link nobody was
  // mailed for an address that did not move, which pendingRevert ignores.
  await core.tokens.revokeAll(user.id, VOIDED_BY_CHANGE);

  const revert = await issueRevert(core, settings, support, user.id, from, to);
  const changed = await support.changeEmail(user.id, { from, to });

  if (changed !== 'changed') {
    await core.tokens.revokeAll(user.id, [PURPOSE.emailRevert]);
    await releaseAddress(core, from);

    return changeFailed(core, user.id, writeRefusal(changed), meta);
  }

  await core.revokeAllSessions(user.id, 'email-changed');
  await core.emit({ type: 'email.changed', userId: user.id }, meta);

  core.mail({
    type: 'email-changed',
    to: from,
    userId: user.id,
    newEmail: to,
    at: new Date(core.clock.now()),
    revertUrl: revert.url,
    revertExpiresAt: new Date(revert.expiresAt),
  });

  // `live` is this user's: the code was looked up under its user, and a link
  // for another account was refused before it was spent.
  const issued = await core.issueSession(
    { ...user, email: to, emailVerified: true },
    { via: 'email-changed', meta, inherit: live, authenticatedAt: live.authenticatedAt },
  );

  return issued.ok ? ok({ session: issued.value }) : issued;
}

/**
 * Whether the user's last change can still be reverted: a live revert link
 * for a move to the address the account has now. A link left by a confirm
 * whose move never happened (a store error) names another address and does
 * not count.
 */
async function pendingRevert<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  user: U,
): Promise<boolean> {
  const revert = await core.tokens.findLive(PURPOSE.emailRevert, user.id);

  return revert?.data['to'] === user.email;
}

/** The account a hold keeps `email` for, as a holder, unless that is the requester. */
function heldFor(
  holderId: string | null,
  requesterId: string,
  email: NormalizedEmail,
): { id: string; email: string } | null {
  return holderId !== null && holderId !== requesterId ? { id: holderId, email } : null;
}

/** The revert link for a change from `from`, and the hold that keeps `from` for this account as long. */
async function issueRevert<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  support: ReturnType<typeof requireSupport>,
  userId: string,
  from: NormalizedEmail,
  to: NormalizedEmail,
): Promise<{ url: string; expiresAt: number }> {
  const ttl = settings.emailChange.revertTtlMs;

  await reserveAddress(core, from, userId, ttl);

  const { token, expiresAt } = await core.tokens.issueLink(PURPOSE.emailRevert, userId, ttl, {
    email: from,
    to,
    changedAt: String(core.clock.now()),
  });

  return { url: support.revertUrl(token), expiresAt };
}

/**
 * Undoes a change from the link mailed to the old address. No session is
 * needed: whoever holds the account now may be the intruder. The next sign-in
 * needs a password reset, which goes to the restored address.
 *
 * The link is looked at, not spent, until the address is back. If the old
 * address has an account again (the hold should prevent that; see
 * email-reservation.ts), the account is locked out anyway (password removed,
 * sessions, trusted devices and pending tokens gone, a late factor removed)
 * and the answer is `email_in_use`, with the link still usable once the
 * address is free. Not atomic: if a store call fails partway, what ran stays
 * done, and the unspent link runs it all again.
 */
export async function revertEmailChange<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  settings: FlowSettings,
  input: { token: string; meta: RequestMeta },
): Promise<AuthResult<void>> {
  const support = requireSupport(core, settings);
  const { meta } = input;
  const limited = await core.rateLimit('email-change-revert', meta.ip, meta);

  if (limited) return limited;

  const link = await core.tokens.peekLink(PURPOSE.emailRevert, input.token);

  if (link.status !== 'valid')
    return revertFailed(
      core,
      namedUserOf(link),
      fail('invalid_token', `email_revert_${link.status}`),
      meta,
    );

  const restore = normalizeEmail(link.data['email']);

  if (!restore) return revertFailed(core, link.userId, fail('invalid_token', 'user_missing'), meta);

  const outcome = await restoreAddress(core, support, link.userId, restore);

  if (!outcome.ok) return revertFailed(core, link.userId, outcome, meta);

  const { user, lost, restored } = outcome.value;

  // Right after the write that removed the password: a session signed in
  // before it is ended here, and none can start after it.
  await core.revokeAllSessions(user.id, 'email-reverted');
  await core.tokens.revokeAll(user.id, VOIDED_BY_REVERT);

  const changedAt = Number(link.data['changedAt']);

  for (const hook of core.hooks.onEmailReverted) await hook({ userId: user.id, changedAt, meta });

  if (!restored) {
    await core.emit(
      {
        type: 'email.change_revert_failed',
        userId: user.id,
        reason: 'email_revert_address_taken',
        data: { review: true, passwordCleared: true, lockedOut: true },
      },
      meta,
    );

    return fail('email_in_use', 'email_revert_address_taken');
  }

  // Spent only now. Of concurrent clicks (each did the same work, which is
  // safe to repeat) the one that spends it answers, audits and mails.
  const spent = await core.tokens.redeemLink(PURPOSE.emailRevert, input.token);

  if (spent.status !== 'valid')
    return revertFailed(core, user.id, fail('invalid_token', `email_revert_${spent.status}`), meta);

  await releaseAddress(core, restore);

  if (lost !== restore) {
    await core.tokens.issueLink(
      PURPOSE.emailChangeBlock,
      user.id,
      settings.emailChange.blockAfterRevertMs,
      { email: lost },
    );
  }

  await core.emit(
    {
      type: 'email.change_reverted',
      userId: user.id,
      data: { review: true, passwordCleared: true },
    },
    meta,
  );

  core.mail({
    type: 'email-change-reverted',
    to: restore,
    userId: user.id,
    at: new Date(core.clock.now()),
  });

  return ok();
}

/**
 * Moves the account back to `restore`, whatever address it has now, and
 * removes the password in the same write. When `restore` has an account
 * again, it removes the password alone (a write that keeps the address), so
 * the lockout still happens. Each write is a compare-and-set on the address
 * just read; a change that lands between the read and the write is read again
 * once.
 */
async function restoreAddress<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  support: ReturnType<typeof requireSupport>,
  userId: string,
  restore: NormalizedEmail,
): Promise<AuthResult<{ user: U; lost: NormalizedEmail; restored: boolean }>> {
  let taken = false;

  for (let attempt = 0; attempt < 3; attempt++) {
    const user = await core.users.findById(userId);

    if (!user) return fail('invalid_token', 'user_missing');

    const lost = user.email as NormalizedEmail;

    const written = await support.changeEmail(user.id, {
      from: lost,
      to: taken ? lost : restore,
      clearPassword: true,
    });

    if (written === 'changed') return ok({ user, lost, restored: !taken });

    taken ||= written === 'taken';
  }

  return fail('invalid_token', 'email_revert_stale');
}

/** The account a refused redemption names, for the audit row; an unknown token names none. */
function namedUserOf(
  redemption: Exclude<TokenRedemption, { status: 'valid' }>,
): string | undefined {
  const { namedUserId } = redemption as { readonly namedUserId?: string };

  return namedUserId;
}

function writeRefusal(result: Exclude<EmailChangeResult, 'changed'>): AuthFailure {
  // The confirmer proved the new mailbox, so naming a taken address tells
  // them only about an address they control.
  return result === 'taken'
    ? fail('email_in_use', 'email_change_taken')
    : fail('invalid_token', 'email_change_stale');
}

async function changeFailed<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string | undefined,
  failure: AuthFailure,
  meta: RequestMeta,
): Promise<AuthFailure> {
  await core.emit(
    { type: 'email.change_failed', ...(userId ? { userId } : {}), reason: failure.reason },
    meta,
  );

  return failure;
}

async function revertFailed<U extends AuthUser, A>(
  core: AuthCore<U, A>,
  userId: string | undefined,
  failure: AuthFailure,
  meta: RequestMeta,
): Promise<AuthFailure> {
  await core.emit(
    {
      type: 'email.change_revert_failed',
      ...(userId ? { userId, data: { review: true } } : {}),
      reason: failure.reason,
    },
    meta,
  );

  return failure;
}
