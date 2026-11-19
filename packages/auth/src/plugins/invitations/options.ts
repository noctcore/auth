import type { StoredInvitation, InvitationStore } from '../../ports/invitations';
import type { AuthUser } from '../../ports/stores';
import { toMilliseconds, type Duration } from '../../shared/duration';
import type { NormalizedEmail } from '../../shared/email';
import { AuthConfigError } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

/** What an inviter asks to do. */
export type InvitationAction = 'create' | 'list' | 'revoke';

/** What `authorize` decides on. */
export interface InvitationRequest {
  /** The acting user, read from the user store by the session's user id. */
  readonly user: AuthUser;
  readonly scope: string;
  readonly action: InvitationAction;
  /** Set for `create`, and when an accept checks the inviter again. */
  readonly email?: NormalizedEmail;
  /** Set for `create`, and when an accept checks the inviter again. */
  readonly payload?: Readonly<Record<string, string>>;
}

/** What `onAccept` is told. */
export interface AcceptedInvitation {
  /** The accepting user; its address is verified and equals the invited one. */
  readonly user: AuthUser;
  readonly invitation: StoredInvitation;
  /** True when the account was created by accepting (`register`). */
  readonly created: boolean;
  readonly meta: RequestMeta;
}

export interface AttemptRule {
  readonly limit: number;
  readonly window: Duration;
}

export interface InvitationsOptions {
  /** Pending invitations. `@noctcore/auth-prisma` and `@noctcore/auth-redis` ship one. */
  readonly store: InvitationStore;
  /**
   * The app's permission check: may this user invite to, list or revoke in
   * this scope? Required: without it the plugin refuses to start, so it can
   * never be wired open by accident. Throwing refuses. It runs again for the
   * inviter when an invitation is accepted (see `recheckInviter`).
   */
  readonly authorize: (request: InvitationRequest) => boolean | Promise<boolean>;
  /**
   * What an accepted invitation means: add the member, grant the role in
   * `invitation.payload`. The invitation is already spent when this runs; a
   * throw reaches the caller and the invitation stays spent.
   */
  readonly onAccept: (accepted: AcceptedInvitation) => void | Promise<void>;
  /**
   * The link in the invitation mail. The token must sit in the path or the
   * fragment, never the query string (checked at startup), and the page that
   * serves it should send `Referrer-Policy: no-referrer`.
   */
  readonly url: (token: string) => string;
  /** How long an invitation can be accepted. Default 7 days, at most 30. */
  readonly ttl?: Duration;
  /**
   * Check `authorize` for the inviter again on accept, with the invitation's
   * scope, address and payload. Default true: an inviter who lost the right
   * (or the account) since sending leaves nothing acceptable behind.
   */
  readonly recheckInviter?: boolean;
  /**
   * Also accept with no session (`accept({ session: null, ... })`): the
   * token, which only the invited mailbox received, then joins the account
   * that holds the invited address, which must be verified. No session is
   * issued, so nobody is signed in by it. Default false: `accept` needs a
   * session of the account with the invited address.
   */
  readonly acceptWithoutSession?: boolean;
  /** Invitations one inviter may send. Default 20 per hour. */
  readonly perInviter?: AttemptRule;
  /** Invitations one address may receive, across scopes. Default 3 per day. */
  readonly perAddress?: AttemptRule;
  /** Creates, accepts and registrations per client IP. Default 10 per minute. */
  readonly perIp?: AttemptRule;
}

export interface InvitationsSettings {
  readonly authorize: InvitationsOptions['authorize'];
  readonly onAccept: InvitationsOptions['onAccept'];
  readonly url: InvitationsOptions['url'];
  readonly ttlMs: number;
  readonly recheckInviter: boolean;
  readonly acceptWithoutSession: boolean;
  readonly perInviter: AttemptRule;
  readonly perAddress: AttemptRule;
  readonly perIp: AttemptRule;
}

/** The longest lifetime an invitation can be given. */
export const MAX_TTL_MS = 30 * 24 * 60 * 60_000;

/** A token-shaped value the `url` check renders, to see where the token lands. */
const PROBE = 'invitationProbeToken0123456789abcdefghijkl';

export function resolveSettings(options: InvitationsOptions): InvitationsSettings {
  if (!options.store) throw new AuthConfigError('invitations: store is required');

  if (typeof options.authorize !== 'function')
    throw new AuthConfigError('invitations: authorize is required, so creating is never open');

  if (typeof options.onAccept !== 'function')
    throw new AuthConfigError('invitations: onAccept is required');

  checkUrl(options.url);

  const ttlMs = toMilliseconds(options.ttl ?? '7d');

  if (ttlMs <= 0 || ttlMs > MAX_TTL_MS)
    throw new AuthConfigError('invitations: ttl must be positive and at most 30 days');

  const acceptWithoutSession: unknown = options.acceptWithoutSession ?? false;

  if (typeof acceptWithoutSession !== 'boolean')
    throw new AuthConfigError('invitations: acceptWithoutSession must be true or false');

  return {
    authorize: options.authorize,
    onAccept: options.onAccept,
    url: options.url,
    ttlMs,
    recheckInviter: options.recheckInviter ?? true,
    acceptWithoutSession,
    perInviter: resolveRule('perInviter', options.perInviter ?? { limit: 20, window: '1h' }),
    perAddress: resolveRule('perAddress', options.perAddress ?? { limit: 3, window: '24h' }),
    perIp: resolveRule('perIp', options.perIp ?? { limit: 10, window: '1m' }),
  };
}

/** The link must carry the token, and never in the query string, which lands in logs. */
function checkUrl(url: InvitationsOptions['url']): void {
  if (typeof url !== 'function') throw new AuthConfigError('invitations: url is required');

  const rendered = url(PROBE);
  let parsed: URL;

  try {
    parsed = new URL(rendered);
  } catch {
    throw new AuthConfigError('invitations: url must return an absolute URL');
  }

  if (!rendered.includes(PROBE)) throw new AuthConfigError('invitations: url must carry the token');

  if (parsed.search.includes(PROBE))
    throw new AuthConfigError(
      'invitations: url must put the token in the path or the fragment, never the query string',
    );
}

/** A limit that is a positive integer over a positive window; anything else would never count or never refuse. */
function resolveRule(name: string, rule: AttemptRule): AttemptRule {
  if (!Number.isInteger(rule.limit) || rule.limit < 1)
    throw new AuthConfigError(`invitations: ${name}.limit must be a positive integer`);

  if (toMilliseconds(rule.window) <= 0)
    throw new AuthConfigError(`invitations: ${name}.window must be positive`);

  return rule;
}
