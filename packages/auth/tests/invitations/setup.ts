// Shared setup for the invitation tests: an app with the plugin on in-memory
// stores, an inviter the app allows, and helpers to read the mailed token.
import { vi, type Mock } from 'vitest';
import type { AuthMailEvent, StoredSession } from '../../src';
import {
  invitations,
  type AcceptedInvitation,
  type InvitationRequest,
  type InvitationsOptions,
} from '../../src/plugins/invitations';
import { MemoryInvitationStore } from '../../src/testing';
import { meta, setup } from '../flows/setup';

export { meta, PASSWORD } from '../flows/setup';

export const SCOPE = 'org_1';

type Session = StoredSession<Record<string, never>>;

/**
 * An app with the invitations plugin. By default `authorize` allows every user
 * in `allowed` (the first signed-in user is added), and `onAccept` records.
 */
export function invitationApp(
  plugin: Partial<InvitationsOptions> = {},
  overrides: Parameters<typeof setup>[0] = {},
) {
  const store = new MemoryInvitationStore();
  const allowed = new Set<string>();

  const authorize: Mock<(request: InvitationRequest) => boolean> = vi.fn(({ user }) =>
    allowed.has(user.id),
  );

  const onAccept: Mock<(accepted: AcceptedInvitation) => void> = vi.fn();

  const plugged = invitations({
    store,
    authorize,
    onAccept,
    url: (token) => `https://app.example/invite#${token}`,
    ...plugin,
  });

  const env = setup({ ...overrides, plugins: [plugged, ...(overrides.plugins ?? [])] });

  const auth = env.auth as typeof env.auth & {
    invitations: ReturnType<NonNullable<typeof plugged.flows>>;
  };

  let count = 0;

  /** A signed-in user with a verified address; `canInvite` adds it to `allowed`. */
  async function user(options: { canInvite?: boolean; email?: string; verified?: boolean } = {}) {
    count++;

    const email = options.email ?? `user${count}@example.com`;
    const { token, session } = await env.signedInUser(email);

    if (options.verified !== false)
      await env.stores.users.markEmailVerified(session.userId, email as never);

    if (options.canInvite === true) allowed.add(session.userId);

    return { token, session: session as Session, userId: session.userId, email };
  }

  /** The token in the last invitation mail. */
  function mailedToken(): string {
    const mail = env.mailer.last('invitation') as Extract<AuthMailEvent, { type: 'invitation' }>;

    return mail.url.split('#')[1] ?? '';
  }

  /** Invites `email` as `inviter` and returns the mailed token. */
  async function invite(inviter: { session: Session }, email: string, scope = SCOPE) {
    const result = await auth.invitations.create({
      session: inviter.session,
      scope,
      email,
      payload: { role: 'member' },
      meta: meta(),
    });

    if (!result.ok || !result.value.invitation) throw new Error('invite failed');

    return { token: mailedToken(), invitation: result.value.invitation };
  }

  return { ...env, auth, store, allowed, authorize, onAccept, user, mailedToken, invite };
}

export type InvitationApp = ReturnType<typeof invitationApp>;
