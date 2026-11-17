/**
 * @noctcore/auth/invitations: invite someone to a scope by email, and let them
 * accept into their account or create one from the link, without the
 * invitation becoming a way to take over an account or to learn which
 * addresses have one.
 *
 * Tokens are 256 random bits, stored only as a keyed hash, single use (spent
 * atomically by the store) and bound to the invited address. Creating needs a
 * session and the app's `authorize`; accepting needs the invited address,
 * verified. The plugin never scopes data: `onAccept` says what an accepted
 * invitation means.
 *
 * ```ts
 * const auth = createAuth({
 *   ...config,
 *   plugins: [invitations({ store, authorize, onAccept, url: (t) => `${origin}/invite#${t}` })],
 * });
 * await auth.invitations.create({ session, scope: orgId, email, payload: { role: 'member' }, meta });
 * ```
 *
 * Guide: Build, "Invitations".
 */
import {
  acceptInvitation,
  registerByInvitation,
  type AcceptInvitationInput,
  type RegisterByInvitationInput,
} from './accept';
import {
  createInvitation,
  listInvitations,
  revokeInvitation,
  type CreateInvitationInput,
  type ListInvitationsInput,
  type RevokeInvitationInput,
} from './manage';
import { resolveSettings, type InvitationsOptions } from './options';
import type { Context, Runtime } from './runtime';
import { definePlugin } from '../../core/plugins';
import { AuthConfigError } from '../../shared/errors';

export type {
  AcceptInvitationInput,
  RegisterByInvitationInput,
  RegisteredByInvitation,
} from './accept';
export type {
  CreatedInvitation,
  CreateInvitationInput,
  ListInvitationsInput,
  RevokeInvitationInput,
} from './manage';
export type {
  AcceptedInvitation,
  AttemptRule,
  InvitationAction,
  InvitationRequest,
  InvitationsOptions,
} from './options';
export type { InvitationView } from './runtime';
export type { InvitationStore, StoredInvitation } from '../../ports/invitations';

/**
 * Revocation reasons after which an inviter's pending invitations are kept:
 * ending sessions the user still controls says nothing about their right to
 * invite. `two-factor-enabled` (which signs out the other devices after an
 * upgrade) counts with them, like `revoke-others`. Every other reason (sign
 * out everywhere, a password reset or change, a membership change, any reason
 * the app adds) deletes them: in the revocation's scope when it names one,
 * otherwise in every scope.
 */
const KEEPS_INVITATIONS: ReadonlySet<string> = new Set([
  'logout',
  'revoke-one',
  'revoke-others',
  'evicted',
  'email-verified',
  'two-factor-enabled',
]);

/**
 * The invitations plugin. `A` is the app's session attribute type, so the
 * sessions the flows take and issue are typed like the core's.
 */
export function invitations<A = Record<string, never>>(options: InvitationsOptions) {
  const settings = resolveSettings(options);
  let runtime: Runtime | null = null;

  return definePlugin({
    id: 'invitations',
    hooks: {
      onSessionsRevoked: async ({
        userId,
        reason,
        scope,
      }: {
        userId: string;
        reason: string;
        scope?: string;
      }) => {
        if (!KEEPS_INVITATIONS.has(reason)) await options.store.deleteByInviter(userId, scope);
      },
    },
    flows: (context) => {
      if (runtime) throw new AuthConfigError('invitations: one plugin instance per createAuth');

      const r: Runtime = { core: context as Context, store: options.store, settings };

      runtime = r;

      return {
        /** Invites an address to a scope and mails the link. */
        create: (input: CreateInvitationInput<A>) => createInvitation(r, input),
        /** The scope's pending invitations. */
        list: (input: ListInvitationsInput<A>) => listInvitations(r, input),
        /** Withdraws a pending invitation. */
        revoke: (input: RevokeInvitationInput<A>) => revokeInvitation(r, input),
        /** Accepts into the signed-in account, whose verified address must be the invited one. */
        accept: (input: AcceptInvitationInput<A>) => acceptInvitation(r, input),
        /** Creates the account for an address that has none, and signs it in. */
        register: (input: RegisterByInvitationInput) => registerByInvitation<A>(r, input),
      };
    },
  });
}
