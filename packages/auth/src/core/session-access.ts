/**
 * The view of the session manager that plugins and flows get. Minting is left
 * out on purpose: a session may only be issued through `AuthCore.issueSession`,
 * after every factor and hook has had its say.
 */
import type { SessionAccess } from './plugin-context';
import type { SessionManager } from '../session/session-manager';

/** The session manager without `mint`. */
export function narrowSessions<A>(manager: SessionManager<A>): SessionAccess<A> {
  return {
    absoluteTtlMs: manager.absoluteTtlMs,
    rememberMeTtlMs: manager.rememberMeTtlMs,
    readEpoch: (userId) => manager.readEpoch(userId),
    validate: (token, options) => manager.validate(token, options),
    findActive: (id) => manager.findActive(id),
    listActive: (userId) => manager.listActive(userId),
    revoke: (userId, ids) => manager.revoke(userId, ids),
    revokeToken: (token) => manager.revokeToken(token),
    revokeAll: (userId) => manager.revokeAll(userId),
  };
}
