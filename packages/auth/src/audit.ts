/**
 * Audit events. Every flow emits one for each success and each refusal, with
 * the internal `reason` a client never sees.
 *
 * Ordering: an event that records a GRANT (a session created, a password
 * changed) is awaited before the flow returns the grant, so a crash cannot
 * leave a grant without its row. A failing sink never fails the flow: the error
 * goes to the Logger. Events carry ids and reasons, never secrets.
 *
 * Guide: Learn, "Audit trails".
 */
import type { RequestMeta } from './meta';

export type AuthEventType =
  | 'register.created'
  | 'register.existing'
  | 'register.refused'
  | 'login.success'
  | 'login.failure'
  | 'login.challenge'
  | 'logout'
  | 'session.created'
  | 'session.revoked'
  | 'sessions.revoked'
  | 'email.verification_sent'
  | 'email.verified'
  | 'email.verification_failed'
  | 'password.reset_requested'
  | 'password.reset_request_ignored'
  | 'password.reset_code_verified'
  | 'password.reset_code_failed'
  | 'password.reset'
  | 'password.reset_failed'
  | 'password.changed'
  | 'password.change_failed'
  | 'password.rehashed'
  /** The breached-password check could not answer; the password was accepted unchecked. */
  | 'password.breach_check_unavailable'
  | 'account.locked'
  | 'rate_limit.exceeded';

export interface AuthEvent {
  readonly type: AuthEventType;
  readonly userId?: string;
  readonly reason?: string;
  readonly data?: Readonly<Record<string, string | number | boolean>>;
}

export interface AuditSink {
  emit(event: AuthEvent, meta: RequestMeta | undefined): Promise<void>;
}
