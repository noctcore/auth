/**
 * Audit events. Every flow emits one for each success and each refusal, with
 * the internal `reason` a client never sees.
 *
 * Ordering: an event that records a GRANT (a session created, a password
 * changed) is awaited before the flow returns the grant, so a crash cannot
 * leave a grant without its row. A failing sink never fails the flow: the error
 * goes to the Logger. Events carry ids and reasons, never secrets.
 */
import type { RequestMeta } from '../shared/meta';

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
  /** Email change: a request (uniform whether or not the new address is taken), a refusal, a confirmed change. */
  | 'email.change_requested'
  | 'email.change_failed'
  | 'email.changed'
  /** A revert link restored the old address. Carries `review: true`: look at the account. */
  | 'email.change_reverted'
  | 'email.change_revert_failed'
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
  | 'rate_limit.exceeded'
  /** The two-factor plugin's events. */
  | 'two_factor.enrollment_started'
  | 'two_factor.enabled'
  | 'two_factor.disabled'
  | 'two_factor.verified'
  | 'two_factor.failed'
  | 'two_factor.refused'
  | 'two_factor.step_up'
  | 'two_factor.recovery_code_used'
  | 'two_factor.recovery_codes_generated'
  | 'two_factor.trusted_device_added'
  | 'two_factor.trusted_devices_revoked';

export interface AuthEvent {
  readonly type: AuthEventType;
  readonly userId?: string;
  readonly reason?: string;
  readonly data?: Readonly<Record<string, string | number | boolean>>;
}

export interface AuditSink {
  emit(event: AuthEvent, meta: RequestMeta | undefined): Promise<void>;
}
