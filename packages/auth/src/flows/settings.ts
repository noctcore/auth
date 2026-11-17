/** The resolved, validated settings the flows read. Built once by `createAuth`. */
import type { PasswordResetJob } from '../core/config';
import type { AuthUser, WithPasswordHash } from '../ports/stores';

export const PURPOSE = {
  emailVerification: 'email-verification',
  passwordReset: 'password-reset',
  passwordResetTicket: 'password-reset-ticket',
  /** The code or link that proves a new address. One per user: a new request replaces it. */
  emailChange: 'email-change',
  /** The revert link mailed to the old address. One per user; while it is live the user cannot start another change. */
  emailRevert: 'email-revert',
  /**
   * Not a secret: holds the old address for its owner while the revert link
   * lives. Filed under the owner, found by the address (email-reservation.ts).
   */
  emailReserved: 'email-reserved',
  /** Not a secret: the lockout after a revert that could not restore the address (email-lockout.ts). */
  emailRevertLockout: 'email-revert-lockout',
  /** Not a secret: remembers, after a revert, the address the account may not change to for a while. */
  emailChangeBlock: 'email-change-block',
} as const;

export const RESET_PURPOSES: readonly string[] = [
  PURPOSE.passwordReset,
  PURPOSE.passwordResetTicket,
];

/** What a password change or reset voids: resets, and an email change started under the old password. */
export const PASSWORD_PURPOSES: readonly string[] = [...RESET_PURPOSES, PURPOSE.emailChange];

export interface FlowSettings {
  readonly revealExisting: boolean;
  readonly autoLogin: boolean;
  readonly verification: {
    readonly kind: 'code' | 'link';
    readonly ttlMs: number;
    readonly digits: number;
    readonly maxAttempts: number;
  };
  readonly reset: {
    readonly kind: 'link' | 'code';
    readonly ttlMs: number;
    readonly digits: number;
    readonly maxAttempts: number;
    readonly ticketTtlMs: number;
    readonly markEmailVerified: boolean;
    readonly enqueue: ((job: PasswordResetJob) => Promise<void>) | undefined;
  };
  readonly emailChange: {
    readonly kind: 'code' | 'link';
    readonly ttlMs: number;
    readonly digits: number;
    readonly maxAttempts: number;
    readonly revertTtlMs: number;
    readonly blockAfterRevertMs: number;
  };
  readonly urls: {
    readonly verifyEmail: ((token: string) => string) | undefined;
    readonly resetPassword: ((token: string) => string) | undefined;
    readonly confirmEmailChange: ((token: string) => string) | undefined;
    readonly revertEmailChange: ((token: string) => string) | undefined;
  };
  readonly freshAuthAgeMs: number;
}

/** The user without its hash: what hooks and callers are given. */
export function publicUser<U extends AuthUser>(credential: WithPasswordHash<U>): U {
  const { passwordHash: _hash, ...user } = credential;

  return user as unknown as U;
}
