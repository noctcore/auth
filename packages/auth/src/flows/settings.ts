/** The resolved, validated settings the flows read. Built once by `createAuth`. */
import type { PasswordResetJob } from '../config';
import type { AuthUser, WithPasswordHash } from '../stores';

export const PURPOSE = {
  emailVerification: 'email-verification',
  passwordReset: 'password-reset',
  passwordResetTicket: 'password-reset-ticket',
} as const;

export const RESET_PURPOSES: readonly string[] = [
  PURPOSE.passwordReset,
  PURPOSE.passwordResetTicket,
];

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
  readonly urls: {
    readonly verifyEmail: ((token: string) => string) | undefined;
    readonly resetPassword: ((token: string) => string) | undefined;
  };
  readonly freshAuthAgeMs: number;
}

/** The user without its hash: what hooks and callers are given. */
export function publicUser<U extends AuthUser>(credential: WithPasswordHash<U>): U {
  const { passwordHash: _hash, ...user } = credential;
  return user as unknown as U;
}
