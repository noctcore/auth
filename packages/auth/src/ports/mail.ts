/**
 * The package never renders mail. It emits typed events and the app's Mailer
 * maps them to its own templates and queue.
 *
 * `Mailer.send` must ENQUEUE, not send over SMTP inline: flows do the same work
 * for known and unknown addresses up to the mail step, and an inline SMTP round
 * trip for known addresses only would put the account's existence back into
 * the response time.
 *
 * `dedupeKey` is a server-minted nonce per event, safe to use as a queue job id.
 */
export type AuthMailEvent =
  | {
      readonly type: 'verify-email';
      readonly to: string;
      readonly userId: string;
      /** Set for link verification. */
      readonly url?: string;
      /** Set for code verification. */
      readonly code?: string;
      readonly expiresAt: Date;
      readonly dedupeKey: string;
    }
  | {
      readonly type: 'password-reset';
      readonly to: string;
      readonly userId: string;
      readonly url: string;
      readonly expiresAt: Date;
      readonly dedupeKey: string;
    }
  | {
      readonly type: 'password-reset-code';
      readonly to: string;
      readonly userId: string;
      readonly code: string;
      readonly expiresAt: Date;
      readonly dedupeKey: string;
    }
  | {
      readonly type: 'password-changed';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly dedupeKey: string;
    }
  /** Registration of an address that already has an account: the uniform answer's mail. */
  | {
      readonly type: 'account-exists';
      readonly to: string;
      readonly userId: string;
      readonly dedupeKey: string;
    }
  | {
      readonly type: 'lockout';
      readonly to: string;
      readonly userId: string;
      readonly until: Date;
      readonly dedupeKey: string;
    };

export interface Mailer {
  send(event: AuthMailEvent): Promise<void>;
}
