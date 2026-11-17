/**
 * The package never renders mail. It emits typed events and the app's Mailer
 * maps them to its own templates and queue.
 *
 * `Mailer.send` must ENQUEUE and return, with templates built and SMTP spoken
 * in a worker. Flows call `send` and answer without awaiting its promise, but
 * the call itself is on the response path: whatever `send` does before it
 * returns that promise (rendering a template, for example) adds to the response
 * time, and since a taken address and a new one get different templates, that
 * difference can tell them apart. Delivery is at most once: a send that throws
 * or rejects is logged and not retried, so retries belong to the queue. Give
 * the enqueue a timeout: the library sets none, and a `send` that never settles
 * stays pending in memory.
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
    }
  /** An email change: the code or link that proves the new address, sent to that address. */
  | {
      readonly type: 'email-change-confirm';
      readonly to: string;
      readonly userId: string;
      /** Set for link confirmation. */
      readonly url?: string;
      /** Set for code confirmation. */
      readonly code?: string;
      readonly expiresAt: Date;
      readonly dedupeKey: string;
    }
  /**
   * An email change to an address that already has an account: the uniform
   * answer's mail, sent to that address. `userId` is the account that holds the address.
   */
  | {
      readonly type: 'email-change-in-use';
      readonly to: string;
      readonly userId: string;
      readonly dedupeKey: string;
    }
  /** An email change was confirmed: sent to the address it replaced. `revertUrl` undoes it until `revertExpiresAt`. */
  | {
      readonly type: 'email-changed';
      readonly to: string;
      readonly userId: string;
      readonly newEmail: string;
      readonly at: Date;
      readonly revertUrl: string;
      readonly revertExpiresAt: Date;
      readonly dedupeKey: string;
    }
  /** A revert link was used: the address is back, every session ended and the password must be reset. */
  | {
      readonly type: 'email-change-reverted';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly dedupeKey: string;
    }
  /** The two-factor plugin: a second factor was turned on for the account. */
  | {
      readonly type: 'two-factor-enabled';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly dedupeKey: string;
    }
  /** The two-factor plugin: the second factor was turned off. */
  | {
      readonly type: 'two-factor-disabled';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly dedupeKey: string;
    }
  /** The two-factor plugin: a recovery code was spent; `remaining` codes are left. */
  | {
      readonly type: 'recovery-code-used';
      readonly to: string;
      readonly userId: string;
      readonly remaining: number;
      readonly at: Date;
      readonly dedupeKey: string;
    };

export interface Mailer {
  send(event: AuthMailEvent): Promise<void>;
}
