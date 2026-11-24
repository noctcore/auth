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
 *
 * `meta` says where the request behind a mail came from (for "asked from this
 * IP" in a reset or security mail). Only mails to an address the account has
 * already proven carry it: `password-reset`, `password-reset-code`,
 * `password-changed`, `lockout`, `email-changed` (to the old address),
 * `email-change-reverted`, `two-factor-enabled`, `two-factor-disabled`,
 * `recovery-code-used`, and `account-exists`, which goes to the owner of the
 * address and carries the IP and user agent of whoever tried to sign up with
 * it. A reset mail takes it from the job, so it is there when the job ran on
 * your queue too. Mails to an address nobody has proven yet (`verify-email`,
 * `email-change-confirm`) and mails to someone other than the account
 * (`email-change-in-use`, `invitation`) never carry it, and nor does a mail a
 * flow sends without a request.
 */
import type { RequestMeta } from '../shared/meta';

/** Where the request behind a mail came from. */
export interface MailRequestMeta {
  /** The client IP, already resolved through the trusted proxy hops. */
  readonly ip: string;
  /** The request's user agent, when the framework passed one. */
  readonly userAgent?: string;
}

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
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  | {
      readonly type: 'password-reset-code';
      readonly to: string;
      readonly userId: string;
      readonly code: string;
      readonly expiresAt: Date;
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  | {
      readonly type: 'password-changed';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  /** Registration of an address that already has an account: the uniform answer's mail. */
  | {
      readonly type: 'account-exists';
      readonly to: string;
      readonly userId: string;
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  /**
   * A new lock on the account. With `permanent` (the opt-in permanent tier)
   * it holds until an admin clears it and `until` is only the far-future
   * expiry it is stored with: say so instead of printing the date.
   */
  | {
      readonly type: 'lockout';
      readonly to: string;
      readonly userId: string;
      readonly until: Date;
      readonly permanent?: true;
      readonly meta?: MailRequestMeta;
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
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  /** A revert link was used: the address is back, every session ended and the password must be reset. */
  | {
      readonly type: 'email-change-reverted';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  /** The two-factor plugin: a second factor was turned on for the account. */
  | {
      readonly type: 'two-factor-enabled';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  /** The two-factor plugin: the second factor was turned off. */
  | {
      readonly type: 'two-factor-disabled';
      readonly to: string;
      readonly userId: string;
      readonly at: Date;
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  /**
   * The two-factor plugin: a recovery code was spent; `remaining` codes are
   * left, or null when the count could not be read (the store failed after a
   * login with an imported code had already issued its session).
   */
  | {
      readonly type: 'recovery-code-used';
      readonly to: string;
      readonly userId: string;
      readonly remaining: number | null;
      readonly at: Date;
      readonly meta?: MailRequestMeta;
      readonly dedupeKey: string;
    }
  /**
   * The invitations plugin: an invitation to `scope`. No `userId`: the address
   * may have no account, and the mail is the same whether it has one or not.
   */
  | {
      readonly type: 'invitation';
      readonly to: string;
      readonly scope: string;
      readonly inviterId: string;
      readonly url: string;
      readonly expiresAt: Date;
      readonly dedupeKey: string;
    };

/** The `meta` of a mail event, from the request's: the IP and the user agent, nothing else. */
export function mailMeta(meta: RequestMeta | undefined): { readonly meta?: MailRequestMeta } {
  if (!meta) return {};

  return {
    meta:
      meta.userAgent === undefined ? { ip: meta.ip } : { ip: meta.ip, userAgent: meta.userAgent },
  };
}

export interface Mailer {
  send(event: AuthMailEvent): Promise<void>;
}
