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
    };

export interface Mailer {
  send(event: AuthMailEvent): Promise<void>;
}
