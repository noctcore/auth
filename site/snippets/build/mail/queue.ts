/**
 * The two calls this guide needs from a job queue. BullMQ, pg-boss, Graphile
 * Worker and SQS all offer them under some name; adapt the names to yours.
 */
export interface Queue<T> {
  /** Adds a job. A second add with the same `jobId` is dropped. */
  add(data: T, options: { jobId: string }): Promise<void>;
}

/** A rendered message, ready for whatever sends your mail. */
export interface OutgoingMail {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}
