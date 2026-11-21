import type { AuthMailEvent, Mailer } from '@noctcore/auth';
import type { OutgoingMail, Queue } from './queue';
import { renderAuthMail } from './templates';

/**
 * Puts the raw event on the queue and returns; a worker renders and sends it.
 * Rendering here would be work done before `send` returns, and a door that
 * mails on one branch only would answer slower on that branch.
 */
export function queueMailer(queue: Queue<AuthMailEvent>): Mailer {
  return {
    async send(event) {
      // dedupeKey is unique per event: if this add is retried, the queue keeps one job.
      await queue.add(event, { jobId: event.dedupeKey });
    },
  };
}

/** Your worker's handler for the mail queue: render off the response path, then deliver. */
export function handleMailJob(
  event: AuthMailEvent,
  deliver: (mail: OutgoingMail) => Promise<void>,
): Promise<void> {
  return deliver(renderAuthMail(event));
}
