import type { Mailer } from '@noctcore/auth';
import type { OutgoingMail, Queue } from './queue';
import { renderAuthMail } from './templates';

/**
 * Renders the event and puts it on the queue; a worker sends it. `send`
 * returns as soon as the job is stored, so a known address costs the request
 * no more time than an unknown one.
 */
export function queueMailer(queue: Queue<OutgoingMail>): Mailer {
  return {
    async send(event) {
      // dedupeKey is unique per event: if this add is retried, the queue keeps one job.
      await queue.add(renderAuthMail(event), { jobId: event.dedupeKey });
    },
  };
}
