import { toPublicError, type AuthMailEvent, type Mailer, type RequestMeta } from '@noctcore/auth';
import type { AppAuth } from '../build/node-server/auth';
import type { Queue } from '../build/mail/queue';

/**
 * The Mailer only enqueues. Rendering and SMTP happen in a worker, so a door
 * that mails on one branch only answers no slower on that branch.
 */
export function enqueueOnlyMailer(queue: Queue<AuthMailEvent>): Mailer {
  return {
    // dedupeKey is unique per event: a retried add keeps one job.
    send: (event) => queue.add(event, { jobId: event.dedupeKey }),
  };
}

/** Sign-up: a taken address and a new one get the same answer. */
export async function signUp(
  auth: AppAuth,
  input: { email: string; password: string; meta: RequestMeta },
  log: (reason: string) => void,
) {
  const result = await auth.register(input);

  if (!result.ok) {
    // The reason stays on the server; the client gets the public code.
    log(result.reason);

    return { error: toPublicError(result) };
  }

  // The owner of a taken address gets an "account exists" mail instead.
  return { message: 'Check your inbox to continue.' };
}
