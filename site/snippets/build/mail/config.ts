import type { Auth, AuthConfig, AuthMailEvent, AuthUser, PasswordResetJob } from '@noctcore/auth';
import { queueMailer } from './mailer';
import type { Queue } from './queue';

export interface MailQueues {
  readonly mail: Queue<AuthMailEvent>;
  readonly passwordResets: Queue<PasswordResetJob>;
}

/** The mail half of the createAuth config: spread it into yours. */
export function mailConfig(
  queues: MailQueues,
): Pick<AuthConfig<AuthUser, unknown, []>, 'mailer' | 'passwordReset'> {
  return {
    mailer: queueMailer(queues.mail),
    passwordReset: {
      // The request only enqueues; the lookup and the mail run in the worker.
      enqueue: (job) => queues.passwordResets.add(job, { jobId: job.dedupeKey }),
    },
  };
}

/** Your worker's handler for the password reset queue. */
export function handlePasswordResetJob(
  auth: Auth<AuthUser, Record<string, never>>,
  job: PasswordResetJob,
): Promise<void> {
  return auth.jobs.processPasswordReset(job);
}
