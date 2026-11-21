import { turnstile, type TurnstileOutcome } from '@noctcore/auth';

const secret = process.env.TURNSTILE_SECRET;

if (!secret) throw new Error('Set TURNSTILE_SECRET');

/** Count every verdict by its cause, so an outage shows apart from a wrong secret. */
function record(outcome: TurnstileOutcome): void {
  const cause = outcome.verdict === 'pass' ? 'pass' : outcome.reason;

  // Cheap and synchronous: the hook runs on the request path.
  process.stdout.write(`captcha ${outcome.door} ${outcome.verdict} ${cause}\n`);
}

// Pass it to createAuth as `captcha`. Both checks are off unless set.
export const captcha = turnstile({
  secret,
  // A token solved on any other hostname is rejected.
  expectedHostnames: ['app.example'],
  // The widget's action must equal the door: login, register, password-reset.
  checkAction: true,
  onResult: record,
});
