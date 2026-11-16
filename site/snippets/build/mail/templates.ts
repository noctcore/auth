import type { AuthMailEvent } from '@noctcore/auth';
import type { OutgoingMail } from './queue';

/** One template per event type. The `never` check fails the build when a new type appears. */
export function renderAuthMail(event: AuthMailEvent): OutgoingMail {
  switch (event.type) {
    case 'verify-email':
      return {
        to: event.to,
        subject: 'Confirm your email address',
        text: event.code
          ? `Your code is ${event.code}. It expires at ${event.expiresAt.toISOString()}.`
          : `Confirm your address: ${event.url ?? ''}`,
      };

    case 'password-reset':
      return {
        to: event.to,
        subject: 'Reset your password',
        text: `Choose a new password: ${event.url}\nIf you did not ask for this, ignore this mail.`,
      };

    case 'password-reset-code':
      return {
        to: event.to,
        subject: 'Your password reset code',
        text: `Your code is ${event.code}. If you did not ask for it, ignore this mail.`,
      };

    case 'password-changed':
      return {
        to: event.to,
        subject: 'Your password was changed',
        text: `Your password was changed at ${event.at.toISOString()}. If this was not you, reset it now.`,
      };

    case 'account-exists':
      return {
        to: event.to,
        subject: 'You already have an account',
        text: 'Someone tried to register with this address. Sign in or reset your password instead.',
      };

    case 'lockout':
      return {
        to: event.to,
        subject: 'Someone is trying to sign in to your account',
        text: `After repeated wrong passwords, your account is locked until ${event.until.toISOString()}. A device you signed in from before can still sign in with your password.`,
      };

    default: {
      const unhandled: never = event;

      throw new Error(`No template for ${JSON.stringify(unhandled)}`);
    }
  }
}
