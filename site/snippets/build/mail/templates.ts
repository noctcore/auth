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

    case 'email-change-confirm':
      return {
        to: event.to,
        subject: 'Confirm your new email address',
        text: event.code
          ? `Your code is ${event.code}. It expires at ${event.expiresAt.toISOString()}. If you did not ask to use this address, ignore this mail.`
          : `Confirm your new address: ${event.url ?? ''}`,
      };

    case 'email-change-in-use':
      return {
        to: event.to,
        subject: 'Someone tried to move an account to your address',
        text: 'An account asked to change its email to this address, which already has an account. Nothing changed. If this was you, sign in to that account instead.',
      };

    case 'email-changed':
      return {
        to: event.to,
        subject: 'Your email address was changed',
        text: `Your account now uses ${event.newEmail}. If this was not you, undo it before ${event.revertExpiresAt.toISOString()}: ${event.revertUrl}`,
      };

    case 'email-change-reverted':
      return {
        to: event.to,
        subject: 'Your email address is back',
        text: 'The email change was undone and every session was signed out. Reset your password to sign in again.',
      };

    // The three below come from the two-factor plugin (@noctcore/auth/two-factor).
    case 'two-factor-enabled':
      return {
        to: event.to,
        subject: 'Two-factor authentication is on',
        text: `Two-factor authentication was turned on at ${event.at.toISOString()}. If this was not you, reset your password and contact support.`,
      };

    case 'two-factor-disabled':
      return {
        to: event.to,
        subject: 'Two-factor authentication is off',
        text: `Two-factor authentication was turned off at ${event.at.toISOString()}. If this was not you, reset your password and contact support.`,
      };

    case 'recovery-code-used':
      return {
        to: event.to,
        subject: 'A recovery code was used',
        text: `A recovery code was used to sign in at ${event.at.toISOString()}. ${event.remaining === null ? '' : `${event.remaining} codes are left. `}If this was not you, reset your password now.`,
      };

    case 'invitation':
      // Never say whether the address has an account: the mail is the same either way.
      return {
        to: event.to,
        subject: 'You are invited',
        text: `You were invited to join. Accept before ${event.expiresAt.toISOString()}: ${event.url}`,
      };

    default: {
      const unhandled: never = event;

      throw new Error(`No template for ${JSON.stringify(unhandled)}`);
    }
  }
}
