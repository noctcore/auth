/**
 * Turns the optional, human-friendly config into the settings the flows read,
 * and refuses a combination that would be unsafe before the app serves a
 * single request.
 */
import type { FlowSettings } from './settings';
import type { AuthConfig, AuthPlugin } from '../core/config';
import type { AuthUser } from '../ports/stores';
import { toMilliseconds } from '../shared/duration';
import { AuthConfigError } from '../shared/errors';

export function resolveSettings<U extends AuthUser, A, P extends readonly AuthPlugin[]>(
  config: AuthConfig<U, A, P>,
): FlowSettings {
  const verificationKind = config.emailVerification?.kind ?? 'code';
  const resetKind = config.passwordReset?.kind ?? 'link';

  const verificationTtl =
    config.emailVerification?.ttl ?? (verificationKind === 'code' ? '15m' : '24h');

  const resetTtl = config.passwordReset?.ttl ?? (resetKind === 'code' ? '15m' : '1h');

  const settings: FlowSettings = {
    revealExisting: config.registration?.revealExisting ?? false,
    autoLogin: config.registration?.autoLogin ?? false,
    verification: {
      kind: verificationKind,
      ttlMs: toMilliseconds(verificationTtl),
      digits: config.emailVerification?.digits ?? 8,
      maxAttempts: config.emailVerification?.maxAttempts ?? 5,
    },
    reset: {
      kind: resetKind,
      ttlMs: toMilliseconds(resetTtl),
      digits: config.passwordReset?.digits ?? 8,
      maxAttempts: config.passwordReset?.maxAttempts ?? 5,
      ticketTtlMs: toMilliseconds(config.passwordReset?.ticketTtl ?? '10m'),
      markEmailVerified: config.passwordReset?.markEmailVerified ?? true,
      enqueue: config.passwordReset?.enqueue,
    },
    urls: { verifyEmail: config.urls?.verifyEmail, resetPassword: config.urls?.resetPassword },
    freshAuthAgeMs: toMilliseconds(config.session?.freshAuthAge ?? '10m'),
  };

  assertSafeSettings(settings);

  return settings;
}

function assertSafeSettings(settings: FlowSettings): void {
  if (settings.autoLogin && !settings.revealExisting) {
    throw new AuthConfigError(
      'registration.autoLogin requires registration.revealExisting: a session would reveal that the account is new',
    );
  }

  if (settings.verification.kind === 'link' && !settings.urls.verifyEmail)
    throw new AuthConfigError('urls.verifyEmail is required for link verification');
  if (settings.reset.kind === 'link' && !settings.urls.resetPassword)
    throw new AuthConfigError('urls.resetPassword is required for link resets');

  const codeLengths = [
    ['emailVerification.digits', settings.verification.digits],
    ['passwordReset.digits', settings.reset.digits],
  ] as const;

  for (const [name, digits] of codeLengths) {
    if (!Number.isInteger(digits) || digits < 6 || digits > 9)
      throw new AuthConfigError(`${name} must be 6 to 9`);
  }
}
