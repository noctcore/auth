/**
 * Turns the optional, human-friendly config into the settings the flows read,
 * and refuses a combination that would be unsafe before the app serves a
 * single request.
 */
import type { FlowSettings } from './settings';
import type { AuthConfig, AuthPlugin } from '../core/config';
import type { AuthUser } from '../ports/stores';
import { assertBoolean, assertCount } from '../shared/config-checks';
import { toMilliseconds } from '../shared/duration';
import { AuthConfigError } from '../shared/errors';

/** The shortest revert window allowed: the old address's owner may be away for a week. */
export const MIN_REVERT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export function resolveSettings<U extends AuthUser, A, P extends readonly AuthPlugin[]>(
  config: AuthConfig<U, A, P>,
): FlowSettings {
  const verificationKind = config.emailVerification?.kind ?? 'code';
  const linkWithoutSession: unknown = config.emailVerification?.linkWithoutSession ?? false;

  // A string such as "false" from an env file would read as on: only a real boolean counts.
  if (typeof linkWithoutSession !== 'boolean')
    throw new AuthConfigError('emailVerification.linkWithoutSession must be true or false');

  assertOptionTypes(config);

  const resetKind = config.passwordReset?.kind ?? 'link';

  const verificationTtl =
    config.emailVerification?.ttl ?? (verificationKind === 'code' ? '15m' : '24h');

  const resetTtl = config.passwordReset?.ttl ?? (resetKind === 'code' ? '15m' : '1h');
  const changeKind = config.emailChange?.kind ?? 'code';
  const changeTtl = config.emailChange?.ttl ?? (changeKind === 'code' ? '15m' : '1h');

  const settings: FlowSettings = {
    revealExisting: config.registration?.revealExisting ?? false,
    autoLogin: config.registration?.autoLogin ?? false,
    verification: {
      kind: verificationKind,
      ttlMs: toMilliseconds(verificationTtl),
      digits: config.emailVerification?.digits ?? 8,
      maxAttempts: config.emailVerification?.maxAttempts ?? 5,
      linkWithoutSession,
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
    emailChange: {
      kind: changeKind,
      ttlMs: toMilliseconds(changeTtl),
      digits: config.emailChange?.digits ?? 8,
      maxAttempts: config.emailChange?.maxAttempts ?? 5,
      revertTtlMs: toMilliseconds(config.emailChange?.revertTtl ?? '7d'),
      blockAfterRevertMs: toMilliseconds(config.emailChange?.blockAfterRevert ?? '30d'),
    },
    urls: {
      verifyEmail: config.urls?.verifyEmail,
      resetPassword: config.urls?.resetPassword,
      confirmEmailChange: config.urls?.confirmEmailChange,
      revertEmailChange: config.urls?.revertEmailChange,
    },
    freshAuthAgeMs: toMilliseconds(config.session?.freshAuthAge ?? '10m'),
  };

  assertSafeSettings(settings);

  return settings;
}

/**
 * The same for the other booleans, read by truthiness, and the attempt
 * counts: `attempt >= NaN` is never true, so a `NaN` count never spends a code.
 */
function assertOptionTypes<U extends AuthUser, A, P extends readonly AuthPlugin[]>(
  config: AuthConfig<U, A, P>,
): void {
  assertBoolean('registration.revealExisting', config.registration?.revealExisting);
  assertBoolean('registration.autoLogin', config.registration?.autoLogin);
  assertBoolean('passwordReset.markEmailVerified', config.passwordReset?.markEmailVerified);
  assertCount('emailVerification.maxAttempts', config.emailVerification?.maxAttempts);
  assertCount('passwordReset.maxAttempts', config.passwordReset?.maxAttempts);
  assertCount('emailChange.maxAttempts', config.emailChange?.maxAttempts);
}

function assertSafeSettings(settings: FlowSettings): void {
  if (settings.autoLogin && !settings.revealExisting) {
    throw new AuthConfigError(
      'registration.autoLogin requires registration.revealExisting: a session would reveal that the account is new',
    );
  }

  if (settings.verification.kind === 'link' && !settings.urls.verifyEmail)
    throw new AuthConfigError('urls.verifyEmail is required for link verification');
  if (settings.verification.linkWithoutSession && settings.verification.kind !== 'link')
    throw new AuthConfigError('emailVerification.linkWithoutSession needs kind: link');
  if (settings.reset.kind === 'link' && !settings.urls.resetPassword)
    throw new AuthConfigError('urls.resetPassword is required for link resets');

  if (settings.emailChange.kind === 'link' && !settings.urls.confirmEmailChange)
    throw new AuthConfigError('urls.confirmEmailChange is required for link email changes');
  if (settings.emailChange.revertTtlMs < MIN_REVERT_TTL_MS)
    throw new AuthConfigError('emailChange.revertTtl must be at least 7 days');

  const codeLengths = [
    ['emailVerification.digits', settings.verification.digits],
    ['passwordReset.digits', settings.reset.digits],
    ['emailChange.digits', settings.emailChange.digits],
  ] as const;

  for (const [name, digits] of codeLengths) {
    if (!Number.isInteger(digits) || digits < 6 || digits > 9)
      throw new AuthConfigError(`${name} must be 6 to 9`);
  }
}
