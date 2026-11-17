/**
 * TOTP (RFC 6238): HOTP (RFC 4226) over the 30-second time step, HMAC-SHA-1,
 * 6 digits, the parameters every authenticator app understands.
 *
 * - Secrets are 160 bits from the CSPRNG (RFC 4226 section 4 asks for at
 *   least 128 and recommends 160).
 * - A code is accepted for the current step and at most one step either side,
 *   to absorb clock drift between the server and the phone.
 * - Every candidate step is computed and compared in constant time, whether or
 *   not an earlier one matched, so the time taken does not say which step (or
 *   whether any) matched. Replay is refused by the caller, which stores the
 *   last accepted step (see ports/two-factor.ts).
 * - The time is the server's clock, never a value from the request.
 *
 * Guide: Learn, "Second factors".
 */
import { encodeBase32UpperCaseNoPadding } from '@oslojs/encoding';
import { generateHOTP } from '@oslojs/otp';

import { secretsEqual } from '../../crypto/hash';
import { randomBytes, type RandomSource } from '../../crypto/random';

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_SECRET_BYTES = 20;
/** Steps accepted either side of the current one. */
export const TOTP_DRIFT_STEPS = 1;

const WHITESPACE = /\s/gu;

export function generateTotpSecret(random: RandomSource): Uint8Array {
  return randomBytes(TOTP_SECRET_BYTES, random);
}

/** The time step `nowMs` falls in. */
export function timeStep(nowMs: number): number {
  return Math.floor(nowMs / (TOTP_PERIOD_SECONDS * 1000));
}

/** The code for one step. `digits` is 6 for logins; the RFC test vectors use 8. */
export function totpCode(secret: Uint8Array, step: number, digits: number = TOTP_DIGITS): string {
  return generateHOTP(secret, BigInt(step), digits);
}

/**
 * The step whose code equals `code`, within the drift window around `nowMs`,
 * or null. When two steps produce the same code the later one is returned, so
 * the stored step moves as far forward as the code allows.
 */
export function matchTotp(secret: Uint8Array, code: unknown, nowMs: number): number | null {
  if (typeof code !== 'string') return null;

  // Every code in the window is computed and compared whatever the input is:
  // a malformed one simply never equals a six-digit code.
  const candidate = code.replace(WHITESPACE, '');
  const current = timeStep(nowMs);
  let matched: number | null = null;

  for (let step = current - TOTP_DRIFT_STEPS; step <= current + TOTP_DRIFT_STEPS; step++) {
    if (secretsEqual(totpCode(secret, step), candidate)) matched = step;
  }

  return matched;
}

/** The secret as an authenticator app expects it typed: base32, upper case, no padding. */
export function encodeTotpSecret(secret: Uint8Array): string {
  return encodeBase32UpperCaseNoPadding(secret);
}

/**
 * The `otpauth://` URI for a QR code (Google Authenticator's Key URI Format).
 * Issuer and account are percent-encoded in the label and in the parameters,
 * with `%20` for a space (some apps show a `+` literally).
 */
export function totpUri(issuer: string, account: string, secret: Uint8Array): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;

  const params = [
    `secret=${encodeTotpSecret(secret)}`,
    `issuer=${encodeURIComponent(issuer)}`,
    'algorithm=SHA1',
    `digits=${TOTP_DIGITS}`,
    `period=${TOTP_PERIOD_SECONDS}`,
  ];

  return `otpauth://totp/${label}?${params.join('&')}`;
}
