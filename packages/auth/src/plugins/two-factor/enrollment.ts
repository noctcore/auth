/**
 * Turning TOTP on.
 *
 * - Enrolling needs a fresh credential proof: a session that proved the
 *   password within `session.freshAuthAge`, or the login challenge of a user
 *   the app requires a factor of (the password was just proved).
 * - The secret is generated here (160 bits), encrypted by the app's cipher,
 *   shown once, and stays PENDING: it guards nothing until a code from it is
 *   confirmed, within 10 minutes, by a compare-and-set on that very secret.
 * - Confirming spends the code's time step, so the code that confirmed the
 *   factor cannot also pass the next challenge, and issues the recovery codes.
 * - The owner is mailed; the app may also end every other session.
 *
 * Guide: Learn, "Second factors"; Build, "Two-factor".
 */
import { CHALLENGE_PURPOSE, ENROLLMENT_TTL_MS } from './options';
import { recoveryCodeHash, totpStep } from './proofs';
import { generateRecoveryCodes } from './recovery-codes';
import { clientTag, factorAccount, limitIp, refused, type Runtime } from './runtime';
import { recordStepUp } from './step-up';
import { encodeTotpSecret, generateTotpSecret, totpUri } from './totp';
import type { IssuedSession } from '../../core/plugin-context';
import { hexDigestsEqual } from '../../crypto/hash';
import type { StoredSession } from '../../ports/stores';
import { fail, ok, type AuthResult } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

/** What to show the user once: the secret to type, and the URI for the QR code. */
export interface Enrollment {
  /** Base32, for typing into the app by hand. */
  readonly secret: string;
  /** `otpauth://totp/...`: render it as a QR code. */
  readonly uri: string;
  /** When the pending secret stops accepting its confirmation code. */
  readonly expiresAt: number;
}

export type EnrollInput<A> =
  | { readonly session: StoredSession<A>; readonly meta: RequestMeta }
  /** The challenge a login returned with the `enroll` method. */
  | { readonly challenge: string; readonly meta: RequestMeta };

export type ConfirmResult =
  | { readonly ok: true; readonly recoveryCodes: string[] }
  | { readonly ok: false; readonly reason: string };

/** Generates and stores a pending secret for a signed-in user or an enrollment challenge. */
export async function enroll<A>(
  runtime: Runtime,
  input: EnrollInput<A>,
): Promise<AuthResult<Enrollment>> {
  const { core, store } = runtime;
  const limited = await limitIp(runtime, input.meta);

  if (limited) return limited;

  const subject = await enrollingUser(runtime, input);

  if (!subject.ok) return subject;

  const user = await core.users.findById(subject.value);

  if (!user) return fail('session_expired', 'user_missing');

  const existing = await store.findFactor(user.id);

  if (existing?.confirmed === true)
    return refused(
      runtime,
      'two_factor.refused',
      'forbidden',
      'factor_active',
      user.id,
      input.meta,
    );

  const secret = generateTotpSecret(core.random);
  const ciphertext = await runtime.cipher.encrypt(secret, { userId: user.id });
  const now = core.clock.now();

  const stored = await store.putPendingFactor({
    userId: user.id,
    secret: ciphertext,
    createdAt: now,
  });

  if (!stored)
    return refused(
      runtime,
      'two_factor.refused',
      'forbidden',
      'factor_active',
      user.id,
      input.meta,
    );

  await core.emit({ type: 'two_factor.enrollment_started', userId: user.id }, input.meta);

  return ok({
    secret: encodeTotpSecret(secret),
    uri: totpUri(runtime.settings.issuer, user.email, secret),
    expiresAt: now + ENROLLMENT_TTL_MS,
  });
}

/** The user an enrollment is for: a fresh session's, or an enrollment challenge's. */
async function enrollingUser<A>(
  runtime: Runtime,
  input: EnrollInput<A>,
): Promise<AuthResult<string>> {
  if ('session' in input) {
    const fresh = runtime.core.requireFreshAuth(input.session);

    return fresh.ok ? ok(input.session.userId) : fresh;
  }

  const peek = await runtime.core.tokens.peekLink(CHALLENGE_PURPOSE, input.challenge);

  if (
    peek.status !== 'valid' ||
    peek.data['mode'] !== 'enroll' ||
    !hexDigestsEqual(String(peek.data['client']), clientTag(input.meta))
  ) {
    const userId = peek.status === 'valid' ? peek.userId : null;

    return refused(
      runtime,
      'two_factor.failed',
      'invalid_token',
      'enroll_challenge',
      userId,
      input.meta,
    );
  }

  return ok(peek.userId);
}

/**
 * Confirms the user's pending factor with a code from it. Same shape as
 * `checkProof`: the attempt is reserved first, the reads and the work happen
 * whatever the outcome, and `blocked` refuses before the compare-and-set.
 */
export async function confirmPending(
  runtime: Runtime,
  request: {
    readonly userId: string;
    readonly account: string;
    readonly code: string;
    readonly blocked: string | null;
    readonly meta: RequestMeta;
  },
): Promise<ConfirmResult> {
  const { core, store } = runtime;
  const gate = await core.throttle.gateFactor(request.account, runtime.settings.attempts);
  const factor = await store.findFactor(request.userId);
  const now = core.clock.now();

  const pending =
    factor !== null && !factor.confirmed && factor.createdAt + ENROLLMENT_TTL_MS > now
      ? factor
      : null;

  const step = await totpStep(runtime, pending, request.code);
  const failure = (reason: string): ConfirmResult => ({ ok: false, reason });

  if (request.blocked !== null) return failure(request.blocked);
  if (!gate.allowed) return failure('factor_locked');
  if (pending === null) return failure('no_pending_enrollment');
  if (step === null) return failure('wrong_code');
  if (!(await store.confirmFactor(pending.userId, pending.secret, step)))
    return failure('enrollment_race');

  await core.throttle.factorSucceeded(request.account);

  const recoveryCodes = await issueRecoveryCodes(runtime, pending.userId, request.meta);
  const user = await core.users.findById(pending.userId);

  await core.emit({ type: 'two_factor.enabled', userId: pending.userId }, request.meta);

  if (user) {
    core.mail({
      type: 'two-factor-enabled',
      to: user.email,
      userId: user.id,
      at: new Date(now),
    });
  }

  return { ok: true, recoveryCodes };
}

/** A new set of recovery codes, replacing every old one in one write. Returned once, never stored. */
export async function issueRecoveryCodes(
  runtime: Runtime,
  userId: string,
  meta: RequestMeta,
): Promise<string[]> {
  const codes = generateRecoveryCodes(runtime.core.random);
  const hashes = codes.map((code) => recoveryCodeHash(runtime, userId, code.replace('-', '')));

  await runtime.store.replaceRecoveryCodes(userId, hashes);
  await runtime.core.emit({ type: 'two_factor.recovery_codes_generated', userId }, meta);

  return codes;
}

export interface ConfirmEnrollmentInput<A> {
  readonly session: StoredSession<A>;
  readonly code: string;
  /** End every other session of the user and re-issue this one. Default false. */
  readonly revokeOtherSessions?: boolean;
  readonly meta: RequestMeta;
}

export interface ConfirmedEnrollment<A> {
  /** Show these once; the store keeps only their HMACs. */
  readonly recoveryCodes: string[];
  /** The re-issued session when `revokeOtherSessions` was set: set its cookie. */
  readonly session: IssuedSession<A> | null;
}

/** A signed-in user confirms the secret `enroll` returned. */
export async function confirmEnrollment<A>(
  runtime: Runtime,
  input: ConfirmEnrollmentInput<A>,
): Promise<AuthResult<ConfirmedEnrollment<A>>> {
  const { core } = runtime;
  const { session, meta } = input;
  const limited = await limitIp(runtime, meta);

  if (limited) return limited;

  const fresh = core.requireFreshAuth(session);

  if (!fresh.ok) return fresh;

  const confirmed = await confirmPending(runtime, {
    userId: session.userId,
    account: factorAccount(session.userId),
    code: input.code,
    blocked: null,
    meta,
  });

  if (!confirmed.ok)
    return refused(
      runtime,
      'two_factor.failed',
      'invalid_second_factor',
      confirmed.reason,
      session.userId,
      meta,
    );

  let reissued: IssuedSession<A> | null = null;

  if (input.revokeOtherSessions === true) {
    const user = await core.users.findById(session.userId);

    if (!user) return fail('session_expired', 'user_missing');

    await core.revokeAllSessions(user.id, 'two-factor-enabled');

    const issued = await core.issueSession(user, {
      via: 'second-factor',
      meta,
      inherit: session,
      authenticatedAt: session.authenticatedAt,
    });

    if (!issued.ok) return issued;

    reissued = issued.value as IssuedSession<A>;
  }

  await recordStepUp(runtime, reissued?.session ?? session);

  return ok({ recoveryCodes: confirmed.recoveryCodes, session: reissued });
}
