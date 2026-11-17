/**
 * Checking a second-factor proof (a TOTP code or a recovery code), the one
 * routine behind the login challenge, step-up, password change and reset.
 *
 * Order matters:
 * 1. the attempt is reserved in the account's factor budget BEFORE anything is
 *    compared, so a parallel burst from many IPs gets no more guesses than the
 *    budget, and a spent budget locks the factor with capped backoff;
 * 2. the same reads and the same work happen whatever the outcome: no factor,
 *    a locked factor and a wrong code all decrypt a secret and compute every
 *    code in the drift window, and all answer the same;
 * 3. a refusal the caller already decided (`blocked`: a challenge that is
 *    unknown, spent, or from another client) is applied after the reads and
 *    BEFORE any write that spends something, so it never burns a step or a
 *    recovery code;
 * 4. a matching TOTP code is accepted only if its step moves the stored last
 *    step forward (compare-and-set), so a code is good once, even under two
 *    concurrent submissions; a recovery code only if the store deletes it.
 *
 * Guide: Learn, "Second factors".
 */
import { normalizeRecoveryCode, RECOVERY_CODE_PURPOSE } from './recovery-codes';
import type { Runtime } from './runtime';
import { matchTotp } from './totp';
import { NO_SUCH_USER_ID } from '../../ports/stores';
import type { StoredTotpFactor } from '../../ports/two-factor';
import type { RequestMeta } from '../../shared/meta';

/** A proof the user typed. */
export type SecondFactorProof =
  | { readonly kind: 'totp'; readonly code: string }
  | { readonly kind: 'recovery-code'; readonly code: string };

export type ProofCheck =
  | { readonly ok: true; readonly kind: SecondFactorProof['kind'] }
  | { readonly ok: false; readonly reason: string };

const SIX_DIGITS = /^\d{6}$/u;
const WHITESPACE = /\s/gu;

/** A proof handed over as one string (`secondFactor` on reset and password change): six digits are a TOTP code. */
export function parseProof(value: string): SecondFactorProof {
  return SIX_DIGITS.test(value.replace(WHITESPACE, ''))
    ? { kind: 'totp', code: value }
    : { kind: 'recovery-code', code: value };
}

export interface ProofRequest {
  /** The user the proof is for; null when the caller could not name one (it still pays). */
  readonly userId: string | null;
  /** The lock key the attempt is counted under (`factorAccount`). */
  readonly account: string;
  readonly proof: SecondFactorProof;
  /** A refusal decided before the check: applied after the reads, before any write. */
  readonly blocked: string | null;
  readonly meta: RequestMeta;
}

/** Checks a proof against the user's confirmed factor. */
export async function checkProof(runtime: Runtime, request: ProofRequest): Promise<ProofCheck> {
  const { core, store } = runtime;
  const gate = await core.throttle.gateFactor(request.account, runtime.settings.attempts);
  const factor = await store.findFactor(request.userId ?? NO_SUCH_USER_ID);
  // Only a confirmed factor of a named user guards anything.
  const owner = factor?.confirmed === true ? request.userId : null;

  const failure = (reason: string): ProofCheck => ({ ok: false, reason });

  if (request.proof.kind === 'recovery-code') {
    const code = normalizeRecoveryCode(request.proof.code);

    // Only an open check against a real factor can spend a code. Every other
    // path (blocked, locked, no factor) deletes under an id no store issues,
    // so it makes the same store calls as a wrong code.
    const subject =
      owner !== null && request.blocked === null && gate.allowed ? owner : NO_SUCH_USER_ID;

    const consumed =
      code !== null &&
      (await store.consumeRecoveryCode(subject, recoveryCodeHash(runtime, subject, code)));

    if (request.blocked !== null) return failure(request.blocked);
    if (!gate.allowed) return failure('factor_locked');
    if (owner === null) return failure('no_factor');
    if (code === null) return failure('malformed_recovery_code');
    if (!consumed) return failure('wrong_recovery_code');

    await recoveryCodeUsed(runtime, owner, request.meta);
  } else {
    // A pending factor's secret is decrypted like a confirmed one; only `owner` decides.
    const step = await totpStep(runtime, factor, request.proof.code);

    if (request.blocked !== null) return failure(request.blocked);
    if (!gate.allowed) return failure('factor_locked');
    if (owner === null) return failure('no_factor');
    if (step === null) return failure('wrong_code');
    if (!(await store.advanceStep(owner, step))) return failure('code_replayed');
  }

  await core.throttle.factorSucceeded(request.account);

  return { ok: true, kind: request.proof.kind };
}

/** The stored form of a normalised recovery code: an HMAC bound to its user. */
export function recoveryCodeHash(runtime: Runtime, userId: string, code: string): string {
  return runtime.core.keyedHash(RECOVERY_CODE_PURPOSE, `${userId}:${code}`);
}

/**
 * The step `code` matches for this factor's secret, or null. With no factor
 * (null) a stand-in secret is decrypted and checked instead, so the work is
 * the same.
 */
export async function totpStep(
  runtime: Runtime,
  factor: StoredTotpFactor | null,
  code: string,
): Promise<number | null> {
  const ciphertext = factor ? factor.secret : await runtime.standIn();
  const userId = factor ? factor.userId : NO_SUCH_USER_ID;
  const secret = await runtime.cipher.decrypt(ciphertext, { userId });

  return matchTotp(secret, code, runtime.core.clock.now());
}

/** A recovery code was spent: the audit row, and a mail to the owner saying how many are left. */
async function recoveryCodeUsed(
  runtime: Runtime,
  userId: string,
  meta: RequestMeta,
): Promise<void> {
  const remaining = await runtime.store.countRecoveryCodes(userId);
  const user = await runtime.core.users.findById(userId);

  await runtime.core.emit(
    { type: 'two_factor.recovery_code_used', userId, data: { remaining } },
    meta,
  );

  if (!user) return;

  runtime.core.mail({
    type: 'recovery-code-used',
    to: user.email,
    userId,
    remaining,
    at: new Date(runtime.core.clock.now()),
  });
}
