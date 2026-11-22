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
 * With `importedRecoveryCodes` on, a recovery code is also hashed the old
 * app's way on every path, and tried under the imported prefix when the
 * plugin's own hash did not match. The check reports an imported code; the
 * login challenge replaces the whole set once its session is issued, so the
 * old hashes leave the store. Only one login per challenge lifetime rotates
 * a set (a claim on a counter), so two logins with two imported codes that
 * race within a challenge's lifetime never leave a set nobody was shown. A
 * hash that throws is read as no match.
 *
 * Guide: Learn, "Second factors".
 */
import {
  generateRecoveryCodes,
  IMPORTED_RECOVERY_CODE_PREFIX,
  importedRecoveryCodeInput,
  normalizeRecoveryCode,
  RECOVERY_CODE_PURPOSE,
} from './recovery-codes';
import { CHALLENGE_TTL_MS } from './options';
import { gateAttempt, type Runtime } from './runtime';
import { matchTotp } from './totp';
import { NO_SUCH_USER_ID, type AuthUser } from '../../ports/stores';
import type { StoredTotpFactor } from '../../ports/two-factor';
import type { RequestMeta } from '../../shared/meta';

/** A proof the user typed. */
export type SecondFactorProof =
  | { readonly kind: 'totp'; readonly code: string }
  | { readonly kind: 'recovery-code'; readonly code: string };

export type ProofCheck =
  | {
      readonly ok: true;
      readonly kind: SecondFactorProof['kind'];
      /** The proof was a recovery code imported from the app's earlier scheme. */
      readonly imported: boolean;
    }
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
  /**
   * The login challenge: it replaces the set when an imported code passes,
   * and reports that code itself (`reportImportedCode`) once it knows the
   * set the user ends with, so the mail and the audit row count that set.
   */
  readonly rotatesImported?: boolean;
}

/** Checks a proof against the user's confirmed factor. */
export async function checkProof(runtime: Runtime, request: ProofRequest): Promise<ProofCheck> {
  const { core, store } = runtime;
  const gate = await gateAttempt(runtime, request);
  const factor = await store.findFactor(request.userId ?? NO_SUCH_USER_ID);
  // Only a confirmed factor of a named user guards anything.
  const owner = factor?.confirmed === true ? request.userId : null;

  const failure = (reason: string): ProofCheck => ({ ok: false, reason });
  let imported = false;

  if (request.proof.kind === 'recovery-code') {
    const code = normalizeRecoveryCode(request.proof.code);

    // Only an open check against a real factor can spend a code. Every other
    // path (blocked, locked, no factor) deletes under an id no store issues,
    // so it makes the same store calls as a wrong code.
    const subject =
      owner !== null && request.blocked === null && gate.allowed ? owner : NO_SUCH_USER_ID;

    const importedKey = await importedHash(runtime, subject, request.proof.code);

    const consumed = code !== null && (await consumeUnderAnyKey(runtime, subject, code));

    const consumedImported =
      !consumed && importedKey !== null && (await store.consumeRecoveryCode(subject, importedKey));

    if (request.blocked !== null) return failure(request.blocked);
    if (!gate.allowed) return failure('factor_locked');
    if (owner === null) return failure('no_factor');
    if (code === null && importedKey === null) return failure('malformed_recovery_code');
    if (!consumed && !consumedImported) return failure('wrong_recovery_code');

    imported = consumedImported;

    if (!(imported && request.rotatesImported === true))
      await recoveryCodeUsed(runtime, owner, request.meta, imported);
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

  return { ok: true, kind: request.proof.kind, imported };
}

/** The stored form of a normalised recovery code: an HMAC bound to its user. */
export function recoveryCodeHash(runtime: Runtime, userId: string, code: string): string {
  return runtime.core.keyedHash(RECOVERY_CODE_PURPOSE, `${userId}:${code}`);
}

/**
 * Spends the code stored under the current key, or under a previous secret
 * of a rotation (`previousSecret`) when the current one finds none: codes
 * issued before the rotation keep working while it lasts. Each try is one
 * atomic consume, so a code is still spent at most once.
 */
async function consumeUnderAnyKey(
  runtime: Runtime,
  userId: string,
  code: string,
): Promise<boolean> {
  for (const hash of runtime.core.keyedHashes(RECOVERY_CODE_PURPOSE, `${userId}:${code}`)) {
    if (await runtime.store.consumeRecoveryCode(userId, hash)) return true;
  }

  return false;
}

/**
 * The store key of the typed code under the app's imported scheme, or null
 * when the option is off or the input cannot be one of its codes. A hash
 * that throws is logged (its name only: a message could quote the input) and
 * read as no match, so the proof is refused like a wrong code.
 */
async function importedHash(
  runtime: Runtime,
  userId: string,
  input: unknown,
): Promise<string | null> {
  const scheme = runtime.settings.importedRecoveryCodes;
  const code = importedRecoveryCodeInput(input);

  if (scheme === null || code === null) return null;

  let hash: string | null;

  try {
    hash = await scheme.hash(code, { userId });
  } catch (error) {
    runtime.core.logger.error('twoFactor: importedRecoveryCodes.hash threw; read as no match', {
      error: errorName(error),
    });

    return null;
  }

  return typeof hash === 'string' && hash.length > 0
    ? `${IMPORTED_RECOVERY_CODE_PREFIX}${hash}`
    : null;
}

/** A caught error for a log field: its name only, since a message could quote a code or a hash. */
function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error;
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

/**
 * After a login passed with an imported code: replaces the user's whole set
 * with new codes and returns them to show once. Returns null, keeping the
 * session, when another login already claimed this set's rotation (two
 * logins racing with two imported codes: the other one shows the live set)
 * or when the claim or the write failed (logged).
 * The claim lasts a challenge's lifetime, longer than any login that passed
 * a code before the winner's write can still be on its way to its own.
 */
export async function rotateImportedSet(
  runtime: Runtime,
  userId: string,
  meta: RequestMeta,
): Promise<string[] | null> {
  try {
    const claimed = await runtime.core.throttle.claimRecoveryCodeRotation(userId, CHALLENGE_TTL_MS);

    return claimed ? await issueRecoveryCodes(runtime, userId, meta) : null;
  } catch (error) {
    runtime.core.logger.error('twoFactor: replacing an imported recovery code set failed', {
      error: errorName(error),
    });

    return null;
  }
}

/**
 * Reports an imported code the login challenge spent, once the set is
 * settled: `rotated` is the new set when this login replaced it, so the
 * owner is told how many codes they now hold. Runs after the session may
 * exist, so nothing here throws: a count that fails is reported as unknown
 * (`remaining` left out of the audit row, null in the mail), a user lookup
 * that fails still writes the audit row, and each failure is logged.
 */
export async function reportImportedCode(
  runtime: Runtime,
  userId: string,
  meta: RequestMeta,
  rotated: readonly string[] | null,
): Promise<void> {
  const remaining =
    rotated?.length ??
    (await settled(runtime, 'count', () => runtime.store.countRecoveryCodes(userId)));

  const user = await settled(runtime, 'user', () => runtime.core.users.findById(userId));

  await announceRecoveryCodeUsed(runtime, { userId, user, meta, imported: true, remaining });
}

/** The value `read` gives, or null when it throws (logged by the error's name). */
async function settled<T>(
  runtime: Runtime,
  what: string,
  read: () => Promise<T>,
): Promise<T | null> {
  try {
    return await read();
  } catch (error) {
    runtime.core.logger.error('twoFactor: reporting a spent imported recovery code failed', {
      step: what,
      error: errorName(error),
    });

    return null;
  }
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

/**
 * A recovery code was spent: the audit row (`imported` when it came from the
 * app's earlier scheme), and a mail to the owner saying how many are left.
 */
async function recoveryCodeUsed(
  runtime: Runtime,
  userId: string,
  meta: RequestMeta,
  imported: boolean,
): Promise<void> {
  const remaining = await runtime.store.countRecoveryCodes(userId);
  const user = await runtime.core.users.findById(userId);

  await announceRecoveryCodeUsed(runtime, { userId, user, meta, imported, remaining });
}

/**
 * The audit row and the owner's mail for a spent recovery code. `remaining`
 * null: the count could not be read, so the row leaves it out and the mail
 * says null. `user` null: no mail, the row still goes out.
 */
async function announceRecoveryCodeUsed(
  runtime: Runtime,
  spent: {
    readonly userId: string;
    readonly user: AuthUser | null;
    readonly meta: RequestMeta;
    readonly imported: boolean;
    readonly remaining: number | null;
  },
): Promise<void> {
  const { userId, user, imported, remaining } = spent;
  const counted = remaining === null ? {} : { remaining };

  await runtime.core.emit(
    {
      type: 'two_factor.recovery_code_used',
      userId,
      data: imported ? { ...counted, imported: true } : counted,
    },
    spent.meta,
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
