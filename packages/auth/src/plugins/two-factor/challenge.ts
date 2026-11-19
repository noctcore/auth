/**
 * The login challenge: the step between a correct password and a session.
 *
 * - After a correct password, a user with a confirmed factor (or one the app
 *   requires a factor of) gets a challenge instead of a session. No session,
 *   and no lockout trusted-device cookie, exists until the challenge passes.
 * - The challenge token is 32 random bytes; the token store keeps its SHA-256
 *   under its own purpose, so it can never be redeemed as a session, a reset
 *   link or a reset ticket. It lasts 5 minutes, accepts 5 codes, is spent by
 *   the one that passes, and is bound to the user, to the client that started
 *   the login (its user agent) and to the revocation epoch read before the
 *   password was checked, so a password change during the challenge voids the
 *   session it would mint. A new login replaces it.
 * - An unknown, spent or foreign challenge does the same reads and the same
 *   code work as a wrong code, and every refusal answers `invalid_second_factor`.
 * - The session is minted by the core's `issueSession` (via `second-factor`),
 *   which runs the app's hooks and the epoch fence.
 *
 * Guide: Learn, "Second factors"; Build, "Two-factor".
 */
import { confirmPending } from './enrollment';
import { CHALLENGE_MAX_ATTEMPTS, CHALLENGE_PURPOSE, CHALLENGE_TTL_MS } from './options';
import { checkProof, type SecondFactorProof } from './proofs';
import { clientTag, factorAccount, limitIp, refused, type Runtime } from './runtime';
import { recordStepUp } from './step-up';
import { isTrustedDevice, trustDevice, type TrustedDevice } from './trusted-devices';
import type { IssuedSession } from '../../core/plugin-context';
import { hexDigestsEqual, sha256Hex } from '../../crypto/hash';
import type { AuthUser } from '../../ports/stores';
import { ok, type AuthResult } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

/** The methods a challenge offers. `enroll`: the app requires a factor the user has not set up. */
export type ChallengeMethod = 'totp' | 'recovery-code' | 'trusted-device' | 'enroll';

/** A proof for a challenge: a code typed now, or the trusted-device cookie's value. */
export type ChallengeProof =
  | SecondFactorProof
  | { readonly kind: 'trusted-device'; readonly token: string | null | undefined };

export interface VerifyChallengeInput {
  readonly challenge: string;
  readonly proof: ChallengeProof;
  /** Trust this device for later logins (a code proof only). */
  readonly rememberDevice?: boolean;
  readonly meta: RequestMeta;
}

export interface PassedChallenge<A> {
  readonly session: IssuedSession<A>;
  /**
   * Set when the challenge was an enrollment, or when it was passed with a
   * recovery code imported from the app's earlier scheme (the whole set was
   * replaced): show these once.
   */
  readonly recoveryCodes: string[] | null;
  /** Set when `rememberDevice` was asked for: set its cookie. */
  readonly trustedDevice: TrustedDevice | null;
}

/** The `loginChallenge` hook: a challenge for a user with a confirmed factor or a required one. */
export async function loginChallenge(
  runtime: Runtime,
  context: { user: AuthUser; rememberMe: boolean; epoch: number; meta: RequestMeta },
): Promise<{ challenge: string; methods: readonly ChallengeMethod[] } | null> {
  const { user } = context;
  const factor = await runtime.store.findFactor(user.id);
  const active = factor?.confirmed === true;

  // With `enforcement`, a required user without a factor signs in and the
  // session's standing confines it, so only a confirmed factor challenges.
  if (!active && (runtime.settings.enforcement || !(await runtime.settings.required({ user }))))
    return null;

  const { token } = await runtime.core.tokens.issueLink(
    CHALLENGE_PURPOSE,
    user.id,
    CHALLENGE_TTL_MS,
    {
      epoch: String(context.epoch),
      rememberMe: context.rememberMe ? 'yes' : 'no',
      client: clientTag(context.meta),
      mode: active ? 'verify' : 'enroll',
    },
  );

  if (!active) return { challenge: token, methods: ['enroll'] };

  const methods: ChallengeMethod[] = ['totp', 'recovery-code'];

  if (runtime.settings.trustedDevices) methods.push('trusted-device');

  return { challenge: token, methods };
}

type Proved =
  | {
      readonly ok: true;
      readonly method: ChallengeProof['kind'];
      readonly recoveryCodes: string[] | null;
    }
  | { readonly ok: false; readonly reason: string };

/** Finishes a challenged login: checks the proof, spends the challenge, issues the session. */
export async function verifyChallenge<A>(
  runtime: Runtime,
  input: VerifyChallengeInput,
): Promise<AuthResult<PassedChallenge<A>>> {
  const { core } = runtime;
  const { meta } = input;
  const limited = await limitIp(runtime, meta);

  if (limited) return limited;

  const peek = await core.tokens.peekLink(CHALLENGE_PURPOSE, input.challenge);
  const challengeKey = sha256Hex(`challenge:${String(input.challenge)}`);

  const perChallenge = await core.throttle.hit(`two-factor-challenge:${challengeKey}`, {
    limit: CHALLENGE_MAX_ATTEMPTS,
    window: `${CHALLENGE_TTL_MS}ms`,
  });

  const userId = peek.status === 'valid' ? peek.userId : null;
  const data = peek.status === 'valid' ? peek.data : {};

  const blocked =
    peek.status !== 'valid'
      ? `challenge_${peek.status}`
      : !perChallenge.allowed
        ? 'challenge_exhausted'
        : hexDigestsEqual(String(data['client']), clientTag(meta))
          ? null
          : 'client_mismatch';

  // An unknown challenge counts under a key of its own, so it neither locks a
  // real account nor shares one lock that would make it cheaper than a wrong code.
  const account = factorAccount(userId ?? challengeKey);
  const epoch = Number(data['epoch']);

  // The user of an enrollment challenge (a required user without a factor yet).
  const enrolling = data['mode'] === 'enroll' ? userId : null;

  const proved = await prove(runtime, input, { userId, account, blocked, enrolling, epoch });

  if (!proved.ok)
    return refused(
      runtime,
      'two_factor.failed',
      'invalid_second_factor',
      proved.reason,
      userId,
      meta,
    );

  const redeemed = await core.tokens.redeemLink(CHALLENGE_PURPOSE, input.challenge);

  if (redeemed.status !== 'valid')
    return refused(
      runtime,
      'two_factor.failed',
      'invalid_second_factor',
      `challenge_lost_race`,
      userId,
      meta,
    );

  const user = await core.users.findById(redeemed.userId);

  if (!user)
    return refused(
      runtime,
      'two_factor.failed',
      'invalid_second_factor',
      'user_missing',
      redeemed.userId,
      meta,
    );

  const issued = await core.issueSession(user, {
    via: 'second-factor',
    meta,
    epoch,
    rememberMe: data['rememberMe'] === 'yes',
  });

  if (!issued.ok) return issued;

  const session = issued.value as IssuedSession<A>;
  const byCode = proved.method !== 'trusted-device';

  // A code typed now is a step-up proof for the new session; a trusted device is not.
  if (byCode) await recordStepUp(runtime, session.session);

  const trustedDevice =
    byCode && input.rememberDevice === true
      ? await trustDevice(runtime, user.id, session.session.epoch, meta)
      : null;

  await core.emit(
    { type: 'two_factor.verified', userId: user.id, data: { method: proved.method } },
    meta,
  );

  return ok({ session, recoveryCodes: proved.recoveryCodes, trustedDevice });
}

/** Checks the proof the way the challenge's mode asks for. */
async function prove(
  runtime: Runtime,
  input: VerifyChallengeInput,
  challenge: {
    readonly userId: string | null;
    readonly account: string;
    readonly blocked: string | null;
    readonly enrolling: string | null;
    readonly epoch: number;
  },
): Promise<Proved> {
  const { proof, meta } = input;
  const { userId, account, blocked, enrolling } = challenge;

  if (proof.kind === 'trusted-device') {
    const trusted = await isTrustedDevice(runtime, userId, proof.token, challenge.epoch);

    const reason =
      blocked ??
      (enrolling !== null ? 'enrollment_required' : trusted ? null : 'device_not_trusted');

    return reason === null
      ? { ok: true, method: proof.kind, recoveryCodes: null }
      : { ok: false, reason };
  }

  if (enrolling !== null) {
    const confirmed = await confirmPending(runtime, {
      userId: enrolling,
      account,
      code: proof.code,
      blocked: blocked ?? (proof.kind === 'totp' ? null : 'enrollment_required'),
      meta,
    });

    return confirmed.ok
      ? { ok: true, method: proof.kind, recoveryCodes: confirmed.recoveryCodes }
      : confirmed;
  }

  const check = await checkProof(runtime, {
    userId,
    account,
    proof,
    blocked,
    meta,
    replaceImported: true,
  });

  return check.ok ? { ok: true, method: check.kind, recoveryCodes: check.recoveryCodes } : check;
}
