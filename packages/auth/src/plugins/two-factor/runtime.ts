/**
 * What every part of the two-factor plugin shares: the plugin context (bound
 * once, when `createAuth` builds the plugin's flows), the store, the cipher,
 * the settings, and the small steps they all repeat (the per-IP limit, the
 * audit row of a refusal, the factor's lock key).
 */
import type { TwoFactorSettings } from './options';
import type { PluginContext } from '../../core/plugin-context';
import { sha256Hex } from '../../crypto/hash';
import { randomBytes } from '../../crypto/random';
import type { AuthEventType } from '../../ports/audit';
import { NO_SUCH_USER_ID, type AuthUser } from '../../ports/stores';
import type { SecretCipher, TwoFactorStore } from '../../ports/two-factor';
import { fail, type AuthErrorCode, type AuthFailure } from '../../shared/errors';
import type { RequestMeta } from '../../shared/meta';

// The plugin is written against any app's user and attribute types.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Context = PluginContext<AuthUser, any>;

export interface Runtime {
  readonly core: Context;
  readonly store: TwoFactorStore;
  readonly cipher: SecretCipher;
  readonly settings: TwoFactorSettings;
  /**
   * A ciphertext of a random secret, made once. Paths with no factor to check
   * (an unknown challenge, a user without a factor) decrypt it and compute the
   * codes anyway, so they cost what a wrong code costs.
   */
  standIn(): Promise<string>;
}

export function createRuntime(
  core: Context,
  store: TwoFactorStore,
  cipher: SecretCipher,
  settings: TwoFactorSettings,
): Runtime {
  let cached: Promise<string> | undefined;

  return {
    core,
    store,
    cipher,
    settings,
    standIn() {
      // A failed encrypt is not cached: the next call tries again.
      cached ??= cipher
        .encrypt(randomBytes(20, core.random), { userId: NO_SUCH_USER_ID })
        .catch((error: unknown) => {
          cached = undefined;

          throw error;
        });

      return cached;
    },
  };
}

/** The factor's lock key: derived from the user id, apart from every password lockout key. */
export function factorAccount(userId: string): string {
  return sha256Hex(`two-factor:${userId}`);
}

/**
 * Checks the factor's lock and reserves one attempt (`throttle.gateFactor`).
 * A new lock counts toward the permanent lockout tier of the user's account
 * (`escalateLock`, which does nothing while the tier is off), so a guesser
 * who holds the password cannot climb past it on codes alone. An attempt
 * with no user to name (an unknown challenge) still makes the same lookup.
 */
export async function gateAttempt(
  runtime: Runtime,
  attempt: { readonly account: string; readonly userId: string | null; readonly meta: RequestMeta },
): ReturnType<Context['throttle']['gateFactor']> {
  const gate = await runtime.core.throttle.gateFactor(attempt.account, runtime.settings.attempts);

  if (!gate.allowed && gate.newLock)
    await runtime.core.escalateLock({
      userId: attempt.userId ?? NO_SUCH_USER_ID,
      meta: attempt.meta,
    });

  return gate;
}

/** The client a challenge is bound to: its user agent, hashed. */
export function clientTag(meta: RequestMeta): string {
  return sha256Hex(`client:${String(meta.userAgent)}`);
}

/** One hit on the per-IP window for code checks; a failure result when over it. */
export async function limitIp(runtime: Runtime, meta: RequestMeta): Promise<AuthFailure | null> {
  const hit = await runtime.core.throttle.hit(`two-factor:${meta.ip}`, runtime.settings.perIp);

  if (hit.allowed) return null;

  if (hit.firstRefusal)
    await runtime.core.emit({ type: 'rate_limit.exceeded', reason: 'two-factor' }, meta);

  return fail('rate_limited', 'rate_limited:two-factor', {
    retryAfterSeconds: hit.retryAfterSeconds,
  });
}

/** Writes the audit row of a refusal and returns the failure. */
export async function refused(
  runtime: Runtime,
  type: AuthEventType,
  code: AuthErrorCode,
  reason: string,
  userId: string | null,
  meta: RequestMeta | undefined,
): Promise<AuthFailure> {
  await runtime.core.emit({ type, ...(userId === null ? {} : { userId }), reason }, meta);

  return fail(code, reason);
}
